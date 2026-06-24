//! `/proc` introspection - port of the maps parsing, `CountAUXV`, and
//! `SanitizeVDSO` logic from `elfcore.c`.
//!
//! Parses `/proc/self/maps` into a fixed-capacity [`Mapping`] list using the
//! libc-free [`crate::io::Io`] buffered reader (no allocation), and reads
//! `/proc/self/auxv` for the AUXV note and VDSO address. All of this runs after
//! threads are suspended, so it must stay allocation- and lock-free.

use core::ffi::{CStr, c_void};
use core::{mem, slice};

use corus_syscall::linux::{EINTR, EINVAL, O_RDONLY};
use corus_syscall::sys;

use crate::elf::{ELFMAG, Ehdr, PF_R, PF_W, PF_X, PT_LOAD, Phdr};
use crate::io::leading_zeros;
use crate::io::{Io, Pipe};

/// Maximum memory mappings we record in one dump. Fixed cap replacing the C VLA
/// `mappings[num_mappings]`; far above realistic process map counts.
pub const MAX_MAPPINGS: usize = 4096;

/// Max stored path length per mapping (`FNAME_MAX` in the C).
pub const FNAME_MAX: usize = 256;

/// AUXV terminator type.
const AT_NULL: u64 = 0;
/// AUXV entry type carrying the vDSO base address.
const AT_SYSINFO_EHDR: u64 = 33;

/// Raw `/proc/self/maps` bit for the private/shared permission column.
const MAPS_PRIVATE: u16 = 1;
/// Raw `/proc/self/maps` bit for execute permission.
const MAPS_EXECUTE: u16 = MAPS_PRIVATE << 1;
/// Raw `/proc/self/maps` bit for write permission.
const MAPS_WRITE: u16 = MAPS_PRIVATE << 2;
/// Raw `/proc/self/maps` bit for read permission.
const MAPS_READ: u16 = MAPS_PRIVATE << 3;
/// Number of low bits to drop when converting raw `rwxp` bits to ELF `PF_*`.
const MAPS_PRIVATE_SHARED_BITS: u32 = 1;
/// Mask covering all ELF segment access bits.
const ELF_ACCESS_MASK: u16 = (PF_R | PF_W | PF_X) as u16;
/// ELF segment read permission bit.
const ELF_READ: u16 = PF_R as u16;
/// ELF segment write permission bit.
const ELF_WRITE: u16 = PF_W as u16;

/// Mapping permission flags. Before [`finalize_mappings`], this holds the raw
/// `/proc/self/maps` `rwxp` bits; after finalization, it holds ELF `PF_*` bits.
#[derive(Clone, Copy, Default)]
pub struct Perms(pub u16);

impl Perms {
    /// True when the mapping has read permission.
    pub fn readable(self) -> bool {
        self.0 & MAPS_READ != 0
    }
    /// True when the mapping has write permission.
    pub fn writable(self) -> bool {
        self.0 & MAPS_WRITE != 0
    }
    /// True when the mapping has execute permission.
    pub fn executable(self) -> bool {
        self.0 & MAPS_EXECUTE != 0
    }
    /// True when the mapping is private rather than shared.
    pub fn private(self) -> bool {
        self.0 & MAPS_PRIVATE != 0
    }

    /// Convert raw `/proc/self/maps` `rwxp` bits to ELF `PF_*` access bits.
    const fn elf_access_bits(self) -> Self {
        Self((self.0 >> MAPS_PRIVATE_SHARED_BITS) & ELF_ACCESS_MASK)
    }

    /// True when finalized ELF permissions contain `PF_R`.
    const fn elf_readable(self) -> bool {
        self.0 & ELF_READ != 0
    }

    /// True when finalized ELF permissions contain `PF_W`.
    const fn elf_writable(self) -> bool {
        self.0 & ELF_WRITE != 0
    }
}

/// One parsed memory mapping.
///
/// `flags` after [`parse_self_maps`] holds the raw `rwxp` bits; after
/// [`finalize_mappings`] it is shifted to ELF `PF_*` bits (dropping the
/// private/shared bit) to match the C's `(flags >> 1) & PF_MASK`.
/// `write_size` is the number of bytes of this segment actually written to the
/// core (0 until [`finalize_mappings`] computes it).
#[derive(Clone, Copy)]
pub struct Mapping {
    /// Inclusive start virtual address.
    pub start: usize,
    /// Exclusive end virtual address.
    pub end: usize,
    /// File offset from `/proc/self/maps`.
    pub offset: usize,
    /// Mapping permission bits.
    pub flags: Perms,
    /// True when the mapping has no file-backed path.
    pub is_anon: bool,
    /// Number of bytes to write for this mapping.
    pub write_size: usize,
    /// smaps `VmFlags: dd` - exclude from dump.
    pub dontdump: bool,
    /// smaps reported any anonymous pages (`Anonymous:` line > 0).
    pub has_anon_pages: bool,
    /// device mapping (under /dev/, excluding /dev/zero).
    pub is_device: bool,
    /// Length of the stored mapping path.
    pub name_len: u32,
    /// NUL-terminated mapping path bytes.
    pub name: [u8; FNAME_MAX],
}

impl Mapping {
    /// Return an empty mapping record.
    const fn zeroed() -> Self {
        Mapping {
            start: 0,
            end: 0,
            offset: 0,
            flags: Perms(0),
            is_anon: false,
            write_size: 0,
            dontdump: false,
            has_anon_pages: false,
            is_device: false,
            name_len: 0,
            name: [0u8; FNAME_MAX],
        }
    }

    /// The file path of this mapping, as bytes (empty for anonymous).
    pub fn path(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// ELF `PF_*` access bits (valid after [`finalize_mappings`]).
    pub fn pf_flags(&self) -> u32 {
        self.flags.0 as u32 & ELF_ACCESS_MASK as u32
    }
}

/// Error returned while parsing `/proc/self/maps`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseMapsError {
    /// Opening `/proc/self/maps` failed with this kernel errno.
    Open(i32),
    /// A maps line was incomplete or did not match the expected kernel format.
    Malformed,
}

impl ParseMapsError {
    /// Convert to the errno-style value used by the legacy C-facing API.
    pub const fn errno(self) -> i32 {
        match self {
            ParseMapsError::Open(errno) => errno,
            ParseMapsError::Malformed => EINVAL,
        }
    }
}

/// `open(2)` retrying on EINTR, for a C string path.
fn open_ro(path: &CStr) -> Result<i32, i32> {
    loop {
        match unsafe { sys::open(path.as_ptr(), O_RDONLY, 0) } {
            Err(EINTR) => continue,
            Ok(fd) => return Ok(fd as i32),
            Err(e) => return Err(e),
        }
    }
}

/// Parse `/proc/self/maps` into `out`, returning the number of mappings filled.
/// Port of the maps-counting + header-line parse in `CreateElfCore` (we read
/// the `maps` header line: `start-end perms offset dev inode path`).
///
/// Stops at `out.len()` mappings.
///
/// # Errors
/// Returns [`ParseMapsError::Open`] on open failure or
/// [`ParseMapsError::Malformed`] for malformed map lines.
pub fn parse_self_maps(out: &mut [Mapping]) -> Result<usize, ParseMapsError> {
    let fd = open_ro(c"/proc/self/maps").map_err(ParseMapsError::Open)?;
    let mut io = Io::new(fd);
    let mut n = 0usize;

    // Prime the first character of the first line.
    let mut ch = io.get_char();

    while n < out.len() {
        let first = match ch {
            Some(c) => c,
            None => break, // clean EOF
        };
        let m = &mut out[n];
        *m = Mapping::zeroed();

        // start-end
        let (start, t1) = io.get_hex_with_init_char(first);
        if t1 != Some(b'-') {
            sys::close(fd).ok();
            return Err(ParseMapsError::Malformed);
        }
        let (end, t2) = io.get_hex();
        if t2 != Some(b' ') {
            sys::close(fd).ok();
            return Err(ParseMapsError::Malformed);
        }
        m.start = start;
        m.end = end;

        // perms: rwxp, packed by shifting in 1 for each non-'-'.
        let mut flags: u16 = 0;
        loop {
            match io.get_char() {
                Some(b' ') => break,
                Some(c) => flags = (flags << 1) | ((c != b'-') as u16),
                None => {
                    sys::close(fd).ok();
                    return Err(ParseMapsError::Malformed);
                }
            }
        }
        m.flags = Perms(flags);

        // offset
        let (offset, t3) = io.get_hex();
        m.offset = offset;
        ch = t3;
        if ch != Some(b' ') {
            sys::close(fd).ok();
            return Err(ParseMapsError::Malformed);
        }

        // Skip device (maj:min) and inode fields: two whitespace-delimited
        // tokens, mirroring the C's two-pass skip.
        for _ in 0..2 {
            while ch == Some(b' ') {
                ch = io.get_char();
            }
            while ch != Some(b' ') && ch != Some(b'\n') && ch.is_some() {
                ch = io.get_char();
            }
            while ch == Some(b' ') {
                ch = io.get_char();
            }
        }

        // Filename: rest of line, truncated to FNAME_MAX-1, trailing spaces
        // trimmed.
        let mut len = 0usize;
        while ch != Some(b'\n') {
            match ch {
                None => break,
                Some(c) => {
                    if len < FNAME_MAX - 1 {
                        m.name[len] = c;
                        len += 1;
                    }
                }
            }
            ch = io.get_char();
        }
        while len > 0 && m.name[len - 1] == b' ' {
            len -= 1;
        }
        m.name[len] = 0;
        m.name_len = len as u32;
        m.is_anon = len == 0 || m.name[0] == b'[';
        m.is_device = is_device_path(&m.name[..len]);

        n += 1;

        // Advance past the newline to the first char of the next line.
        if ch == Some(b'\n') {
            ch = io.get_char();
        } else if ch.is_none() {
            break;
        }
    }

    sys::close(fd).ok();
    Ok(n)
}

/// True if `name` is a device mapping under `/dev/`, excluding `/dev/zero`
/// (which is treated as ordinary anonymous-ish memory). Port of the C
/// `is_device` check.
fn is_device_path(name: &[u8]) -> bool {
    const DEV: &[u8] = b"/dev/";
    const ZERO: &[u8] = b"zero";
    if name.len() < DEV.len() || &name[..DEV.len()] != DEV {
        return false;
    }
    // /dev/zero is NOT a device for our purposes.
    !(name.len() == DEV.len() + ZERO.len() && &name[DEV.len()..] == ZERO)
}

/// Enrich the parsed mappings with smaps detail (`VmFlags: dd`, anonymous
/// pages), then apply the C's keep/skip rules and compute `write_size`,
/// returning the number of mappings kept (compacted to the front of `maps`).
///
/// Mirrors the back half of the smaps loop in `CreateElfCore`:
/// 1. drop the private/shared bit: `flags = (flags >> 1) & PF_MASK`;
/// 2. skip device / dontdump / non-readable mappings;
/// 3. skip leading zero pages and zero-sized segments;
/// 4. compute `write_size`: full size if anon / has-anon-pages / writable; else
///    one page if it's a file-backed ELF header (offset 0, starts with ELFMAG);
///    else 0.
///
/// `loopback` is a pipe pair for the [`crate::io::leading_zeros`] safe page
/// scan; `scratch` must be at least `pagesize` bytes.
///
/// # Safety
/// Reads mapping memory (indirectly, through the loopback pipe). Must run while
/// the address space is stable (threads suspended), with `[start,end)` valid in
/// this process's VM.
pub unsafe fn finalize_mappings(
    maps: &mut [Mapping],
    n: usize,
    pagesize: usize,
    loopback: &Pipe,
    scratch: &mut [u8],
) -> usize {
    // Pull dontdump / anonymous-page hints from /proc/self/smaps. Best-effort:
    // if smaps is unavailable we proceed with maps-only info.
    enrich_from_smaps(maps, n);

    let mut kept = 0usize;
    for idx in 0..n {
        let mut m = maps[idx];
        // 1. ELF access bits.
        m.flags = m.flags.elf_access_bits();

        // 2. skip device / dontdump / non-readable.
        let readable = m.flags.elf_readable();
        if m.is_device || m.dontdump || !readable {
            continue;
        }

        // 3. skip leading zero pages, then drop if now empty.
        let len = m.end - m.start;
        let lead = unsafe { leading_zeros(loopback, m.start as *const u8, len, pagesize, scratch) };
        m.start += lead;
        if m.end == m.start {
            continue;
        }

        // 4. write_size.
        let writable = m.flags.elf_writable();
        if m.is_anon || m.has_anon_pages || writable {
            m.write_size = m.end - m.start;
        } else if !m.is_anon && m.offset == 0 && readable && first_bytes_are_elf(m.start) {
            m.write_size = pagesize;
        } else {
            m.write_size = 0;
        }

        maps[kept] = m;
        kept += 1;
    }
    let _ = ELFMAG;
    kept
}

/// Check the first 4 bytes at `addr` equal the ELF magic. Reads memory directly;
/// only called for readable file-backed mappings, so the page is mapped.
fn first_bytes_are_elf(addr: usize) -> bool {
    // SAFETY: caller guarantees `addr` is the start of a readable mapping.
    let p = addr as *const u8;
    unsafe {
        p.read_volatile() == ELFMAG[0]
            && p.add(1).read_volatile() == ELFMAG[1]
            && p.add(2).read_volatile() == ELFMAG[2]
            && p.add(3).read_volatile() == ELFMAG[3]
    }
}

/// Read `/proc/self/smaps` and set `dontdump` / `has_anon_pages` on each mapping
/// by matching the per-segment header line's start address. Best-effort: if
/// smaps cannot be opened or a section cannot be matched, the maps-only dump
/// policy still applies.
fn enrich_from_smaps(maps: &mut [Mapping], n: usize) {
    let fd = match open_ro(c"/proc/self/smaps") {
        Ok(fd) => fd,
        Err(_) => return,
    };
    let mut io = Io::new(fd);
    // Index in `maps` for the smaps section currently being scanned. `None`
    // means the section did not correspond to one of the parsed map entries.
    let mut cur: Option<usize> = None;

    // smaps is a sequence of sections. Each section starts with a maps-like
    // header line, followed by detail lines for that mapping. We only need the
    // header start address to select `cur`, then two detail lines:
    // `Anonymous:` (>0 => has_anon_pages) and `VmFlags:` containing `dd`.
    let mut line = [0u8; 256];
    loop {
        let mut len = 0usize;
        let mut ch = io.get_char();
        if ch.is_none() {
            break;
        }
        // A bounded line buffer is enough here: the fields we consume are near
        // the start of their lines, and long path/header tails can be ignored.
        while let Some(c) = ch {
            if c == b'\n' {
                break;
            }
            if len < line.len() {
                line[len] = c;
                len += 1;
            }
            ch = io.get_char();
        }
        let l = &line[..len];
        if is_header_line(l) {
            // Header lines begin with the mapping start address. Matching on
            // `start` is sufficient because this follows `parse_self_maps`,
            // which built `maps` from the same process snapshot.
            let mut val = 0usize;
            for &b in l {
                match b {
                    b'0'..=b'9' => val = (val << 4) | (b - b'0') as usize,
                    b'a'..=b'f' => val = (val << 4) | ((b - b'a') as usize + 10),
                    b'A'..=b'F' => val = (val << 4) | ((b - b'A') as usize + 10),
                    _ => break,
                }
            }
            cur = (0..n).find(|&i| maps[i].start == val);
        } else if let Some(i) = cur {
            // Detail lines only apply after a matched header. Unmatched smaps
            // sections are ignored rather than failing the whole dump.
            if let Some(rest) = strip_prefix(l, b"Anonymous:") {
                // `Anonymous:` counts private anonymous pages inside this VMA.
                // If a file-backed mapping has any, its contents are no longer
                // fully recoverable from the file, so dump the segment bytes.
                if number_after(rest) > 0 {
                    maps[i].has_anon_pages = true;
                }
            } else if strip_prefix(l, b"VmFlags:").is_some() && contains_token(l, b"dd") {
                // `dd` is the kernel's VM_DONTDUMP flag, commonly set via
                // MADV_DONTDUMP. Match Linux core-dump policy and skip it.
                maps[i].dontdump = true;
            }
        }
    }
    sys::close(fd).ok();
}

/// True if an smaps line starts a mapping header.
fn is_header_line(l: &[u8]) -> bool {
    // Header lines start with a hex digit (address range). Detail lines start
    // with an uppercase letter (e.g. "Size:", "VmFlags:").
    matches!(l.first(), Some(b'0'..=b'9' | b'a'..=b'f'))
}

/// Strip a byte prefix from a line.
fn strip_prefix<'a>(l: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if l.len() >= prefix.len() && &l[..prefix.len()] == prefix {
        Some(&l[prefix.len()..])
    } else {
        None
    }
}

/// Parse the first decimal number after optional ASCII whitespace.
fn number_after(mut s: &[u8]) -> u64 {
    while let Some(&b) = s.first() {
        if b == b' ' || b == b'\t' {
            s = &s[1..];
        } else {
            break;
        }
    }
    let mut v = 0u64;
    for &b in s {
        if b.is_ascii_digit() {
            v = v * 10 + (b - b'0') as u64;
        } else {
            break;
        }
    }
    v
}

/// True if `token` appears as a whitespace-delimited field in `l`.
fn contains_token(l: &[u8], token: &[u8]) -> bool {
    // Whitespace-delimited token search (so "dd" doesn't match inside another).
    let mut i = 0;
    while i < l.len() {
        // skip whitespace
        while i < l.len() && (l[i] == b' ' || l[i] == b'\t') {
            i += 1;
        }
        let start = i;
        while i < l.len() && l[i] != b' ' && l[i] != b'\t' {
            i += 1;
        }
        if &l[start..i] == token {
            return true;
        }
    }
    false
}

/// Read `/proc/self/auxv`: returns `(num_auxv, vdso_ehdr_address)`. Port of
/// `CountAUXV`. `vdso_ehdr` is 0 if no `AT_SYSINFO_EHDR` entry is present.
pub fn count_auxv() -> (usize, usize) {
    let mut num_auxv = 0usize;
    let mut vdso_ehdr = 0usize;
    let fd = match open_ro(c"/proc/self/auxv") {
        Ok(fd) => fd,
        Err(_) => return (0, 0),
    };
    // Each entry is two u64 words (a_type, a_val) on x86_64.
    let mut entry = [0u64; 2];
    loop {
        let n = loop {
            match unsafe {
                sys::read(
                    fd,
                    entry.as_mut_ptr() as *mut c_void,
                    mem::size_of::<[u64; 2]>(),
                )
            } {
                Err(EINTR) => continue,
                other => break other,
            }
        };
        match n {
            Ok(sz) if sz == mem::size_of::<[u64; 2]>() => {
                num_auxv += 1;
                if entry[0] == AT_SYSINFO_EHDR {
                    vdso_ehdr = entry[1] as usize;
                }
                if entry[0] == AT_NULL {
                    break;
                }
            }
            _ => break,
        }
    }
    sys::close(fd).ok();
    (num_auxv, vdso_ehdr)
}

/// True when `value` is aligned to the power-of-two `align` boundary.
#[inline]
const fn is_aligned_to(value: usize, align: usize) -> bool {
    value & (align - 1) == 0
}

/// Verify an alleged VDSO `Ehdr` is internally sane and fully within
/// `[start, end)`. Returns the pointer back if valid, else `None`. Faithful
/// port of `SanitizeVDSO`.
///
/// # Safety
/// `ehdr_addr` is treated as an in-memory ELF header to be validated; this
/// function only reads through it after bounds/alignment checks, but the caller
/// must ensure `[start, end)` is the mapping the VDSO is supposed to occupy.
pub unsafe fn sanitize_vdso(ehdr_addr: usize, start: usize, end: usize) -> Option<usize> {
    let align = mem::size_of::<usize>();
    if ehdr_addr == 0 || !is_aligned_to(ehdr_addr, align) {
        return None;
    }
    if end <= ehdr_addr + mem::size_of::<Ehdr>() {
        return None;
    }
    // SAFETY: alignment and the lower bound on `end` are checked above.
    let ehdr = unsafe { &*(ehdr_addr as *const Ehdr) };
    if !is_aligned_to(ehdr.e_phoff as usize, align) {
        return None;
    }
    let phdr_addr = ehdr_addr + ehdr.e_phoff as usize;
    let phnum = ehdr.e_phnum as usize;
    let phdr_end = phdr_addr + phnum * mem::size_of::<Phdr>();
    if phdr_addr <= start || end <= phdr_end {
        return None;
    }
    // SAFETY: the Phdr array is fully within (start, end] per the check above.
    let phdrs = unsafe { slice::from_raw_parts(phdr_addr as *const Phdr, phnum) };
    if phnum == 0 {
        return None;
    }
    if phdrs[0].p_type != PT_LOAD
        || phdrs[0].p_vaddr as usize != start
        || (phdrs[0].p_vaddr + phdrs[0].p_memsz) as usize >= end
    {
        return None;
    }
    for ph in &phdrs[1..] {
        if ph.p_type == PT_LOAD {
            return None; // only one PT_LOAD, at index 0
        }
        if !is_aligned_to(ph.p_vaddr as usize, align) {
            return None;
        }
        if (ph.p_vaddr as usize) <= start || end <= (ph.p_vaddr + ph.p_filesz) as usize {
            return None;
        }
    }
    Some(ehdr_addr)
}

/// Allocate a zeroed mapping array on the caller's stack. Helper so callers can
/// write `let mut maps = mapping_buf();` without spelling out the array type.
pub const fn mapping_buf() -> [Mapping; MAX_MAPPINGS] {
    [Mapping::zeroed(); MAX_MAPPINGS]
}
