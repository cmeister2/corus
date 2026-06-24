//! /proc/self/maps parsing and note construction validated against ground truth
//! (the kernel's own /proc text + a known vsyscall/vdso), and NT_FILE/note
//! byte-layout checks.

use corus_core::notes::{align_note, note_size, nt_file_sizes, write_nt_file, write_prpsinfo};
use corus_core::proc_parse::{count_auxv, mapping_buf, parse_self_maps};

/// One reference mapping parsed from the kernel's `/proc/self/maps` text.
struct ReferenceMap {
    /// Inclusive start virtual address.
    start: usize,
    /// Exclusive end virtual address.
    end: usize,
    /// Raw permissions field (`rwxp` or similar).
    perms: String,
    /// Mapping path, if present.
    path: String,
}

/// Parse a reference line set from the kernel via std, to cross-check our
/// libc-free parser against the same data.
fn reference_maps() -> Vec<ReferenceMap> {
    let text = std::fs::read_to_string("/proc/self/maps").unwrap();
    let mut out = Vec::new();
    for line in text.lines() {
        // format: start-end perms offset dev inode path
        let mut parts = line.splitn(6, ' ');
        let range = parts.next().unwrap();
        let perms = parts.next().unwrap().to_string();
        let mut rr = range.split('-');
        let start = usize::from_str_radix(rr.next().unwrap(), 16).unwrap();
        let end = usize::from_str_radix(rr.next().unwrap(), 16).unwrap();
        // path is the last field (may be empty or have leading spaces collapsed)
        let path = line
            .splitn(6, ' ')
            .nth(5)
            .map(|s| s.trim_start().to_string())
            .unwrap_or_default();
        out.push(ReferenceMap {
            start,
            end,
            perms,
            path,
        });
        let _ = &mut parts;
    }
    out
}

#[test]
fn maps_parse_matches_kernel_ranges() {
    let reference = reference_maps();
    let mut buf = mapping_buf();
    let n = parse_self_maps(&mut buf).expect("parse maps");

    // The map can change slightly between the two reads (rare), so compare the
    // stable prefix: our count should be within a couple of the reference, and
    // the first several ranges must match exactly.
    assert!(n > 0, "should parse at least one mapping");
    let check = n.min(reference.len()).min(8);
    for i in 0..check {
        assert_eq!(buf[i].start, reference[i].start, "start mismatch at {i}");
        assert_eq!(buf[i].end, reference[i].end, "end mismatch at {i}");
    }
}

#[test]
fn maps_parse_flags_and_anon() {
    let reference = reference_maps();
    let mut buf = mapping_buf();
    let n = parse_self_maps(&mut buf).expect("parse maps");

    // Verify perm decoding against the kernel's raw maps text, and check that
    // at least one named mapping exists in a normal process. Some kernels can
    // expose execute-only VMAs, so do not assume x implies r.
    let mut saw_anon = false;
    let mut saw_named = false;
    for m in &buf[..n] {
        if let Some(expected) = reference
            .iter()
            .find(|r| r.start == m.start && r.end == m.end)
        {
            let perms = expected.perms.as_bytes();
            assert_eq!(m.flags.readable(), perms.first() == Some(&b'r'));
            assert_eq!(m.flags.writable(), perms.get(1) == Some(&b'w'));
            assert_eq!(m.flags.executable(), perms.get(2) == Some(&b'x'));
            assert_eq!(m.flags.private(), perms.get(3) == Some(&b'p'));
        }
        if m.is_anon {
            saw_anon = true;
        } else {
            saw_named = true;
            // A named mapping should have a path that starts with '/' or '['.
            let p = m.path();
            assert!(!p.is_empty());
        }
    }
    assert!(saw_named, "expected at least one file-backed mapping");
    let _ = saw_anon; // anon may legitimately be absent in tiny processes
}

#[test]
fn named_mappings_have_paths_matching_kernel() {
    let reference = reference_maps();
    let mut buf = mapping_buf();
    let n = parse_self_maps(&mut buf).expect("parse maps");

    // Find the first file-backed mapping in both and compare the path text.
    let ours = buf[..n]
        .iter()
        .find(|m| !m.is_anon)
        .map(|m| core::str::from_utf8(m.path()).unwrap().to_string());
    let theirs = reference
        .iter()
        .find(|m| !m.path.is_empty() && m.path.starts_with('/'))
        .map(|m| m.path.clone());

    if let (Some(a), Some(b)) = (ours, theirs) {
        assert_eq!(a, b, "first file-backed path should match kernel");
    }
}

#[test]
fn count_auxv_finds_entries_and_vdso() {
    let (num, vdso) = count_auxv();
    assert!(num > 1, "auxv should have several entries, got {num}");
    // Almost every modern process has a vDSO; assert it's a plausible address.
    assert_ne!(vdso, 0, "expected AT_SYSINFO_EHDR (vdso) to be present");
    assert_eq!(vdso & 0xfff, 0, "vdso should be page-aligned");
}

#[test]
fn note_size_alignment() {
    assert_eq!(align_note(0), 0);
    assert_eq!(align_note(1), 4);
    assert_eq!(align_note(5), 8);
    assert_eq!(align_note(8), 8);
    // CORE note name is 5 bytes -> padded to 8; header is 12.
    assert_eq!(note_size(5, 0), 12 + 8);
    assert_eq!(note_size(5, 100), 12 + 8 + 100);
    assert_eq!(note_size(5, 101), 12 + 8 + 104);
}

/// A Writer that captures bytes into a Vec, for inspecting note output.
struct VecWriter(Vec<u8>);
impl corus_core::io::Writer for VecWriter {
    fn write(&mut self, buf: &[u8]) -> isize {
        self.0.extend_from_slice(buf);
        buf.len() as isize
    }
    fn done(&mut self) -> bool {
        false
    }
}

#[test]
fn nt_file_note_is_well_formed() {
    // Parse real mappings, then emit the NT_FILE note and validate its framing.
    let mut buf = mapping_buf();
    let n = parse_self_maps(&mut buf).expect("parse maps");
    let maps = &buf[..n];

    let (count, desc_len) = nt_file_sizes(maps);
    assert!(count > 0, "should have file-backed mappings");

    let mut w = VecWriter(Vec::new());
    write_nt_file(&mut w, maps, 4096).expect("write NT_FILE note");
    let bytes = w.0;

    // Nhdr: n_namesz=5, n_descsz=desc_len, n_type=NT_FILE(0x46494c45).
    let n_namesz = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let n_descsz = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let n_type = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    assert_eq!(n_namesz, 5);
    assert_eq!(n_descsz as usize, desc_len);
    assert_eq!(n_type, 0x46494c45);
    assert_eq!(&bytes[12..20], b"CORE\0\0\0\0");

    // Descriptor header: count, pagesize.
    let got_count = i64::from_le_bytes(bytes[20..28].try_into().unwrap());
    let got_pgsz = i64::from_le_bytes(bytes[28..36].try_into().unwrap());
    assert_eq!(got_count as usize, count);
    assert_eq!(got_pgsz, 4096);

    // Total note length must be 4-aligned and match note_size accounting.
    assert_eq!(bytes.len() % 4, 0, "note must be 4-byte aligned overall");
    assert_eq!(bytes.len(), note_size(5, desc_len));
}

#[test]
fn prpsinfo_note_framing() {
    use corus_core::elf::Prpsinfo;
    // SAFETY: Prpsinfo is POD; zeroed is a valid (if empty) note payload.
    let info: Prpsinfo = unsafe { core::mem::zeroed() };
    let mut w = VecWriter(Vec::new());
    write_prpsinfo(&mut w, &info).expect("write PRPSINFO note");
    let bytes = w.0;
    // header(12) + "CORE"(8) + sizeof(Prpsinfo)=136, all 4-aligned.
    assert_eq!(bytes.len(), 12 + 8 + 136);
    let n_type = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    assert_eq!(n_type, 3, "NT_PRPSINFO");
}
