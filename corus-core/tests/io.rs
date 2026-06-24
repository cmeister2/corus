//! IO-layer tests: GetHex/GetHexWithInitChar,
//! LeadingZeros, and the limit/truncation writer.
//!
//! These exercise the real syscalls via temp files and pipes, since the helpers
//! wrap `c_read`/`c_write` over actual fds.

use core::ffi::{c_int, c_void};
use corus_core::io::{Io, LimitWriter, Pipe, SimpleWriter, Writer, c_write, leading_zeros};
use std::env::temp_dir;
use std::fs::{File, OpenOptions, remove_file};
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

/// Write `content` to a temp file and return an open RDONLY fd positioned at 0,
/// plus the File to keep it alive.
fn temp_fd_with(content: &[u8]) -> (File, c_int) {
    let mut f = tempfile();
    f.write_all(content).unwrap();
    f.seek(SeekFrom::Start(0)).unwrap();
    let fd = f.as_raw_fd();
    (f, fd)
}

fn tempfile() -> File {
    // Minimal tempfile without external crates: open a unique path O_RDWR and
    // unlink it so it disappears on close.
    let path = temp_dir().join(format!(
        "cd_io_{}_{}.tmp",
        process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    let _ = remove_file(&path); // unlink; fd stays valid
    f
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

#[test]
fn get_hex_parses_maps_style_line() {
    // A representative /proc/self/maps prefix: "address-range perms ..."
    let (_f, fd) = temp_fd_with(b"7f3c0a1b2000-7f3c0a1c3000 r-xp 00000000");
    let mut io = Io::new(fd);

    // First hex run = start address; terminator should be '-'.
    let (start, t1) = io.get_hex();
    assert_eq!(start, 0x7f3c_0a1b_2000);
    assert_eq!(t1, Some(b'-'));

    // Second hex run = end address; terminator should be ' '.
    let (end, t2) = io.get_hex();
    assert_eq!(end, 0x7f3c_0a1c_3000);
    assert_eq!(t2, Some(b' '));
    assert!(end > start);
}

#[test]
fn get_hex_with_init_char_uses_supplied_first_char() {
    // Suppose the caller already consumed 'a' and wants it counted as the first
    // hex digit of the value.
    let (_f, fd) = temp_fd_with(b"bc ");
    let mut io = Io::new(fd);
    let (val, term) = io.get_hex_with_init_char(b'a');
    assert_eq!(val, 0xabc);
    assert_eq!(term, Some(b' '));
}

#[test]
fn get_hex_handles_uppercase_and_eof() {
    let (_f, fd) = temp_fd_with(b"DEADBEEF");
    let mut io = Io::new(fd);
    let (val, term) = io.get_hex();
    assert_eq!(val, 0xDEAD_BEEF);
    assert_eq!(term, None, "should hit EOF after the last digit");
}

#[test]
fn get_char_reads_then_eofs() {
    let (_f, fd) = temp_fd_with(b"Xy");
    let mut io = Io::new(fd);
    assert_eq!(io.get_char(), Some(b'X'));
    assert_eq!(io.get_char(), Some(b'y'));
    assert_eq!(io.get_char(), None);
}

#[test]
fn limit_writer_truncates_at_max_length() {
    // Write into a pipe; LimitWriter should cap total output at max_length.
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(rc, 0);

    let mut w = LimitWriter {
        fd: fds[1],
        max_length: 10,
    };
    // First write of 6 bytes: fully accepted.
    assert_eq!(w.write(b"123456"), 6);
    assert!(!w.done());
    // Second write of 8 bytes: only 4 remaining -> truncated to 4.
    assert_eq!(w.write(b"ABCDEFGH"), 4);
    assert!(w.done(), "should be exhausted at max_length");
    // Further writes produce 0.
    assert_eq!(w.write(b"more"), 0);

    // Read back exactly 10 bytes: "123456ABCD".
    let mut buf = [0u8; 32];
    let n = unsafe { libc::read(fds[0], buf.as_mut_ptr() as *mut c_void, buf.len()) };
    assert_eq!(n, 10);
    assert_eq!(&buf[..10], b"123456ABCD");

    unsafe {
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
}

#[test]
fn simple_writer_writes_all() {
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(rc, 0);
    let mut w = SimpleWriter { fd: fds[1] };
    assert_eq!(w.write(b"hello world"), 11);
    assert!(!w.done());
    let mut buf = [0u8; 16];
    let n = unsafe { libc::read(fds[0], buf.as_mut_ptr() as *mut c_void, buf.len()) };
    assert_eq!(n, 11);
    assert_eq!(&buf[..11], b"hello world");
    unsafe {
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
}

#[test]
fn leading_zeros_counts_zero_pages() {
    let pagesize = 4096usize;
    // Two zero pages followed by a page starting with a non-zero byte.
    let mut mem = vec![0u8; pagesize * 3];
    mem[pagesize * 2] = 0x42; // first non-zero byte at start of 3rd page

    let loopback = Pipe::new().expect("pipe");

    let mut scratch = vec![0u8; pagesize];
    let n = unsafe { leading_zeros(&loopback, mem.as_ptr(), mem.len(), pagesize, &mut scratch) };
    assert_eq!(
        n,
        pagesize * 2,
        "should count exactly two leading zero pages"
    );
}

#[test]
fn leading_zeros_all_zero_region() {
    let pagesize = 4096usize;
    let mem = vec![0u8; pagesize * 2];
    let loopback = Pipe::new().expect("pipe");
    let mut scratch = vec![0u8; pagesize];
    let n = unsafe { leading_zeros(&loopback, mem.as_ptr(), mem.len(), pagesize, &mut scratch) };
    assert_eq!(n, pagesize * 2);
}

#[test]
fn c_write_writes_full_buffer() {
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let data = b"abcdefghij";
    let n = unsafe { c_write(fds[1], data.as_ptr() as *const c_void, data.len()) }.unwrap();
    assert_eq!(n, data.len());
    let mut buf = [0u8; 16];
    let r = unsafe { libc::read(fds[0], buf.as_mut_ptr() as *mut c_void, buf.len()) };
    assert_eq!(r as usize, data.len());
    assert_eq!(&buf[..data.len()], data);
    unsafe {
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
}
