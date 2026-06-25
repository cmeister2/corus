//! Tests for the C compatibility features: priority limiting (exact byte size),
//! extra notes (visible in readelf), and the pre-dump callback (success + abort
//! paths). Driven through the C ABI, since that's the surface
//! `coredumper_unittest.c` uses.

mod common;

use core::ffi::{c_char, c_int, c_void};
use core::mem;
use core::ptr;
use corus::params::{CoreDumpParameters, CoredumperCompressor, CoredumperNote};
use std::env::temp_dir;
use std::ffi::{CString, OsString};
use std::fs::remove_file;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::process::{self, Command};
use std::sync::atomic::{AtomicI32, Ordering};

use common::ptrace_denied;

unsafe extern "C" {
    // From the C ABI (linked into this crate).
    safe fn WriteCoreDumpLimited(file_name: *const c_char, max_length: usize) -> c_int;
    safe fn WriteCoreDumpLimitedByPriority(file_name: *const c_char, max_length: usize) -> c_int;
    safe fn WriteCompressedCoreDump(
        file_name: *const c_char,
        max_length: usize,
        compressors: *const CoredumperCompressor,
        selected_compressor: *mut *mut CoredumperCompressor,
    ) -> c_int;
    safe fn WriteCoreDumpWith(params: *const CoreDumpParameters, file_name: *const c_char)
    -> c_int;
    safe fn ClearCoreDumpParametersInternal(params: *mut CoreDumpParameters, size: usize);
    safe fn SetCoreDumpNotes(
        params: *mut CoreDumpParameters,
        notes: *mut CoredumperNote,
        note_count: c_int,
    ) -> c_int;
    safe fn SetCoreDumpLimited(params: *mut CoreDumpParameters, max_length: usize) -> c_int;
    safe fn SetCoreDumpCompressed(
        params: *mut CoreDumpParameters,
        compressors: *const CoredumperCompressor,
        selected_compressor: *mut *mut CoredumperCompressor,
    ) -> c_int;
    safe fn SetCoreDumpCallback(
        params: *mut CoreDumpParameters,
        func: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
        arg: *mut c_void,
    ) -> c_int;
}

#[test]
fn priority_limit_produces_exact_size() -> Result<(), Box<dyn std::error::Error>> {
    let core = temp_dir().join(format!("cd_prio_{}.core", process::id()));
    let path = CString::new(core.to_str().unwrap())?;

    // Size 0 -> no file (matches the C unit test).
    let _ = remove_file(&core);
    let rc = WriteCoreDumpLimitedByPriority(path.as_ptr(), 0);
    if ptrace_denied(rc, "priority size-0 dump") {
        return Ok(());
    }
    assert!(!core.exists(), "size-0 priority dump should write no file");

    // Size 60000 -> exactly 60000 bytes (the C unit test's assertion).
    let rc = WriteCoreDumpLimitedByPriority(path.as_ptr(), 60000);
    if ptrace_denied(rc, "priority size-limited dump") {
        return Ok(());
    }
    let len = core.metadata().expect("core exists").len();
    assert_eq!(
        len, 60000,
        "priority-limited core must be exactly 60000 bytes"
    );
    let _ = remove_file(&core);
    Ok(())
}

fn uncompressed_compressor_table(empty: &CString) -> [CoredumperCompressor; 2] {
    [
        CoredumperCompressor {
            compressor: empty.as_ptr(),
            args: core::ptr::null(),
            suffix: empty.as_ptr(),
        },
        CoredumperCompressor {
            compressor: core::ptr::null(),
            args: core::ptr::null(),
            suffix: core::ptr::null(),
        },
    ]
}

#[test]
fn write_compressed_coredump_honors_limit() -> Result<(), Box<dyn std::error::Error>> {
    let core = temp_dir().join(format!("cd_c_compress_limit_{}.core", process::id()));
    let path = CString::new(core.as_os_str().as_bytes())?;
    let _ = remove_file(&core);
    let empty = CString::new("")?;
    let compressors = uncompressed_compressor_table(&empty);
    let mut selected: *mut CoredumperCompressor = ptr::null_mut();
    let limit = 4096usize;

    let rc = WriteCompressedCoreDump(path.as_ptr(), limit, compressors.as_ptr(), &mut selected);
    if ptrace_denied(rc, "compressed limited dump") {
        return Ok(());
    }
    assert_eq!(selected, compressors.as_ptr() as *mut CoredumperCompressor);
    assert_eq!(core.metadata().expect("core exists").len() as usize, limit);
    let _ = remove_file(&core);
    Ok(())
}

#[test]
fn compressed_params_preserve_callback_and_limit() -> Result<(), Box<dyn std::error::Error>> {
    let core = temp_dir().join(format!("cd_c_params_compress_{}.core", process::id()));
    let path = CString::new(core.as_os_str().as_bytes())?;
    let _ = remove_file(&core);
    let empty = CString::new("")?;
    let compressors = uncompressed_compressor_table(&empty);
    let mut selected: *mut CoredumperCompressor = ptr::null_mut();
    let mut count: c_int = 0;
    let limit = 8192usize;

    let mut params: CoreDumpParameters = unsafe { mem::zeroed() };
    ClearCoreDumpParametersInternal(&mut params, mem::size_of::<CoreDumpParameters>());
    assert_eq!(
        SetCoreDumpCompressed(&mut params, compressors.as_ptr(), &mut selected),
        0
    );
    assert_eq!(SetCoreDumpLimited(&mut params, limit), 0);
    assert_eq!(
        SetCoreDumpCallback(
            &mut params,
            Some(ok_callback),
            &mut count as *mut c_int as *mut c_void
        ),
        0
    );

    let rc = WriteCoreDumpWith(&params, path.as_ptr());
    if ptrace_denied(rc, "compressed params dump") {
        return Ok(());
    }
    assert_eq!(selected, compressors.as_ptr() as *mut CoredumperCompressor);
    assert_eq!(count, 1, "callback should run on compressed params path");
    assert_eq!(core.metadata().expect("core exists").len() as usize, limit);
    let _ = remove_file(&core);
    Ok(())
}

#[test]
fn c_path_accepts_non_utf8_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = temp_dir();
    let control = tmp.join(format!("cd_utf8_control_{}.core", process::id()));
    let control_path = CString::new(control.as_os_str().as_bytes())?;
    let _ = remove_file(&control);

    let rc = WriteCoreDumpLimited(control_path.as_ptr(), 4096);
    if ptrace_denied(rc, "control dump") {
        return Ok(());
    }
    let _ = remove_file(&control);

    let mut name = format!("cd_nonutf8_{}", process::id()).into_bytes();
    name.push(0xff);
    name.extend_from_slice(b".core");
    let non_utf8 = tmp.join(OsString::from_vec(name));
    let non_utf8_path = CString::new(non_utf8.as_os_str().as_bytes())?;
    let _ = remove_file(&non_utf8);

    let rc = WriteCoreDumpLimited(non_utf8_path.as_ptr(), 4096);
    assert_eq!(rc, 0, "non-UTF-8 C path bytes should be accepted");
    assert_eq!(non_utf8.metadata().expect("core exists").len(), 4096);
    let _ = remove_file(&non_utf8);
    Ok(())
}

#[test]
fn extra_notes_appear_in_readelf() -> Result<(), Box<dyn std::error::Error>> {
    // Determine which readelf to use up front.
    let readelf = if which::which("eu-readelf").is_ok() {
        "eu-readelf"
    } else if which::which("readelf").is_ok() {
        "readelf"
    } else {
        eprintln!("skipping: no readelf");
        return Ok(());
    };

    let core = temp_dir().join(format!("cd_notes_{}.core", process::id()));
    let path = CString::new(core.to_str().unwrap())?;
    let _ = remove_file(&core);

    // One extra note with a distinctive vendor name + payload.
    let note_name = CString::new("COREDUMPER_TEST")?;
    let desc: [u8; 8] = *b"PAYLOAD!";
    let mut notes = [CoredumperNote {
        name: note_name.as_ptr(),
        r#type: 0x1234,
        description_size: desc.len() as u32,
        description: desc.as_ptr() as *const c_void,
    }];

    let mut params: CoreDumpParameters = unsafe { mem::zeroed() };
    ClearCoreDumpParametersInternal(&mut params, mem::size_of::<CoreDumpParameters>());
    assert_eq!(SetCoreDumpNotes(&mut params, notes.as_mut_ptr(), 1), 0);

    let rc = WriteCoreDumpWith(&params, path.as_ptr());
    if ptrace_denied(rc, "notes dump") {
        return Ok(());
    }

    // Confirm the note vendor name shows up in the note dump.
    let out = Command::new(readelf)
        .arg("-n")
        .arg(&core)
        .output()
        .expect("readelf");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("COREDUMPER_TEST") || text.contains("1234") || text.contains("0x1234"),
        "extra note should appear in readelf -n output:\n{text}"
    );
    let _ = remove_file(&core);
    Ok(())
}

/// corus extension flag: select the `InProcessFrozen` dump strategy. Must match
/// `COREDUMPER_FLAG_IN_PROCESS_FROZEN` in `capi.rs`.
const COREDUMPER_FLAG_IN_PROCESS_FROZEN: c_int = 1 << 16;

#[test]
fn in_process_frozen_flag_dumps_via_c_abi() -> Result<(), Box<dyn std::error::Error>> {
    let core = temp_dir().join(format!("cd_frozen_flag_{}.core", process::id()));
    let path = CString::new(core.to_str().unwrap())?;
    let _ = remove_file(&core);

    // Select the no-fork strategy purely through the C flags field.
    let mut params: CoreDumpParameters = unsafe { mem::zeroed() };
    ClearCoreDumpParametersInternal(&mut params, mem::size_of::<CoreDumpParameters>());
    params.flags |= COREDUMPER_FLAG_IN_PROCESS_FROZEN;

    let rc = WriteCoreDumpWith(&params, path.as_ptr());
    if ptrace_denied(rc, "in-process-frozen flag dump") {
        return Ok(());
    }
    // The flag must be accepted and still produce a valid, non-empty core.
    let len = core.metadata().expect("core exists").len();
    assert!(
        len > 0,
        "frozen-strategy dump should write a non-empty core"
    );
    let _ = remove_file(&core);
    Ok(())
}

static CALLBACK_HITS: AtomicI32 = AtomicI32::new(0);

unsafe extern "C" fn ok_callback(arg: *mut c_void) -> c_int {
    CALLBACK_HITS.fetch_add(1, Ordering::SeqCst);
    // arg points at an i32 we increment, mirroring the C MyCallback.
    if !arg.is_null() {
        unsafe {
            *(arg as *mut c_int) += 1;
        }
    }
    0 // proceed
}

unsafe extern "C" fn abort_callback(_arg: *mut c_void) -> c_int {
    1 // non-zero -> abort the dump
}

#[test]
fn callback_runs_and_can_abort() {
    let core = temp_dir().join(format!("cd_cb_{}.core", process::id()));
    let path = CString::new(core.to_str().unwrap()).unwrap();
    let _ = remove_file(&core);

    // Success path: callback returns 0, dump proceeds, arg incremented.
    let mut count: c_int = 0;
    let mut params: CoreDumpParameters = unsafe { mem::zeroed() };
    ClearCoreDumpParametersInternal(&mut params, mem::size_of::<CoreDumpParameters>());
    assert_eq!(SetCoreDumpLimited(&mut params, 0x10000), 0);
    assert_eq!(
        SetCoreDumpCallback(
            &mut params,
            Some(ok_callback),
            &mut count as *mut c_int as *mut c_void
        ),
        0
    );
    let rc = WriteCoreDumpWith(&params, path.as_ptr());
    if ptrace_denied(rc, "callback dump") {
        return;
    }
    assert_eq!(count, 1, "callback should have run exactly once");
    assert!(core.exists(), "dump should have been written");
    let _ = remove_file(&core);

    // Abort path: callback returns non-zero -> no file, rc != 0.
    let mut params2: CoreDumpParameters = unsafe { core::mem::zeroed() };
    ClearCoreDumpParametersInternal(&mut params2, core::mem::size_of::<CoreDumpParameters>());
    assert_eq!(SetCoreDumpLimited(&mut params2, 0x10000), 0);
    assert_eq!(
        SetCoreDumpCallback(&mut params2, Some(abort_callback), core::ptr::null_mut()),
        0
    );
    let rc = WriteCoreDumpWith(&params2, path.as_ptr());
    assert_ne!(rc, 0, "aborted dump should report failure");
    assert!(!core.exists(), "aborted dump should write no file");
}
