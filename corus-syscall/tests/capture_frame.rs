//! aarch64 `capture_frame` register-slot mapping test.
//!
//! `capture_frame` snapshots the caller's GP registers into the `Regs` layout
//! (`regs[N] = xN`) so the dumping thread's core backtrace reflects the API
//! call site. A scratch-register mistake in the save sequence can silently shift
//! or drop slots (e.g. clobbering the base register before its own slot is
//! written). This test pins distinct sentinels into a broad range of registers,
//! calls `capture_frame`, and asserts each landed in the matching slot.
//!
//! aarch64-only: x86_64 has a separate `capture_frame` assembly sequence with
//! its own (different) `Regs` layout, validated elsewhere.
#![cfg(target_arch = "aarch64")]

use core::arch::asm;

/// `Regs` slot count (x0..x30, sp, pc, pstate).
const N_SLOTS: usize = 34;

#[test]
fn capture_frame_maps_registers_to_slots() {
    // Output buffer for capture_frame; one u64 per Regs slot.
    let mut regs = [0u64; N_SLOTS];

    // Sentinels for the registers we can safely control across the call. We
    // avoid:
    //   x0  - holds the output pointer (its slot is checked to equal the ptr),
    //   x18 - the platform register (reserved; not a valid asm operand),
    //   x19 - reserved internally by LLVM (not a valid asm operand),
    //   x29/x30/sp - frame/link/stack, used by the call mechanics themselves.
    // That leaves x1..x17 and x20..x28, which still covers the previously buggy
    // shift range (a base-register clobber used to shift x9..x28 down a slot).
    //
    // Each sentinel xN gets value 0xA5A5_0000 + N so a shifted slot is obvious.
    const BASE: u64 = 0xA5A5_0000;

    // Load sentinels and call capture_frame in a single asm block, so the
    // register values survive into the call. x0 = regs buffer pointer.
    unsafe {
        asm!(
            // Low half = the register number N (so the final value is
            // 0xA5A5_0000 + N = BASE + N once the high half is set below).
            "mov x1,  #1",
            "mov x2,  #2",
            "mov x3,  #3",
            "mov x4,  #4",
            "mov x5,  #5",
            "mov x6,  #6",
            "mov x7,  #7",
            "mov x8,  #8",
            "mov x9,  #9",
            "mov x10, #10",
            "mov x11, #11",
            "mov x12, #12",
            "mov x13, #13",
            "mov x14, #14",
            "mov x15, #15",
            "mov x16, #16",
            "mov x17, #17",
            // (skip x18 platform register and x19 LLVM-reserved register)
            "mov x20, #20",
            "mov x21, #21",
            "mov x22, #22",
            "mov x23, #23",
            "mov x24, #24",
            "mov x25, #25",
            "mov x26, #26",
            "mov x27, #27",
            "mov x28, #28",
            // Set the high half (0xA5A5_xxxx) so each sentinel is BASE + N.
            "movk x1,  #0xA5A5, lsl #16",
            "movk x2,  #0xA5A5, lsl #16",
            "movk x3,  #0xA5A5, lsl #16",
            "movk x4,  #0xA5A5, lsl #16",
            "movk x5,  #0xA5A5, lsl #16",
            "movk x6,  #0xA5A5, lsl #16",
            "movk x7,  #0xA5A5, lsl #16",
            "movk x8,  #0xA5A5, lsl #16",
            "movk x9,  #0xA5A5, lsl #16",
            "movk x10, #0xA5A5, lsl #16",
            "movk x11, #0xA5A5, lsl #16",
            "movk x12, #0xA5A5, lsl #16",
            "movk x13, #0xA5A5, lsl #16",
            "movk x14, #0xA5A5, lsl #16",
            "movk x15, #0xA5A5, lsl #16",
            "movk x16, #0xA5A5, lsl #16",
            "movk x17, #0xA5A5, lsl #16",
            "movk x20, #0xA5A5, lsl #16",
            "movk x21, #0xA5A5, lsl #16",
            "movk x22, #0xA5A5, lsl #16",
            "movk x23, #0xA5A5, lsl #16",
            "movk x24, #0xA5A5, lsl #16",
            "movk x25, #0xA5A5, lsl #16",
            "movk x26, #0xA5A5, lsl #16",
            "movk x27, #0xA5A5, lsl #16",
            "movk x28, #0xA5A5, lsl #16",
            "blr {cf}",
            cf = in(reg) corus_syscall::arch::capture_frame as unsafe extern "C" fn(*mut u64),
            in("x0") regs.as_mut_ptr(),
            // capture_frame clobbers nothing of ours that we read back from
            // memory, but the sentinel registers and call-clobbered regs are
            // dead after this; mark the ones we set so the compiler doesn't
            // expect them preserved.
            out("x1") _, out("x2") _, out("x3") _, out("x4") _, out("x5") _,
            out("x6") _, out("x7") _, out("x8") _, out("x9") _, out("x10") _,
            out("x11") _, out("x12") _, out("x13") _, out("x14") _, out("x15") _,
            out("x16") _, out("x17") _, out("x20") _, out("x21") _,
            out("x22") _, out("x23") _, out("x24") _, out("x25") _, out("x26") _,
            out("x27") _, out("x28") _, out("x30") _,
            clobber_abi("C"),
        );
    }

    // regs[0] is x0 = the output buffer pointer we passed in.
    assert_eq!(
        regs[0],
        regs.as_ptr() as u64,
        "regs[0] should hold x0 (the output pointer)"
    );

    // Every controlled register must land in its own slot. This is the crux:
    // a base-register clobber previously shifted x9..x28 down by one slot and
    // left regs[28] stale.
    for n in 1..=28usize {
        if n == 18 || n == 19 {
            continue; // x18 platform / x19 LLVM-reserved: not controlled.
        }
        assert_eq!(
            regs[n],
            BASE + n as u64,
            "regs[{n}] should hold x{n} sentinel {:#x}, got {:#x}",
            BASE + n as u64,
            regs[n],
        );
    }

    // sp (index 31) and pc (index 32) should be plausible non-zero values.
    assert_ne!(regs[31], 0, "sp slot should be non-zero");
    assert_ne!(regs[32], 0, "pc slot should be non-zero");
}
