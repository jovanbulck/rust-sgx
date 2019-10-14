/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std;
use std::cell::RefCell;
use std::os::raw::c_void;

use sgx_isa::Enclu;
use sgxs::loader::Tcs;

pub(crate) type DebugBuffer = [u8; 1024];

#[derive(Debug)]
pub enum CoResult<Y, R> {
    Yield(Y),
    Return(R),
}

#[derive(Debug)]
pub struct Usercall<T: Tcs> {
    tcs: T,
    parameters: (u64, u64, u64, u64, u64),
}

pub type ThreadResult<T> = CoResult<Usercall<T>, (T, u64, u64)>;

impl<T: Tcs> Usercall<T> {
    pub fn parameters(&self) -> (u64, u64, u64, u64, u64) {
        self.parameters
    }

    pub fn coreturn(
        self,
        retval: (u64, u64),
        debug_buf: Option<&RefCell<DebugBuffer>>,
    ) -> ThreadResult<T> {
        coenter(self.tcs, 0, retval.0, retval.1, 0, 0, debug_buf)
    }

    pub fn tcs_address(&self) -> *mut c_void {
        self.tcs.address()
    }
}

pub(crate) fn coenter<T: Tcs>(
    tcs: T,
    mut p1: u64,
    mut p2: u64,
    mut p3: u64,
    mut p4: u64,
    mut p5: u64,
    debug_buf: Option<&RefCell<DebugBuffer>>,
) -> ThreadResult<T> {
    let sgx_result: u32;
    let mut _tmp1: u64;
    let mut _tmp2: u64;

// using a macro for conditional compilation because inline assembly requires
// a string literal, a string constant doesn't work
#[cfg(target_os = "linux")]
macro_rules! enclu_with_aep(() => ("
.weak __vdso_sgx_enter_enclave
.type __vdso_sgx_enter_enclave, function
        mov __vdso_sgx_enter_enclave@GOTPCREL(%rip), %r11    // Check if __vdso_sgx_enter_enclave
        test %r11, %r11                                      // exists. We're using weak linkage,
                                                             // so it might not.

        jnz 2f                                               // Jump & use VDSO if available,
                                                             // otherwise, just call ENCLU directly.

        lea 1f(%rip), %rcx                                   // set SGX AEP
1:      enclu
        jmp 3f

        // Strongly link to another symbol in the VDSO, so that the linker will
        // include a DT_NEEDED entry for `linux-vdso.so.1`. This doesn't happen
        // automatically because rustc passes `--as-needed` to the linker. This
        // is never executed because of the unconditional jump above.
.global __vdso_clock_gettime
        call __vdso_clock_gettime@PLT

2:      pushq $$0                                            // push argument: handler = NULL
        pushq $$0                                            // push argument: e = NULL
        push %rbx                                            // push argument: tcs
        mov %rax, %rcx                                       // VDSO takes leaf in wrong register
        call __vdso_sgx_enter_enclave@PLT
        add $$0x18, %rsp                                     // pop function arguments

        test %rax, %rax                                      // Check if there was an error, and if
        jnz 3f                                               // there wasn't, set RAX (return value)
        mov $$4, %rax                                        // to 4 (EEXIT), just like ENCLU.
3:
")
);

#[cfg(not(target_os = "linux"))]
macro_rules! enclu_with_aep(() => ("
        lea 1f(%rip), %rcx                                   // set SGX AEP
1:      enclu
")
);

    unsafe {
        let mut uninit_debug_buf: std::mem::MaybeUninit<DebugBuffer>;
        let debug_buf = debug_buf.map(|r| r.borrow_mut());
        let debug_buf = match debug_buf {
            Some(mut buf) => buf.as_mut_ptr(),
            None => {
                uninit_debug_buf = std::mem::MaybeUninit::uninit();
                uninit_debug_buf.as_mut_ptr() as *mut _
            }
        };
        llvm_asm!(enclu_with_aep!()
            : "={eax}"(sgx_result), "={rbx}"(_tmp1), "={r10}"(_tmp2),
              "={rdi}"(p1), "={rsi}"(p2), "={rdx}"(p3), "={r8}"(p4), "={r9}"(p5)
            : "{eax}" (2), "{rbx}"(tcs.address()), "{r10}"(debug_buf),
              "{rdi}"(p1), "{rsi}"(p2), "{rdx}"(p3), "{r8}"(p4), "{r9}"(p5)
            : "rcx", "r11", "memory"
            : "volatile"
        )
    };

    if sgx_result != (Enclu::EExit as u32) {
        panic!("Invalid return value in EAX! eax={}", sgx_result);
    }

    if p1 == 0 {
        CoResult::Return((tcs, p2, p3))
    } else {
        CoResult::Yield(Usercall {
            tcs: tcs,
            parameters: (p1, p2, p3, p4, p5),
        })
    }
}
