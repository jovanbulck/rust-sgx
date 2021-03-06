/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use core::mem::MaybeUninit;
use super::Enclu;

/// Wrapper struct to force 16-byte alignment.
#[repr(align(16))]
pub struct Align16<T>(pub T);

/// Wrapper struct to force 128-byte alignment.
#[repr(align(128))]
pub struct Align128<T>(pub T);

/// Wrapper struct to force 512-byte alignment.
#[repr(align(512))]
pub struct Align512<T>(pub T);

/// Call the `EGETKEY` instruction to obtain a 128-bit secret key.
pub fn egetkey(request: &Align512<[u8; 512]>) -> Result<Align16<[u8; 16]>, u32> {
    unsafe {
        let mut out = MaybeUninit::uninit();
        let error;

        asm!(
            "enclu"
            : "={eax}"(error)
            : "{eax}"(Enclu::EGetkey),
              "{rbx}"(request),
              "{rcx}"(out.as_mut_ptr())
            : "flags"
        );

        match error {
            0 => Ok(out.assume_init()),
            err => Err(err),
        }
    }
}

/// Call the `EREPORT` instruction.
///
/// This creates a cryptographic report describing the contents of the current
/// enclave. The report may be verified by the enclave described in
/// `targetinfo`.
pub fn ereport(
    targetinfo: &Align512<[u8; 512]>,
    reportdata: &Align128<[u8; 64]>,
) -> Align512<[u8; 432]> {
    unsafe {
        let mut report = MaybeUninit::uninit();

        asm!(
            "enclu"
            : /* no output registers */
            : "{eax}"(Enclu::EReport),
              "{rbx}"(targetinfo),
              "{rcx}"(reportdata),
              "{rdx}"(report.as_mut_ptr())
        );

        report.assume_init()
    }
}
