extern crate vulcan;
use vulcan::*;

// #[cfg(feature = "sgx")]
// #[macro_use]
// extern crate sgx_tstd as std;
// extern crate sgx_rand;
// #[macro_use]
// extern crate sgx_rand_derive;

use std::ops::Deref;

// #[derive(Rand)]
pub struct SancusKey {
    inner: [u8; SANCUS_KEY_SIZE],
}

impl Deref for SancusKey {
    type Target = [u8; SANCUS_KEY_SIZE];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub fn init_vulcan() {

    // TODO for every PM
    let PMs = [0x20, 0x22];
    for pm in PMs.iter() {
        let key = sgx_rand::random::<SancusKey>();
        let kk = key.into_vec();
        vulcan::spongent::spongent_wrap()
    }
}
