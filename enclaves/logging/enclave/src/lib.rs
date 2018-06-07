#![no_std]

#[macro_use]
extern crate lazy_static;
extern crate byteorder;
extern crate vulcan;

#[macro_use]
extern crate sgx_tstd as std;

use std::slice;
use std::collections::HashMap;
use std::sync::SgxMutex;

use vulcan::*;

const CAN_ID_PING: u16 = 0xf0;
const CAN_ID_PONG: u16 = 0xf8;
const CAN_ID_AEC: u16 = 0xbb;

const KEY_PING: [u8; SANCUS_KEY_SIZE] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
      0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
const KEY_PONG: [u8; SANCUS_KEY_SIZE] = [0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
const KEY_AEC: SancusKey = [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];


extern {
    fn can_send(id: u32, dlen: usize, data: *const u8);
}

fn vulcan_send(id: u32, data: &[u8]) {
    unsafe {
        can_send(id, data.len(), data.as_ptr());
    }
}

struct ExpectedStore(HashMap<u16, [u8; CAN_PAYLOAD_SIZE]>);

impl ExpectedStore {
    fn new() -> Self {
        ExpectedStore(HashMap::new())
    }
}

impl VulCANStore for ExpectedStore {
    type K = u16;
    type V = [u8; CAN_PAYLOAD_SIZE];

    #[inline]
    fn get(&self, k: &Self::K) -> Option<&Self::V> {
        self.0.get(k)
    }
    #[inline]
    fn insert(&mut self, k: &Self::K, v: Self::V) -> Option<Self::V> {
        self.0.insert(*k, v)
    }
    #[inline]
    fn remove(&mut self, k: &Self::K) -> Option<Self::V> {
        self.0.remove(k)
    }
    #[inline]
    fn contains_key(&self, k: &Self::K) -> bool {
        self.0.contains_key(k)
    }
    #[inline]
    fn len(&self) -> usize {
        self.0.len()
    }
}

lazy_static! {
    static ref VULCAN: SgxMutex<LeiAContext<ExpectedStore>> = {
        let connections = [
            LeiAConnection::new(CAN_ID_PING).with_k_i(&KEY_PING),
            LeiAConnection::new(CAN_ID_PONG).with_k_i(&KEY_PONG),
        ];
        let aec = LeiAConnection::new(CAN_ID_AEC).with_k_i(&KEY_AEC);
        
        let store = ExpectedStore::new();
            
        let mut vulcan = vulcan::leia(&connections, aec, store, vulcan_send);
        vulcan.init();

        SgxMutex::new(vulcan)
    };
}

#[no_mangle]
pub extern "C" fn recv_message(eid: u32, dlen: u32, data: *const u8) -> u16 {

    // Construct slice from raw pointer
    let data = unsafe {
        slice::from_raw_parts(data, dlen as usize)
    };

    let mut context = VULCAN.lock().unwrap();
    
    // Pass the message to the leia context
    if let Ok(resp) = context.auth_recv(eid, &data) {
        match resp {
            Event::Received(x, ref mac) => {
                println!("[MSG]\tReceived '0x{:X}, expecting mac: {:?}'.", x, mac);
            }
            Event::Authenticated(id) => {
                println!("[AUTH]\tMessage from '0x{:X}' has been authenticated.", id);
            }
            Event::MissingMAC(id) => {
                println!("[FAIL]\tPrevious message for id '0x{:X}' was not authenticated.", id)
            }
            Event::UnexpectedMAC(id) => {
                println!("[FAIL]\tReceived unexpected MAC message for id '0x{:X}'.", id)
            }
            Event::IncorrectMAC(id) => {
                println!("[FAIL]\tReceived incorrect MAC message for id '0x{:X}'.", id)
            }
            Event::Desync(id) => {
                println!("[DESYNC]\tWith '0x{:X}'.", id);
            }
            Event::Resynced(id) => {
                println!("[RESYNC]\tWith '0x{:X}'.", id);
            }
            Event::UnknownId(id) => {
                println!("[FAIL]\tUnknown connection id '0x{:X}'.", id);
            }
            _ => {
                println!("Something happened.")
            }
        }
    }

    0
}
