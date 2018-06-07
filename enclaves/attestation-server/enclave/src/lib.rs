#![no_std]
#![feature(conservative_impl_trait)]

#[macro_use]
extern crate lazy_static;
extern crate byteorder;
extern crate vulcan;

#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_rand;
#[macro_use]
extern crate sgx_rand_derive;

use std::slice;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::SgxMutex;
use std::vec::Vec;

use byteorder::{ByteOrder, LittleEndian, BigEndian};

use vulcan::*;
use vulcan::spongent::*;

const CAN_ID_PING: u16 = 0xf0;
const CAN_ID_PONG: u16 = 0xf8;
const CAN_ID_AEC_SEND: u16 = 0xaa;
const CAN_ID_AEC_RECV: u16 = 0xbb;

const CAN_ID_ATTEST_SEND: u16 = 0x555;
const CAN_ID_ATTEST_RECV: u16 = 0x556;

extern {
    fn can_send(id: u32, dlen: usize, data: *const u8);
}

fn vulcan_send(id: u32, data: &[u8]) {
    unsafe {
        can_send(id, data.len(), data.as_ptr());
    }
}

lazy_static! {
    // Maps PM identifiers to module-specific key K_PM
    static ref PM_KEYS: SgxMutex<HashMap<u16, SancusKey>> = {
        SgxMutex::new(HashMap::new())
    };

    // Maps connection identifiers to connection key
    static ref CONNECTION_KEYS: SgxMutex<HashMap<u16, SancusKey>> = {
        SgxMutex::new(HashMap::new())
    };

    // Maps connection identifiers to set of participating PM identifiers 
    static ref PARTICIPATION: SgxMutex<Vec<(u16, HashSet<u16>)>> =
        SgxMutex::new(Vec::new());

    // Maps PM identifiers
    static ref NONCE_MACS: SgxMutex<HashMap<u16, Vec<(u16, [u8; CAN_PAYLOAD_SIZE])>>> =
        SgxMutex::new(HashMap::new());

    static ref EXPECT_MAC: SgxMutex<Option<(u16, u16)>> =
        SgxMutex::new(None);
}

#[derive(Copy, Clone, Debug, Default, Rand)]
struct Key([u8; SANCUS_KEY_SIZE]);

/// Returns a tuple containing the key distribution sequence and the expected nonce mac.
fn build_key_distribution_sequence(key_pm: &SancusKey, key_conn: &SancusKey, id_conn: u16) -> (impl Iterator<Item=CANPayload>, CANPayload) {
    let mut sequence: [CANPayload; 6] = [[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]; 6];

    let nonce = sgx_rand::random::<u64>();
    println!("Generated nonce {:x}", nonce);

    let mut nonce_buf = [0; 8];
    BigEndian::write_u64(&mut nonce_buf, nonce);

    let mut id_buf = [0; 2];
    LittleEndian::write_u16(&mut id_buf, id_conn);

    for &byte in key_conn.iter() {
        print!("{:02x}", byte);
    }
    println!("");

    let mut payload = [0x00; 8 * 4];
    payload[..2].clone_from_slice(&id_buf);
    payload[8..16].clone_from_slice(&nonce_buf);
    payload[16..].clone_from_slice(key_conn);

    let mut payload_encrypted = [0x00; 8 * 4];
    let mac = spongent_wrap(key_pm, &[0x01, 0x02, 0x03, 0x04], &payload, &mut payload_encrypted, false).unwrap();

    // TODO impl Default?
    let mut expected_nonce_mac: CANPayload = [0x00; CAN_PAYLOAD_SIZE];
    expected_nonce_mac.clone_from_slice(&spongent_mac(key_pm, &nonce_buf).unwrap()[8..]);

    sequence[0].copy_from_slice(&payload_encrypted[0..8]);
    sequence[1].copy_from_slice(&payload_encrypted[8..16]);
    sequence[2].copy_from_slice(&payload_encrypted[16..24]);
    sequence[3].copy_from_slice(&payload_encrypted[24..]);
    
    sequence[4].copy_from_slice(&mac[..8]);
    sequence[5].copy_from_slice(&mac[8..]);

    (sequence.to_vec().into_iter(), expected_nonce_mac)
}

fn handle_key_request(id: u16) {
    println!("Got key request for: {:X}", id);

    let nonce = sgx_rand::random::<u64>();

    println!("Nonce generated: {:X}", nonce);

    let mut nonce_buf = [0; 8];
    LittleEndian::write_u64(&mut nonce_buf, nonce);

    /* TODO Update for new key mgmt
    let mut nonce_buf_encrypted = [0; 8];
    let mac = spongent_wrap(&SM_KEY_PING, &[0x11, 0x22], &nonce_buf, &mut nonce_buf_encrypted, false).unwrap();

    let mut context = VULCAN.lock().unwrap();
    context.send(CAN_ID_ATTEST_SEND, &nonce_buf_encrypted);
    */
}

#[no_mangle]
pub extern "C" fn initialize() -> u32 {
    // Store node specific keys K_PM
    // TODO Should be retrieved from confidentiallity and integrity protected
    // storage
    let mut pm_keys = PM_KEYS.lock().unwrap();
    pm_keys.insert(0x01, [0xab, 0x30, 0x62, 0x72, 0x34, 0xd6, 0x77, 0x01, 0x3b, 0x0f, 0xbb, 0xe6, 0xc9, 0x0a, 0xcb, 0x2a]);
    pm_keys.insert(0x02, [0xa5, 0xf3, 0x9b, 0x2a, 0x13, 0xd7, 0x58, 0x29, 0x44, 0x62, 0x8e, 0x1d, 0xe5, 0x1f, 0x53, 0x08]);

    // Randomly generate connection keys for all connections
    let mut connection_keys = CONNECTION_KEYS.lock().unwrap();
    connection_keys.insert(CAN_ID_PING, sgx_rand::random::<SancusKey>());
    connection_keys.insert(CAN_ID_PONG, sgx_rand::random::<SancusKey>());
    connection_keys.insert(CAN_ID_AEC_SEND, sgx_rand::random::<SancusKey>());
    connection_keys.insert(CAN_ID_AEC_RECV, sgx_rand::random::<SancusKey>());

    let mut participation = PARTICIPATION.lock().unwrap();
    let connection_set = {
        let mut set = HashSet::new();
        set.insert(CAN_ID_PING);
        set.insert(CAN_ID_PONG);
        set.insert(CAN_ID_AEC_SEND);
        set.insert(CAN_ID_AEC_RECV);
        set
    };

    // Push id for ecu-send first because it waits for sync message from ecu-recv.
    participation.push((0x01, connection_set.clone()));
    participation.push((0x02, connection_set.clone())); 

    // let mut context = VULCAN.lock().unwrap();
    let mut nonce_macs = NONCE_MACS.lock().unwrap();

    for &(id_pm, ref connections) in participation.iter() {
        let key_pm = pm_keys.get(&id_pm).expect("Missing K_PM for connection participant");
        nonce_macs.insert(id_pm, Vec::new());
        for id_conn in connections {
            let key_conn = connection_keys.get(&id_conn).expect("Missing connection key");

            let (sequence, expected_nonce_mac) = build_key_distribution_sequence(&key_pm, &key_conn, *id_conn);
            nonce_macs.get_mut(&id_pm).unwrap().push((*id_conn, expected_nonce_mac));
            for msg in sequence {
                vulcan_send(CAN_ID_ATTEST_SEND as u32, &msg);
            }
        }
    }

    0
}

#[no_mangle]
pub extern "C" fn recv_message(eid: u32, dlen: u32, data: *const u8) -> u16 {
    // Construct slice from raw pointer
    let data = unsafe {
        slice::from_raw_parts(data, dlen as usize)
    };

    if eid as u16 == CAN_ID_ATTEST_RECV {
        print!("AS received: ");
        for &byte in data.iter() {
            print!("{:02x}", byte);
        }
        println!("");

        let mut expect_mac = EXPECT_MAC.lock().unwrap();
        let mut nonce_macs = NONCE_MACS.lock().unwrap();

        match *expect_mac {
            None => {
                let pm_id = LittleEndian::read_u16(&data[0..2]);
                let connection_id = LittleEndian::read_u16(&data[2..4]);
                println!("Expecting nonce mac for conn {:x} for pm {:x}", connection_id, pm_id);
                *expect_mac = Some((pm_id, connection_id));
            }
            Some((pm_id, conn_id)) => {
                let pos = match nonce_macs.get_mut(&pm_id).expect("No nonce macs stored for id").iter().position(|&(cid, _)| cid == conn_id) {
                    Some(x) => {
                        println!("Attested connection {:x} for pm {:x}", conn_id,  pm_id);
                        x
                    },
                    None => {
                        println!("Can't find connection id");
                        return 0;
                    }
                };

                nonce_macs.get_mut(&pm_id).unwrap().remove(pos);
                *expect_mac = None;
            }
        }
    }

    0
}
