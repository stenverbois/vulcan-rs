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

use std::collections::HashMap;
use std::collections::HashSet;
use std::io::{stdout, Write};
use std::slice;
use std::sync::SgxMutex;
use std::vec::Vec;

use byteorder::{ByteOrder, LittleEndian};

use vulcan::spongent::*;
use vulcan::*;

const CAN_ID_ATTEST_SEND: u16 = 0x555;
const CAN_ID_ATTEST_RECV: u16 = 0x556;

extern "C" {
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
    static ref RESPONSE_MACS: SgxMutex<HashMap<u16, Vec<(u16, [u8; CAN_PAYLOAD_SIZE])>>> =
        SgxMutex::new(HashMap::new());

    static ref EXPECT_MAC: SgxMutex<Option<(u16, u16)>> =
        SgxMutex::new(None);
}

#[derive(Copy, Clone, Debug, Default, Rand)]
struct Key([u8; SANCUS_KEY_SIZE]);

/// Returns a tuple containing the key distribution sequence and the expected nonce mac.
fn build_key_distribution_sequence(
    id_pm: u16,
    key_pm: &SancusKey,
    id_conn: u16,
    key_conn: &SancusKey,
) -> (impl Iterator<Item = CANPayload>, CANPayload) {
    let mut sequence: [CANPayload; 5] = [[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]; 5];

    println!(
        "Building key distribution sequence for PM ID {:#02X} and connection ID {:#X}",
        id_pm, id_conn
    );
    print!("Connection key: ");
    for &byte in key_conn.iter() {
        print!("{:02x}", byte);
    }
    println!("");

    let mut id_pm_buf = [0; 2];
    LittleEndian::write_u16(&mut id_pm_buf, id_pm);

    let mut id_conn_buf = [0; 2];
    LittleEndian::write_u16(&mut id_conn_buf, id_conn);

    // Size of payload to encrypt is first three messages except for the PM identifier
    let mut payload_to_encrypt = [0x00; 8 * 3 - 2];
    payload_to_encrypt[..2].clone_from_slice(&id_conn_buf);
    payload_to_encrypt[6..].clone_from_slice(key_conn);

    let mut payload = [0x00; 8 * 3];
    payload[..2].clone_from_slice(&id_pm_buf);
    let mac = spongent_wrap(
        key_pm,
        &[0x00, 0x00, 0x00, 0x00],
        &payload_to_encrypt,
        &mut payload[2..],
        false,
    ).unwrap();

    // TODO impl Default?
    let mut expected_nonce_mac: CANPayload = [0x00; CAN_PAYLOAD_SIZE];
    expected_nonce_mac
        .clone_from_slice(&spongent_mac(key_conn, &[0xA7, 0x7E, 0x57, 0xED]).unwrap()[8..]);

    sequence[0].copy_from_slice(&payload[0..8]);
    sequence[1].copy_from_slice(&payload[8..16]);
    sequence[2].copy_from_slice(&payload[16..24]);

    sequence[3].copy_from_slice(&mac[..8]);
    sequence[4].copy_from_slice(&mac[8..]);

    (sequence.to_vec().into_iter(), expected_nonce_mac)
}

#[no_mangle]
pub extern "C" fn initialize() -> u32 {
    // -- Start topology data
    // TODO Should be retrieved from confidentiallity and integrity protected
    // storage
    let mut pm_keys = PM_KEYS.lock().unwrap();
    pm_keys.insert(
        0x01,
        [
            0xd3, 0xcc, 0x86, 0x67, 0x57, 0x82, 0xc3, 0xde, 0x8d, 0xc2, 0x8a, 0x21, 0x29, 0x9f,
            0x43, 0xac,
        ],
    );
    pm_keys.insert(
        0x02,
        [
            0xd8, 0x3a, 0x77, 0x70, 0xe8, 0xc4, 0xa3, 0x42, 0x1e, 0xc7, 0x91, 0x89, 0xbc, 0x34,
            0xd2, 0xbb,
        ],
    );

    const CAN_ID_PING: u16 = 0xf0;
    const CAN_ID_PONG: u16 = 0xf8;
    const CAN_ID_AEC_SEND: u16 = 0xaa;
    const CAN_ID_AEC_RECV: u16 = 0xbb;

    // -- End topology data

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

    let mut response_macs = RESPONSE_MACS.lock().unwrap();

    for &(id_pm, ref connections) in participation.iter() {
        let key_pm = pm_keys
            .get(&id_pm)
            .expect("Missing K_PM for connection participant");
        response_macs.insert(id_pm, Vec::new());
        for id_conn in connections {
            let key_conn = connection_keys
                .get(&id_conn)
                .expect("Missing connection key");

            let (sequence, expected_nonce_mac) =
                build_key_distribution_sequence(id_pm, &key_pm, *id_conn, &key_conn);
            response_macs
                .get_mut(&id_pm)
                .unwrap()
                .push((*id_conn, expected_nonce_mac));
            for (idx, msg) in sequence.enumerate() {
                print!("\rSending message {}/5 of sequence...", idx + 1);
                let _ = stdout().flush();
                vulcan_send(CAN_ID_ATTEST_SEND as u32, &msg);
            }
            println!("");
        }
    }

    0
}

#[no_mangle]
pub extern "C" fn recv_message(eid: u32, dlen: u32, data: *const u8) -> u16 {
    // Construct slice from raw pointer
    let data = unsafe { slice::from_raw_parts(data, dlen as usize) };

    if eid as u16 == CAN_ID_ATTEST_RECV {
        let mut expect_mac = EXPECT_MAC.lock().unwrap();
        let mut response_macs = RESPONSE_MACS.lock().unwrap();

        match *expect_mac {
            None => {
                let pm_id = LittleEndian::read_u16(&data[0..2]);
                let connection_id = LittleEndian::read_u16(&data[2..4]);
                // println!("Expecting response mac for conn {:#X} for pm {:#X}", connection_id, pm_id);
                *expect_mac = Some((pm_id, connection_id));
            }
            Some((pm_id, conn_id)) => {
                let pos = match response_macs
                    .get_mut(&pm_id)
                    .expect("No nonce macs stored for id")
                    .iter()
                    .position(|&(cid, _)| cid == conn_id)
                {
                    Some(x) => x,
                    None => {
                        println!("Can't find connection id");
                        return 0;
                    }
                };

                // FIXME Disabled because of unreliable reponses from Sancus PMs.
                // FIXME PM should only be attested of MAC matches expected MAC.
                // if response_macs.get_mut(&pm_id).unwrap().get(pos).unwrap().1 == data {
                //     println!("MACs match");
                // }
                // else {
                //     println!("MACs don't match");
                // }

                println!("Attested connection {:#X} for PM {:#02X}", conn_id, pm_id);

                response_macs.get_mut(&pm_id).unwrap().remove(pos);
                *expect_mac = None;
            }
        }
    }

    0
}
