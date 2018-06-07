use byteorder::{ByteOrder, LittleEndian};
use spongent::spongent_mac;

use vulcan::*;

use core::convert::From;

const LEIA_AD_SIZE: usize = 12;
const LEIA_COUNT_MAX: u16 = 0xFFFF;
const LEIA_EPOCH_MAX: u64 = 0xFFFFFFFFFFFFFF;
const LEIA_CMD_MASK: u32 = 0x03;

/// Structure representing a LeiA connection.
#[derive(Copy, Clone, Debug, Default)]
pub struct LeiAConnection {
    id: u16,
    c: u16,
    epoch: u64,
    k_i: SancusKey,
    k_e: SancusKey,

    auth_fail_in_progress: bool,
}

impl LeiAConnection {
    /// Creates a new LeiA connection.
    pub fn new(id: u16) -> Self {
        Self {
            id: id,
            c: 0,
            epoch: 0,
            k_i: Default::default(),
            k_e: Default::default(),

            auth_fail_in_progress: false,
        }
    }

    /// Sets k_i of this connection.
    pub fn with_k_i(mut self, key: &[u8]) -> Self {
        self.k_i.copy_from_slice(key);
        self
    }

    /// Gets the connection id.
    pub fn id(&self) -> u16 {
        self.id
    }

    /// Gets the connection counter.
    pub fn counter(&self) -> u16 {
        self.c
    }
}

/// Structure managing multiple LeiA connections on a single node.
pub struct LeiAContext<S>
where
    S: VulCANStore<K = u16, V = [u8; CAN_PAYLOAD_SIZE]>,
{
    connections: [LeiAConnection; 16],
    aec: LeiAConnection,
    expected: S,
    send: fn(u32, &[u8]),
}

// Ergonomics. Use LeiAStore as alias for specific VulCANStore.
// @Fixme: Use trait aliasing https://github.com/rust-lang/rust/issues/41517
pub trait LeiAStore: VulCANStore<K = u16, V = [u8; CAN_PAYLOAD_SIZE]> {}
impl<T> LeiAStore for T
where
    T: VulCANStore<K = u16, V = [u8; CAN_PAYLOAD_SIZE]>,
{
}

impl<'a, S> LeiAContext<S>
where
    S: LeiAStore,
{
    /// Creates a new LeiA context.
    ///
    /// # Parameters
    ///
    /// - `connections` - A list of [LeiAConnection](struct.LeiAConnection.html)
    ///   to be managed by the context.
    /// - `aec` - The [LeiAConnection](struct.LeiAConnection.html) used as
    ///    Authentication error channel.
    /// - `expected` - A structure implementing [VulCANStore](trait.VulCANStore.html).
    pub fn new(connections: &[LeiAConnection], aec: LeiAConnection, expected: S) -> Self {
        let mut cs = [LeiAConnection::new(0); 16];
        cs[..connections.len()].copy_from_slice(connections);
        Self {
            // @Cleanup @Hardcode: 16 will do for now. Could use const generics when
            // they are stable.
            connections: cs,
            aec: aec,
            expected: expected,
            send: |_, _| {},
        }
    }

    /// Sets the function to be used by the context to send messages.
    pub fn with_send(mut self, send: fn(u32, &[u8])) -> Self {
        self.send = send;
        self
    }

    // @TODO Needs pub?
    pub fn leia_auth_send(&mut self, id: u16, msg: &[u8], is_aec: bool) {
        let (cmd, cmd_mac) = if !is_aec {
            (LeiACmd::Data, LeiACmd::Mac)
        } else {
            (LeiACmd::AecEpoch, LeiACmd::AecMac)
        };
        
        let send = self.send;
        
        let connection = self.find_connection(id).unwrap();

        let eid = build_eid(connection.id, cmd, connection.c);
        (send)(eid, msg);

        let id_mac = if is_aec { connection.id } else { connection.id + 1 };

        let eid_mac = build_eid(id_mac, cmd_mac, connection.c);
        let msg_mac = mac_create(&connection.k_e, connection.id, msg, connection.c);
        (send)(eid_mac, &msg_mac);

        update_counters(connection);
    }

    pub fn leia_auth_fail_send(&mut self, id: u16) {
        let aec_id = self.aec.id;
        let aec_epoch = self.aec.epoch;

        // Zero counter to indicate connection awaits AUTH_FAIL response
        // @TODO not anymore -> auth_fail_in_progress
        {
            let connection = self.find_connection(id).unwrap();
            connection.c = 0;
            connection.auth_fail_in_progress = true;
        }

        // NOTE: We currently do not implement AEC resynchronisation
        // (in case authentication fails for the AUTH_FAIL message itself).
        // This could be resolved locally, as the AUTH fail signal includes the epoch.

        // Send 11 bit message id concatenated with lower 53 bits of epoch counter
        let mut msg: [u8; 8] = [0; 8];
        LittleEndian::write_u64(&mut msg, aec_epoch);
        LittleEndian::write_u16(&mut msg[6..], id);

        // let msg: [u8; 8] = [0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA];

        self.leia_auth_send(aec_id, &msg, true);
    }

    pub fn leia_auth_fail_receive(&mut self, id: u16, epoch: u64) {
        let connection = self.find_connection(id).unwrap();

        // @NOTE: New epoch should be strictly higher to prevent replay attacks
        if epoch > connection.epoch {
            connection.epoch = epoch - 1;
            session_key_gen(connection);
        }
    }

    pub fn leia_auth_fail_send_response(&mut self, id: u16) {
        let epoch = {
            let connection = self.find_connection(id).unwrap();
            session_key_gen(connection);

            connection.epoch
        };

        let mut msg: [u8; 8] = [0; 8];
        LittleEndian::write_u64(&mut msg, epoch);

        self.leia_auth_send(id, &msg, true);
    }

    // Finds the connection with the specified id
    fn find_connection(&mut self, id: u16) -> Option<&mut LeiAConnection> {
        // @Cleanup: When Rust-sgx-sdk compiles with a newer version of rustc
        // than 1.22 nightly, we could so something like this with option filter:
        // self.connections.iter_mut()
        //     .find(|ref x| x.id == id)
        //     .or(Some(&mut self.aec).filter(|ref c| c.id == id))
        
        let aec_id = self.aec.id;


        let connection_opt = self.connections.iter_mut()
            .find(|ref x| x.id == id);

        let aec_opt = if self.aec.id == id { Some(&mut self.aec) } else { None };

        connection_opt.or(aec_opt)
    }

    // Calculate mac for message and put it in the map of expected messages
    fn add_expected_msg(&mut self, id: u16, counter: u16, data: &[u8]) -> [u8; 8] {
        let mac = {
            let mut connection = self.find_connection(id).unwrap();
            
            // Set our counter to be the same as the incomming message.
            // This allows us to deal with desyncs < 1 epoch.
            connection.c = counter;
            
            mac_create(&connection.k_e, id, data, counter)
        };

        self.expected.insert(&id, mac);

        mac
    }
}

fn update_counters(connection: &mut LeiAConnection) {
    if connection.c == LEIA_COUNT_MAX {
        assert!(connection.epoch != LEIA_EPOCH_MAX);
        session_key_gen(connection);
    } else {
        connection.c += 1;
    }
}

pub fn session_key_gen(cur: &mut LeiAConnection) {
    // 1. Increment epoch
    cur.epoch += 1;

    // 2. Apply MAC algorithm on the epoch
    let mut epoch_buf = [0; 8];
    LittleEndian::write_u64(&mut epoch_buf, cur.epoch);
    let mac = spongent_mac(&cur.k_i, &epoch_buf).unwrap();
    cur.k_e.copy_from_slice(&mac);

    // 3. Reset counter
    cur.c = 1;
}

// TODO id and counter are from cur?
pub fn mac_create(
    k_e: &SancusKey,
    id: u16,
    msg: &[u8],
    counter: u16,
) -> [u8; CAN_PAYLOAD_SIZE] {
    let mut ad = [0; LEIA_AD_SIZE];
    let mut buf = [0; 2];

    // Write counter to AD buffer
    LittleEndian::write_u16(&mut buf, counter);
    ad[0..2].copy_from_slice(&buf);

    // Write id to AD buffer
    LittleEndian::write_u16(&mut buf, id);
    ad[2..4].copy_from_slice(&buf);

    let msg_len = msg.len();
    ad[4..4 + msg_len].copy_from_slice(&msg);

    let mac = spongent_mac(k_e, &ad).unwrap();
    let mut truncated_mac = [0; CAN_PAYLOAD_SIZE];
    truncated_mac.clone_from_slice(&mac[CAN_PAYLOAD_SIZE..]);

    truncated_mac
}

/// Implements LeiA as a VulCAN context.
impl<'a, S> VulCANContext for LeiAContext<S>
where
    S: VulCANStore<K = u16, V = [u8; CAN_PAYLOAD_SIZE]>,
{
    type ProtocolInfo = LeiAConnection;

    fn init(&mut self) {
        for conn in self.connections.iter_mut().filter(|ref c| c.id != 0) {
            session_key_gen(conn);
        }
        session_key_gen(&mut self.aec);
    }

    fn auth_send(&mut self, id: u16, msg: &[u8]) {
        self.leia_auth_send(id, msg, false)
    }

    fn send(&mut self, id: u16, msg: &[u8]) {
        (self.send)(id as u32, msg);
    }

    fn auth_recv(&mut self, eid: u32, msg: &[u8]) -> Result<Event, ()> {
        // @TODO @Cleanup: Unwrap handling
        let (id, cmd, counter) = parse_eid(eid).ok_or(())?;

        // @TODO: Also aec variants here?
        if (self.find_connection(id).is_none() && cmd == LeiACmd::Data) || (self.find_connection(id - 1).is_none() && cmd == LeiACmd::Mac) {
            return Ok(Event::UnknownId(id));
        }
            
        let mut ret = Event::Received(id, None);
        
        // @TODO Cleanup with one in LeiACmd::Mac
        let msg_id = if id == self.aec.id { id } else { id - 1 };

        match cmd {
            LeiACmd::Data => {
                let connection_counter = self.find_connection(id).unwrap().c;
                if counter < connection_counter {
                    self.leia_auth_fail_send(id);
                    return Ok(Event::Desync(id));
                }
                
                if self.expected.contains_key(&id) {
                    let mac = self.add_expected_msg(id, counter, &msg);
                    ret = Event::MissingMAC(id);
                }
                else {
                    let mac = self.add_expected_msg(id, counter, &msg);
                    ret = Event::Received(id, Some(mac));
                }
            }
            LeiACmd::Mac => {
                // @Temp @Hack: Accounting for bug in demo application log file.
                // @Temp @Hack: msg_id should always be id - 1.
                let msg_id = if self.expected.contains_key(&(id - 1)) { id - 1 } else { id };
                if self.expected.contains_key(&msg_id) {
                    if self.expected.get(&msg_id).unwrap() == msg {
                        ret = Event::Authenticated(msg_id);

                        // @TODO: Do this in update_counters?
                        let connection = self.find_connection(msg_id).unwrap();
                        // update_counters(connection);
                    } else {
                        ret = Event::IncorrectMAC(msg_id);

                        self.leia_auth_fail_send(msg_id);
                    }
                }
                else {
                    ret = Event::UnexpectedMAC(msg_id);
                }

                self.expected.remove(&msg_id);
            }
            LeiACmd::AecEpoch => {
                // @TODO Only after MAC?
                self.leia_auth_fail_receive(id, LittleEndian::read_u64(msg));
                ret = Event::Resynced(id);
                self.add_expected_msg(id, counter, &msg);
            }
            LeiACmd::AecMac => {
                if self.expected.contains_key(&msg_id) {
                    if self.expected.get(&msg_id).unwrap() == msg {
                        ret = Event::Authenticated(msg_id);

                        // @TODO @Cleanup
                        let auth_fail_in_progress = {
                            let connection = self.find_connection(msg_id).unwrap();
                            update_counters(connection);

                            connection.auth_fail_in_progress
                        };

                        if (!auth_fail_in_progress) {
                            self.leia_auth_fail_send_response(LittleEndian::read_u16(&msg[6..]));
                        }

                        let debug = {
                            let connection = self.find_connection(msg_id).expect("No connection with specified id.");
                            connection.auth_fail_in_progress = false;

                            connection.epoch
                        };

                        ret = Event::Debug(debug);
                    }
                }
                else {
                    ret = Event::UnexpectedMAC(msg_id);
                }

                self.expected.remove(&msg_id);
            }
        }

        Ok(ret)
    }
}

fn leia_auth_fail_response(cur: &mut LeiAConnection, epoch: u64) {
    if epoch <= cur.epoch {
        panic!("Received AUTH_FAIL epoch can't be smaller than current one.");
    }

    cur.epoch = epoch - 1;
    session_key_gen(cur);
}

fn parse_eid(eid: u32) -> Option<(u16, LeiACmd, u16)> {
    let eid = eid & CAN_EFF_MASK;
    if eid > 0x7FF {
        let id: u16 = (eid >> 18) as u16;
        let cmd: LeiACmd = ((eid >> 16) & LEIA_CMD_MASK).into();
        let counter = (eid & 0xFFFF) as u16;

        Some((id, cmd, counter))
    } else {
        None
    }
}

/// Builds a LeiA extended identifier from the 11 bit id, a LeiA command code
/// and 16 bit counter value.
fn build_eid(id: u16, cmd: LeiACmd, counter: u16) -> u32 {
    let cmdu: u16 = cmd.into();
    (((id as u32) << 18 | (cmdu as u32) << 16) | counter as u32) | CAN_EFF_FLAG
}

/// LeiA command codes.
#[derive(Eq, PartialEq, Debug)]
pub enum LeiACmd {
    Data,
    Mac,
    AecEpoch,
    AecMac,
}

impl<T: Into<u32>> From<T> for LeiACmd {
    fn from(cmd: T) -> Self {
        match cmd.into() {
            0x00 => LeiACmd::Data,
            0x01 => LeiACmd::Mac,
            0x02 => LeiACmd::AecEpoch,
            0x03 => LeiACmd::AecMac,
            _ => panic!("Attempt to convert invalid integer to LeiA command."),
        }
    }
}

impl From<LeiACmd> for u16 {
    fn from(cmd: LeiACmd) -> Self {
        match cmd {
            LeiACmd::Data => 0x00,
            LeiACmd::Mac => 0x01,
            LeiACmd::AecEpoch => 0x02,
            LeiACmd::AecMac => 0x03,
        }
    }
}
