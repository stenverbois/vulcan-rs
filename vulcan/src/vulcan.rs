use leia::*;

pub const SANCUS_KEY_SIZE: usize = 16;
pub const CAN_PAYLOAD_SIZE: usize = 8;

pub const CAN_EFF_MASK: u32 = 0x1FFFFFFF;
pub const CAN_EFF_FLAG: u32 = 0x80000000;

pub type SancusKey = [u8; SANCUS_KEY_SIZE];
pub type CANPayload = [u8; CAN_PAYLOAD_SIZE];

pub enum Event {
    Received(u16, Option<[u8; 8]>),
    Authenticated(u16),
    MissingMAC(u16),
    UnexpectedMAC(u16),
    IncorrectMAC(u16),
    Desync(u16),
    Resynced(u16),
    UnknownId(u16),
    Debug(u64),
}

/// Trait representing a VulCAN context on a single node.
pub trait VulCANContext {
    type ProtocolInfo;

    // fn send_fn() -> fn(u32, &[u8]);
    fn init(&mut self);
    fn auth_send(&mut self, id: u16, msg: &[u8]);
    fn auth_recv(&mut self, eid: u32, msg: &[u8]) -> Result<Event, ()>;

    fn send(&mut self, id: u16, msg: &[u8]);

    // TODO change to these
    // fn auth_send(&mut self, connection: &mut Self::ProtocolInfo, msg: &[u8]);
    //fn send(&mut self, connection: &mut Self::ProtocolInfo, msg: &[u8]);
}

pub fn leia<S>(
    connections: &[LeiAConnection],
    aec: LeiAConnection,
    store: S,
    send: fn(u32, &[u8]),
) -> LeiAContext<S>
where
    S: LeiAStore,
{
    LeiAContext::new(connections, aec, store).with_send(send)
}

pub trait VulCANStore {
    type K;
    type V;

    fn get(&self, k: &Self::K) -> Option<&Self::V>;
    fn insert(&mut self, k: &Self::K, Self::V) -> Option<Self::V>;
    fn remove(&mut self, k: &Self::K) -> Option<Self::V>;
    fn contains_key(&self, k: &Self::K) -> bool;
    fn len(&self) -> usize;
}
