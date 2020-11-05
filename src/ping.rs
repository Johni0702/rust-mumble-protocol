//! Ping messages and codec
//!
//! A Mumble client can send periodic UDP [PingPacket]s to servers
//! in order to query their current state and measure latency.
//! A server will usually respond with a corresponding [PongPacket] containing
//! the requested details.
//!
//! Both packets are of fixed size and can be converted to/from `u8` arrays/slices via
//! the respective `From`/`TryFrom` impls.

use std::convert::TryFrom;
use std::convert::TryInto;

/// A ping packet sent to the server.
#[derive(Clone, Debug, PartialEq)]
pub struct PingPacket {
    /// Opaque, client-generated id.
    ///
    /// Will be returned by the server unmodified and can be used to correlate
    /// pong replies to ping requests to e.g. calculate latency.
    pub id: u64,
}

/// A pong packet sent to the client in reply to a previously received [PingPacket].
#[derive(Clone, Debug, PartialEq)]
pub struct PongPacket {
    /// Opaque, client-generated id.
    ///
    /// Should match the value in the corresponding [PingPacket].
    pub id: u64,

    /// Server version. E.g. `0x010300` for `1.3.0`.
    pub version: u32,

    /// Current amount of users connected to the server.
    pub users: u32,

    /// Configured limit on the amount of users which can be connected to the server.
    pub max_users: u32,

    /// Maximum bandwidth for server-bound speech per client in bits per second
    pub bandwidth: u32,
}

/// Error during parsing of a [PingPacket].
#[derive(Clone, Debug, PartialEq)]
pub enum ParsePingError {
    /// Ping packets must always be 12 bytes in size.
    InvalidSize,
    /// Ping packets must have an all zero header of 4 bytes.
    InvalidHeader,
}

impl TryFrom<&[u8]> for PingPacket {
    type Error = ParsePingError;
    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        match <[u8; 12]>::try_from(buf) {
            Ok(array) => {
                if array[0..4] != [0, 0, 0, 0] {
                    Err(ParsePingError::InvalidHeader)
                } else {
                    Ok(Self {
                        id: u64::from_be_bytes(array[4..12].try_into().unwrap()),
                    })
                }
            }
            Err(_) => Err(ParsePingError::InvalidSize),
        }
    }
}

impl From<PingPacket> for [u8; 12] {
    fn from(packet: PingPacket) -> Self {
        let id = packet.id.to_be_bytes();
        // Is there no nicer way to do this?
        [
            0, 0, 0, 0, id[0], id[1], id[2], id[3], id[4], id[5], id[6], id[7],
        ]
    }
}

/// Error during parsing of a [PongPacket].
#[derive(Clone, Debug, PartialEq)]
pub enum ParsePongError {
    /// Pong packets must always be 24 bytes in size.
    InvalidSize,
}

impl TryFrom<&[u8]> for PongPacket {
    type Error = ParsePongError;
    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        match <[u8; 24]>::try_from(buf) {
            Ok(array) => Ok(Self {
                version: u32::from_be_bytes(array[0..4].try_into().unwrap()),
                id: u64::from_be_bytes(array[4..12].try_into().unwrap()),
                users: u32::from_be_bytes(array[12..16].try_into().unwrap()),
                max_users: u32::from_be_bytes(array[16..20].try_into().unwrap()),
                bandwidth: u32::from_be_bytes(array[20..24].try_into().unwrap()),
            }),
            Err(_) => Err(ParsePongError::InvalidSize),
        }
    }
}

impl From<PongPacket> for [u8; 24] {
    fn from(packet: PongPacket) -> Self {
        let version = packet.version.to_be_bytes();
        let id = packet.id.to_be_bytes();
        let users = packet.users.to_be_bytes();
        let max_users = packet.max_users.to_be_bytes();
        let bandwidth = packet.bandwidth.to_be_bytes();
        // Is there no nicer way to do this?
        [
            version[0],
            version[1],
            version[2],
            version[3],
            id[0],
            id[1],
            id[2],
            id[3],
            id[4],
            id[5],
            id[6],
            id[7],
            users[0],
            users[1],
            users[2],
            users[3],
            max_users[0],
            max_users[1],
            max_users[2],
            max_users[3],
            bandwidth[0],
            bandwidth[1],
            bandwidth[2],
            bandwidth[3],
        ]
    }
}
