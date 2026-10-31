//! An open `atem-ch1` channel (§R9.7 "Records" and "Limits").
//!
//! `ct = ChaCha20-Poly1305(k_dir, nonce = 4 zero bytes ‖ u64 counter,
//! aad = enc(["atem-ch1-rec", dir]), plain)`, counters from 0 per direction.
//! The transport is ordered, so the receiver opens each record under exactly
//! its next counter: a gap, a replay, a reordering, a failed tag or a record
//! of the other direction fails, and the channel closes without a reply and
//! wipes its keys. The side that would pass a limit (2^32 records or 2^36
//! plaintext bytes per direction, the lifetime) sends nothing more and
//! closes.
use zeroize::Zeroizing;

use super::transcript::{aead_open, aead_seal};
use super::wire::{Frame, parse_frame};
use super::{ChannelError, Limit, MAX_DIRECTION_BYTES, MAX_PLAINTEXT, MAX_RECORDS};
use crate::domain;
use crate::encoding::enc;

/// Which end of the channel this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Host,
}

/// A record's direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    C2h,
    H2c,
}

impl Direction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Direction::C2h => "c2h",
            Direction::H2c => "h2c",
        }
    }
}

/// `enc(["atem-ch1-rec", dir])`.
pub fn record_aad(dir: Direction) -> Vec<u8> {
    enc(&[domain::CH1_RECORD_AAD.as_bytes(), dir.as_str().as_bytes()])
}

/// 4 zero bytes ‖ u64 counter (big-endian).
pub fn record_nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

struct Half {
    key: Zeroizing<[u8; 32]>,
    counter: u64,
    bytes: u64,
}

/// An open channel. Dropping it (or any failure) wipes its keys.
pub struct Channel {
    role: Role,
    send: Half,
    recv: Half,
    channel_id: String,
    /// The monotonic time (ms) the channel ends.
    deadline_ms: u64,
    /// Client: the host's first record opened (it derived `th4`). Until
    /// then a clear `error` frame (a failed `finish` tag) is still possible.
    confirmed: bool,
    closed: bool,
}

impl Channel {
    pub(crate) fn new(
        role: Role,
        (k_c2h, k_h2c): (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>),
        channel_id: String,
        deadline_ms: u64,
    ) -> Self {
        let (send, recv) = match role {
            Role::Client => (k_c2h, k_h2c),
            Role::Host => (k_h2c, k_c2h),
        };
        let half = |key| Half {
            key,
            counter: 0,
            bytes: 0,
        };
        Channel {
            role,
            send: half(send),
            recv: half(recv),
            channel_id,
            deadline_ms,
            confirmed: role == Role::Host,
            closed: false,
        }
    }

    pub fn role(&self) -> Role {
        self.role
    }

    /// `hex(th4[0..16])`.
    pub fn channel_id(&self) -> &str {
        &self.channel_id
    }

    /// When the channel ends (monotonic ms).
    pub fn deadline_ms(&self) -> u64 {
        self.deadline_ms
    }

    /// Ends the channel earlier: a service's or browser's expiry, or the
    /// client's `welcome.authorization_ms_left`. Never extends it.
    pub fn limit_lifetime(&mut self, deadline_ms: u64) {
        self.deadline_ms = self.deadline_ms.min(deadline_ms);
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Records sent and received so far.
    pub fn counters(&self) -> (u64, u64) {
        (self.send.counter, self.recv.counter)
    }

    /// Closes the channel and wipes its keys.
    pub fn close(&mut self) {
        self.closed = true;
        *self.send.key = [0u8; 32];
        *self.recv.key = [0u8; 32];
    }

    fn fail(&mut self, error: ChannelError) -> ChannelError {
        self.close();
        error
    }

    fn directions(&self) -> (Direction, Direction) {
        match self.role {
            Role::Client => (Direction::C2h, Direction::H2c),
            Role::Host => (Direction::H2c, Direction::C2h),
        }
    }

    /// Seals one session-family message as the next record frame.
    pub fn seal(&mut self, plain: &[u8], now_ms: u64) -> Result<Vec<u8>, ChannelError> {
        if self.closed {
            return Err(ChannelError::Closed);
        }
        if plain.len() > MAX_PLAINTEXT {
            return Err(ChannelError::TooLarge);
        }
        if now_ms >= self.deadline_ms {
            return Err(self.fail(ChannelError::Limit(Limit::Lifetime)));
        }
        if self.send.counter >= MAX_RECORDS {
            return Err(self.fail(ChannelError::Limit(Limit::Records)));
        }
        if self.send.bytes + plain.len() as u64 > MAX_DIRECTION_BYTES {
            return Err(self.fail(ChannelError::Limit(Limit::Bytes)));
        }
        let (dir, _) = self.directions();
        let ct = aead_seal(
            &self.send.key,
            &record_nonce(self.send.counter),
            &record_aad(dir),
            plain,
        );
        self.send.counter += 1;
        self.send.bytes += plain.len() as u64;
        Ok(Frame::Rec { ct }.to_bytes())
    }

    /// Opens the next record frame. Any failure closes the channel (no
    /// reply); a clear `error` before the host's first record (a client
    /// whose `finish` failed its tag) is returned as advisory.
    pub fn open(&mut self, frame: &[u8], now_ms: u64) -> Result<Zeroizing<Vec<u8>>, ChannelError> {
        if self.closed {
            return Err(ChannelError::Closed);
        }
        if now_ms >= self.deadline_ms {
            return Err(self.fail(ChannelError::Limit(Limit::Lifetime)));
        }
        let ct = match parse_frame(frame) {
            Ok(Frame::Rec { ct }) => ct,
            Ok(Frame::Error { code }) if !self.confirmed => {
                // Unauthenticated: a reason to retry or show, nothing more.
                return Err(self.fail(ChannelError::Advisory { code }));
            }
            _ => return Err(self.fail(ChannelError::RecordRejected)),
        };
        if self.recv.counter >= MAX_RECORDS {
            return Err(self.fail(ChannelError::Limit(Limit::Records)));
        }
        let (_, dir) = self.directions();
        let Some(plain) = aead_open(
            &self.recv.key,
            &record_nonce(self.recv.counter),
            &record_aad(dir),
            &ct,
        ) else {
            return Err(self.fail(ChannelError::RecordRejected));
        };
        if self.recv.bytes + plain.len() as u64 > MAX_DIRECTION_BYTES {
            return Err(self.fail(ChannelError::Limit(Limit::Bytes)));
        }
        self.recv.counter += 1;
        self.recv.bytes += plain.len() as u64;
        self.confirmed = true;
        Ok(plain)
    }
}

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel")
            .field("role", &self.role)
            .field("channel_id", &self.channel_id)
            .field("counters", &self.counters())
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Channel, Channel) {
        let keys = || (Zeroizing::new([1u8; 32]), Zeroizing::new([2u8; 32]));
        (
            Channel::new(Role::Client, keys(), "id".into(), 1_000),
            Channel::new(Role::Host, keys(), "id".into(), 1_000),
        )
    }

    #[test]
    fn the_record_limit_closes_before_counter_2_pow_32() {
        let (mut client, mut host) = pair();
        client.send.counter = MAX_RECORDS - 1;
        host.recv.counter = MAX_RECORDS - 1;
        let last = client.seal(b"last", 0).unwrap();
        assert_eq!(&**host.open(&last, 0).unwrap(), b"last");
        assert_eq!(
            client.seal(b"one more", 0),
            Err(ChannelError::Limit(Limit::Records))
        );
        assert!(client.is_closed());
        // The receiver refuses one more as well, without trying to open it.
        assert_eq!(
            host.open(&last, 0),
            Err(ChannelError::Limit(Limit::Records))
        );
        assert!(host.is_closed());
    }

    #[test]
    fn the_byte_limit_closes_both_sides() {
        let (mut client, mut host) = pair();
        client.send.bytes = MAX_DIRECTION_BYTES - 4;
        host.recv.bytes = MAX_DIRECTION_BYTES - 4;
        let frame = client.seal(b"four", 0).unwrap();
        host.open(&frame, 0).unwrap();
        assert_eq!(client.seal(b"x", 0), Err(ChannelError::Limit(Limit::Bytes)));
        // A sender past the limit (a peer that ignores it) is refused too.
        let (mut client, mut host) = pair();
        host.recv.bytes = MAX_DIRECTION_BYTES - 3;
        let frame = client.seal(b"four", 0).unwrap();
        assert_eq!(host.open(&frame, 0), Err(ChannelError::Limit(Limit::Bytes)));
        assert!(host.is_closed());
    }

    #[test]
    fn the_lifetime_ends_the_channel_and_only_shrinks() {
        let (mut client, mut host) = pair();
        client.limit_lifetime(5_000);
        assert_eq!(client.deadline_ms(), 1_000);
        host.limit_lifetime(500);
        let frame = client.seal(b"m", 600).unwrap();
        assert_eq!(
            host.open(&frame, 600),
            Err(ChannelError::Limit(Limit::Lifetime))
        );
        assert_eq!(
            client.seal(b"m", 1_000),
            Err(ChannelError::Limit(Limit::Lifetime))
        );
        assert_eq!(client.seal(b"m", 0), Err(ChannelError::Closed));
    }

    #[test]
    fn close_wipes_the_keys() {
        let (mut client, _) = pair();
        client.close();
        assert_eq!(*client.send.key, [0u8; 32]);
        assert_eq!(*client.recv.key, [0u8; 32]);
    }
}
