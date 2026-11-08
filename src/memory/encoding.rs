//! Length-prefixed encoding for every signed, hashed or bound input: each
//! field is a 4-byte big-endian length followed by its bytes, label first.
//! See designs/e2e-encryption.md "Formats".
use anyhow::{Result, anyhow, bail};
use serde::Serialize;
use std::io::Write;
use zeroize::Zeroizing;

/// The same encoding r9 signs over (`atem_client::encoding`, §R9.1).
pub use atem_client::encoding::{enc, u64_field};

pub fn dec(mut bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut fields = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            bail!("encoded statement is truncated");
        }
        let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        bytes = &bytes[4..];
        if bytes.len() < len {
            bail!("encoded statement is truncated");
        }
        fields.push(bytes[..len].to_vec());
        bytes = &bytes[len..];
    }
    Ok(fields)
}

pub fn read_u64(field: &[u8]) -> Result<u64> {
    let bytes: [u8; 8] = field
        .try_into()
        .map_err(|_| anyhow!("expected an 8-byte number"))?;
    Ok(u64::from_be_bytes(bytes))
}

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The first `chars` base32 characters of `bytes` (RFC 4648 alphabet, no padding).
pub fn base32_prefix(bytes: &[u8], chars: usize) -> String {
    let mut out = String::with_capacity(chars);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            if out.len() == chars {
                return out;
            }
            bits -= 5;
            out.push(BASE32[((buffer >> bits) & 31) as usize] as char);
        }
        buffer &= (1 << bits) - 1;
    }
    // Final partial group: zero-pad to 5 bits, as RFC 4648 does.
    if bits > 0 && out.len() < chars {
        out.push(BASE32[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Zeroes `bytes` in one pass at `memset` speed, in a way the compiler must
/// keep: the stores are followed by an empty `asm!` block that is handed the
/// buffer's address and may read memory (no `nomem`), so the zeros are
/// observable and can't be removed as dead stores, even right before the
/// buffer is freed or goes out of scope. This is zeroize 1.9's
/// `optimization_barrier`; zeroize 1.8 (ours) writes one volatile byte at a
/// time, about 1.5 GB/s. Architectures without stable `asm!` use zeroize.
pub(crate) fn wipe(bytes: &mut [u8]) {
    // SAFETY: `bytes` is a valid, writable slice of `bytes.len()` bytes.
    unsafe { wipe_raw(bytes.as_mut_ptr(), bytes.len()) }
}

/// [`wipe`] for memory that may not be initialized (a `Vec`'s spare capacity).
pub(crate) fn wipe_uninit(bytes: &mut [std::mem::MaybeUninit<u8>]) {
    // SAFETY: writing bytes into allocated memory is valid, initialized or not.
    unsafe { wipe_raw(bytes.as_mut_ptr().cast(), bytes.len()) }
}

/// # Safety
/// `ptr` must be valid for writes of `len` bytes.
unsafe fn wipe_raw(ptr: *mut u8, len: usize) {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    // SAFETY: the caller's contract; the asm block reads nothing and writes
    // nothing (an empty template), it only counts as possibly reading `ptr`.
    unsafe {
        std::ptr::write_bytes(ptr, 0, len);
        std::arch::asm!(
            "# {}",
            in(reg) ptr.cast_const(),
            options(readonly, preserves_flags, nostack),
        );
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    // SAFETY: the caller's contract.
    unsafe {
        zeroize::Zeroize::zeroize(std::slice::from_raw_parts_mut(ptr, len));
    }
}

/// Bytes that may be secret, wiped whole with [`wipe`] when dropped: made at
/// their final size (`copy_of`, `zeroed`, `from_vec`), they
/// can be written in place but never grow, so no reallocation leaves an
/// unwiped copy behind.
#[derive(Default)]
pub(crate) struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub(crate) fn copy_of(bytes: &[u8]) -> Self {
        let mut vec = Vec::with_capacity(bytes.len());
        vec.extend_from_slice(bytes);
        Self(vec)
    }

    /// `len` zero bytes, to read into.
    pub(crate) fn zeroed(len: usize) -> Self {
        Self(vec![0; len])
    }

    /// Takes `vec` as it is (its earlier allocations, if any, are its owner's
    /// business): e.g. what an AEAD returned.
    pub(crate) fn from_vec(vec: Vec<u8>) -> Self {
        Self(vec)
    }

    /// Keeps the first `len` bytes; the rest stays in the allocation until
    /// the drop wipes it.
    pub(crate) fn truncate(&mut self, len: usize) {
        self.0.truncate(len);
    }

    /// Wipes the whole allocation, used bytes and spare capacity.
    fn wipe_all(&mut self) {
        // SAFETY: the whole allocation is valid for writes.
        unsafe { wipe_raw(self.0.as_mut_ptr(), self.0.capacity()) }
    }
}

impl std::ops::Deref for SecretBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::DerefMut for SecretBytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.wipe_all();
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes({} bytes)", self.0.len())
    }
}

/// A growing buffer that wipes what it outgrows (`Vec` would leave the old
/// allocation behind unwiped).
pub(crate) struct WipingBuf(pub(crate) Zeroizing<Vec<u8>>);

impl WipingBuf {
    pub(crate) fn new() -> Self {
        Self::with_capacity(4096)
    }

    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self(Zeroizing::new(Vec::with_capacity(capacity)))
    }

    pub(crate) fn append(&mut self, data: &[u8]) {
        let needed = self.0.len() + data.len();
        if needed > self.0.capacity() {
            let mut bigger = Zeroizing::new(Vec::with_capacity(needed.max(self.0.capacity() * 2)));
            bigger.extend_from_slice(&self.0);
            let outgrown = std::mem::replace(&mut self.0, bigger);
            wipe_dropped(outgrown);
        }
        self.0.extend_from_slice(data);
    }
}

/// Drops `buf` with its whole allocation wiped by [`wipe`] (what is left in
/// the `Zeroizing` is empty, so zeroize's own slower pass has nothing to do).
fn wipe_dropped(mut buf: Zeroizing<Vec<u8>>) {
    drop(SecretBytes(std::mem::take(&mut *buf)));
}

impl Drop for WipingBuf {
    fn drop(&mut self) {
        wipe_dropped(std::mem::take(&mut self.0));
    }
}

impl Write for WipingBuf {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.append(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Counts the bytes written to it, keeping none.
struct ByteCount(usize);

impl Write for ByteCount {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0 += data.len();
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// `value` as JSON in one allocation of exactly its size, wiped on drop: for
/// payloads that carry keys. It is measured first, then written, so the
/// buffer never grows (`serde_json::to_vec` would leave every smaller copy
/// behind in freed memory, unwiped). Should the two passes differ, the
/// buffer grows by wiping copies.
pub(crate) fn to_presized_json<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>> {
    let mut count = ByteCount(0);
    serde_json::to_writer(&mut count, value)?;
    let mut buf = WipingBuf::with_capacity(count.0);
    serde_json::to_writer(&mut buf, value)?;
    Ok(std::mem::take(&mut buf.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presized_json_is_exact_and_matches_serde() {
        let value = serde_json::json!({"key": "a".repeat(10_000), "n": [1, 2, 3]});
        let bytes = to_presized_json(&value).unwrap();
        assert_eq!(*bytes, serde_json::to_vec(&value).unwrap());
        assert_eq!(bytes.capacity(), bytes.len(), "never grew");
    }

    #[test]
    fn wipe_zeroes_every_byte_initialized_or_not() {
        let mut bytes = *b"secret bytes";
        wipe(&mut bytes);
        assert_eq!(bytes, [0; 12]);
        let mut vec = Vec::with_capacity(64);
        vec.extend_from_slice(b"secret");
        // SAFETY: fills the spare capacity, so all 64 bytes are initialized.
        unsafe { std::ptr::write_bytes(vec.as_mut_ptr().add(6), 0xAA, 58) };
        wipe_uninit(vec.spare_capacity_mut());
        wipe(&mut vec);
        // SAFETY: all 64 bytes of the live allocation were written above.
        let all = unsafe { std::slice::from_raw_parts(vec.as_ptr(), 64) };
        assert!(all.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn secret_bytes_wipe_their_whole_allocation() {
        let mut vec = Vec::with_capacity(4096);
        vec.extend_from_slice(b"SECRET-PLAIN-TEXT");
        // SAFETY: marks the spare capacity, as an earlier, longer use would.
        unsafe { std::ptr::write_bytes(vec.as_mut_ptr().add(17), 0xAA, 4096 - 17) };
        let mut secret = SecretBytes::from_vec(vec);
        secret.truncate(6);
        assert_eq!(&secret[..], b"SECRET");
        let (ptr, capacity) = (secret.0.as_ptr(), secret.0.capacity());
        secret.wipe_all();
        // SAFETY: the allocation is still live and every byte was written.
        let all = unsafe { std::slice::from_raw_parts(ptr, capacity) };
        assert!(all.iter().all(|byte| *byte == 0));
        assert_eq!(SecretBytes::copy_of(b"abc").0.capacity(), 3, "exact size");
    }

    #[test]
    fn a_wiping_buffer_keeps_its_contents_when_it_grows() {
        let mut buf = WipingBuf::with_capacity(2);
        buf.append(b"ab");
        buf.append(b"cdef");
        assert_eq!(&buf.0[..], b"abcdef");
        assert!(buf.0.capacity() >= 6);
    }

    #[test]
    fn round_trip_keeps_every_field() {
        let fields: Vec<&[u8]> = vec![b"label", b"", b"\x00\x01", b"abc"];
        let bytes = enc(&fields);
        let back = dec(&bytes).unwrap();
        assert_eq!(back, fields.iter().map(|f| f.to_vec()).collect::<Vec<_>>());
    }

    #[test]
    fn field_boundaries_cannot_shift() {
        assert_ne!(enc(&[b"a/b", b"cd"]), enc(&[b"a/bc", b"d"]));
    }

    #[test]
    fn truncated_input_is_rejected() {
        let mut bytes = enc(&[b"label", b"value"]);
        bytes.pop();
        assert!(dec(&bytes).is_err());
        assert!(dec(&[0, 0]).is_err());
    }

    #[test]
    fn u64_fields_round_trip() {
        assert_eq!(
            read_u64(&u64_field(0x0102_0304_0506_0708)).unwrap(),
            0x0102_0304_0506_0708
        );
        assert!(read_u64(b"short").is_err());
    }

    #[test]
    fn base32_matches_rfc4648() {
        assert_eq!(base32_prefix(b"foobar", 10), "MZXW6YTBOI");
        assert_eq!(base32_prefix(b"foobar", 4), "MZXW");
        assert_eq!(base32_prefix(&[0xff; 32], 12), "777777777777");
    }
}
