use core::fmt;
use std::convert::{From, Into};

/// STORE_BLOCK_SIZE is the size in bytes of blocks used for the raw
/// storage pools. This is the unit counted by the StoreBlocks type.
pub const STORE_BLOCK_SIZE: u64 = 8192;

#[derive(Debug, PartialEq)]
pub struct Bytes(u64);

impl fmt::Display for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Convert from StoreBlocks byte count;
impl From<StoreBlocks> for Bytes {
    fn from(nblocks: StoreBlocks) -> Self {
        Bytes(nblocks.0 * STORE_BLOCK_SIZE)
    }
}

/// Convert from byte count to Bytes.
impl From<u64> for Bytes {
    fn from(nbytes: u64) -> Self {
        Bytes(nbytes)
    }
}

/// Convert from Bytes to a count of bytes.
impl From<Bytes> for u64 {
    fn from(nbytes: Bytes) -> u64 {
        nbytes.0
    }
}

/// StoreBlocks counts blocks in units of STORE_BLOCK_SIZE bytes.
#[derive(Debug, PartialEq)]
pub struct StoreBlocks(u64);

impl StoreBlocks {
    pub fn as_bytes(&self) -> u64 {
        self.0 * STORE_BLOCK_SIZE
    }
}

impl fmt::Display for StoreBlocks {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Convert from block count to StoreBlocks.
impl From<u64> for StoreBlocks {
    fn from(nblocks: u64) -> Self {
        StoreBlocks(nblocks)
    }
}

/// Convert from StoreBlocks to a raw count of blocks.
impl From<StoreBlocks> for u64 {
    fn from(nblocks: StoreBlocks) -> u64 {
        nblocks.0
    }
}

/// Convert from Bytes to the number of store blocks needed to cover
/// the range of bytes.
impl From<Bytes> for StoreBlocks {
    fn from(nbytes: Bytes) -> Self {
        // Round the store blocks up to cover the full byte count.
        StoreBlocks((Into::<u64>::into(nbytes) + (STORE_BLOCK_SIZE - 1)) / STORE_BLOCK_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_to_store_blocks() {
        assert!(StoreBlocks::from(Bytes::from(1u64)) == StoreBlocks::from(1u64));
        assert!(StoreBlocks::from(Bytes::from(STORE_BLOCK_SIZE)) == StoreBlocks::from(1u64));
        assert!(StoreBlocks::from(Bytes::from(STORE_BLOCK_SIZE + 1)) == StoreBlocks::from(2u64));
    }

    #[test]
    fn store_blocks_to_bytes() {
        assert!(Bytes::from(StoreBlocks::from(1u64)) == Bytes::from(STORE_BLOCK_SIZE));
        assert!(Bytes::from(StoreBlocks::from(4u64)) == Bytes::from(STORE_BLOCK_SIZE * 4));
    }
}
