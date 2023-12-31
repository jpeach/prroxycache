pub mod disk;
pub mod types;

mod span;
mod vol;

// TODO(jpeach) think about exactly what we want to export here ...
pub use span::Span; // XXX
pub use vol::Vol; // XXX

pub const DOC_MAGIC: u32 = 0x5F129B13;
pub const DOC_CORRUPT: u32 = 0xDEADBABE;
pub const DOC_NO_CHECKSUM: u32 = 0xA0B0C0D0;

pub const CACHE_DB_MAJOR_VERSION: u8 = 24;
pub const CACHE_DB_MINOR_VERSION: u8 = 2;

pub const CACHE_DIR_MAJOR_VERSION: u8 = 18;
pub const CACHE_DIR_MINOR_VERSION: u8 = 0;
