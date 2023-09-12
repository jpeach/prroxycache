/// Module disk contains direct transliterations of Traffic Server on-disk structures.
use core::fmt;
use std::{io, mem};

use super::types::{Bytes, StoreBlocks};

/// Basic block size (in bytes) for cache storage.
pub const CACHE_BLOCK_SIZE: u64 = 512;

/// SPAN_HEADER_MAGIC is the magic number used to identify disk header.
pub const SPAN_HEADER_MAGIC: u32 = 0xABCD1237;

/// VOL_HEADER_MAGIC is the magic number used to identify VolHeaderFooter structures. Traffic
/// Server calls this VOL_MAGIC.
pub const VOL_HEADER_MAGIC: u32 = 0xF1D0F00D;

/// ENTRY_SIZE is the size of a directory entry on disk. Traffic Server
/// calls this SIZEOF_DIR. This is the same value as Dir::SIZE_BYTES.
pub const ENTRY_SIZE: u64 = 10;

/// ENTRIES_PER_BUCKET is the number of Dir entries in each segment
/// bucket. Traffic Server calls this DIR_DEPTH.
pub const ENTRIES_PER_BUCKET: u64 = 4;
pub const MAX_ENTRIES_PER_SEGMENT: u64 = 1 << 16; // 16-bit index
pub const MAX_BUCKETS_PER_SEGMENT: u64 = MAX_ENTRIES_PER_SEGMENT / ENTRIES_PER_BUCKET;

/// SpanHeader is the header for a Traffic Server cache storage volume (either a file or a block device).
///
/// Traffic Server calls this type "struct DiskHeader".
/// https://github.com/apache/trafficserver/blob/master/iocore/cache/P_CacheDisk.h#L71-L79
#[derive(Copy, Clone, Default, PartialEq)]
pub struct SpanHeader {
    // Disk magic, SPAN_HEADER_MAGIC.
    pub magic: u32,
    // Number of volumes (DiskVol) in this span.
    pub num_volumes: u32,      /* number of discrete volumes (DiskVol) */
    pub num_free: u32,         /* number of disk volume blocks free */
    pub num_used: u32,         /* number of disk volume blocks in use */
    pub num_diskvol_blks: u32, /* number of disk volume blocks */
    pub num_blocks: u64,
}

impl fmt::Debug for SpanHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpanHeader")
            .field("magic", &format_args!("{:#X}", &self.magic))
            .field("num_volumes", &self.num_volumes)
            .field("num_free", &self.num_free)
            .field("num_used", &self.num_used)
            .field("num_diskvol_blks", &self.num_diskvol_blks)
            .field("num_blocks", &self.num_blocks)
            .finish()
    }
}

impl SpanHeader {
    /// SIZE_BYTES is the number of bytes that the on-disk layout
    /// consumes. This is the same as the in-memory "struct DiskHeader"
    /// layout, so it includes field alignment inserted by the compiler.
    pub const SIZE_BYTES : usize  =
        4 + /* magic */
        4 + /* num_volumes */
        4 + /* num_free */
        4 + /* num_used */
        4 + /* num_diskvol_blks */
        4 + /* padding for u64 alignment */
        8  /* num_blocks */
        ;

    pub fn from_bytes(bytes: &[u8]) -> io::Result<SpanHeader> {
        let mut h = SpanHeader {
            ..Default::default()
        };

        if bytes.len() < SpanHeader::SIZE_BYTES {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }

        h.magic = u32::from_ne_bytes(bytes[0..4].try_into().unwrap());

        // If the magic is byte-swapped, we are a different endianness
        // than the process that wrote the cache. No support for that
        // yet.
        if h.magic == u32::swap_bytes(SPAN_HEADER_MAGIC) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "cache is in non-native byte order",
            ));
        }

        if h.magic != SPAN_HEADER_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid cache header",
            ));
        }

        h.num_volumes = u32::from_ne_bytes(bytes[4..8].try_into().unwrap());
        h.num_free = u32::from_ne_bytes(bytes[8..12].try_into().unwrap());
        h.num_used = u32::from_ne_bytes(bytes[12..16].try_into().unwrap());
        h.num_diskvol_blks = u32::from_ne_bytes(bytes[16..20].try_into().unwrap());
        h.num_blocks = u64::from_ne_bytes(bytes[24..32].try_into().unwrap());

        Ok(h)
    }
}

pub const SPAN_BLOCK_TYPE_NONE: u32 = 0; // CACHE_NONE_TYPE
pub const SPAN_BLOCK_TYPE_HTTP: u32 = 1; // CACHE_HTTP_TYPE
pub const SPAN_BLOCK_TYPE_RTSP: u32 = 2; // CACHE_RTSP_TYPE

/// TrafficServer calls this type "struct DiskVolBlock".
/// https://github.com/apache/trafficserver/blob/master/iocore/cache/P_CacheDisk.h#L47-L53
#[derive(Copy, Clone, Default, PartialEq)]
pub struct SpanBlock {
    /// Offset in bytes from the start of the span device to the where?
    offset: u64,
    len: u64, // Block length in cache blocks.
    num: u32,
    flags: u32, // Compiler bitfield, with type:3 and free:1 elements.
}

impl SpanBlock {
    pub const SIZE_BYTES: usize =
        8 +/* offset */
        8 + /* len */
        4 + /* num */
        4 /* flags */
        ;

    /// offset returns the ofset (in bytes) from the beginning of the
    /// span file, to the start of the data that this block describes.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// block_type returns the type of the span, block, which is encoded
    /// in the top 3 bits of the flags field. This returns one of the
    /// SPAN_BLOCK_TYPE constants.
    pub fn block_type(self: &Self) -> u32 {
        self.flags & 0x00000007
    }

    /// is_free returns whether the block is marked as a free block,
    /// which is encoded in bit 4 of the block flags.
    pub fn is_free(self: &Self) -> bool {
        self.flags & 0x00000008 == 0x00000008
    }

    pub fn size_bytes(self: &Self) -> Bytes {
        Bytes::from(self.size_blocks())
    }

    pub fn size_blocks(self: &Self) -> StoreBlocks {
        StoreBlocks::from(self.len)
    }

    pub fn number(self: &Self) -> u32 {
        self.num
    }

    pub fn from_bytes(bytes: &[u8]) -> io::Result<SpanBlock> {
        let mut b = SpanBlock {
            ..Default::default()
        };

        if bytes.len() < SpanBlock::SIZE_BYTES {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }

        b.offset = u64::from_ne_bytes(bytes[0..8].try_into().unwrap());
        b.len = u64::from_ne_bytes(bytes[8..16].try_into().unwrap());
        b.num = u32::from_ne_bytes(bytes[16..20].try_into().unwrap());
        b.flags = u32::from_ne_bytes(bytes[20..24].try_into().unwrap());

        Ok(b)
    }
}

impl fmt::Debug for SpanBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let default_name = self.block_type().to_string();
        let type_name = match self.block_type() {
            SPAN_BLOCK_TYPE_NONE => "none",
            SPAN_BLOCK_TYPE_HTTP => "http",
            SPAN_BLOCK_TYPE_RTSP => "rtsp",
            _ => default_name.as_str(),
        };

        f.debug_struct("SpanBlock")
            .field("number", &self.number())
            .field("size (bytes)", &self.size_bytes())
            .field("size (cache blocks)", &self.size_blocks())
            .field("offset (bytes)", &self.offset)
            .field("type", &type_name)
            .field("free", &self.is_free())
            .finish()
    }
}

// See I_CacheDefs.h.
const CACHE_DB_MAJOR_VERSION: u16 = 24;
#[allow(dead_code)]
const CACHE_DB_MINOR_VERSION: u16 = 2;

const CACHE_DB_MAJOR_VERSION_COMPATIBLE: u16 = 21;

#[derive(Default, PartialEq)]
pub struct VolHeaderFooter {
    pub magic: u32, // Stripe header magic, VOL_MAGIC.
    pub major_version: u16,
    pub minor_version: u16,
    pub create_time: i64, // Assuming 64-bit time_t.
    pub write_pos: i64,
    pub last_write_pos: i64,
    pub agg_pos: i64,
    pub generation: u32,
    pub phase: u32,
    pub cycle: u32,
    pub sync_serial: u32,
    pub write_serial: u32,
    pub dirty: u32,
    pub sector_size: u32,
    unused: u32,
}

impl VolHeaderFooter {
    pub const SIZE_BYTES : usize  =
    4 + /* magic */
    2 + /* major_version */
    2 + /* minor_version */
    8 + /* create_time */
    8 + /* write_pos */
    8 + /* last_write_pos */
    8 + /* agg_pos */
    4 + /* generation */
    4 + /* phase */
    4 + /* cycle */
    4 + /* sync_serial */
    4 + /* write_serial */
    4 + /* dirty */
    4 + /* sector_size */
    4  /* pad */
    ;

    pub fn from_bytes(bytes: &[u8]) -> io::Result<VolHeaderFooter> {
        let mut v = VolHeaderFooter {
            ..Default::default()
        };

        if bytes.len() < VolHeaderFooter::SIZE_BYTES {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }

        v.magic = u32::from_ne_bytes(bytes[0..4].try_into().unwrap());

        if v.magic == u32::swap_bytes(VOL_HEADER_MAGIC) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "cache is in non-native byte order",
            ));
        }

        if v.magic != VOL_HEADER_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "invalid VolHeaderFooter header",
            ));
        }

        v.major_version = u16::from_ne_bytes(bytes[4..6].try_into().unwrap());
        v.minor_version = u16::from_ne_bytes(bytes[6..8].try_into().unwrap());
        v.create_time = i64::from_ne_bytes(bytes[8..16].try_into().unwrap());
        v.write_pos = i64::from_ne_bytes(bytes[16..24].try_into().unwrap());
        v.last_write_pos = i64::from_ne_bytes(bytes[24..32].try_into().unwrap());
        v.agg_pos = i64::from_ne_bytes(bytes[32..40].try_into().unwrap());
        v.generation = u32::from_ne_bytes(bytes[40..44].try_into().unwrap());
        v.phase = u32::from_ne_bytes(bytes[44..48].try_into().unwrap());
        v.cycle = u32::from_ne_bytes(bytes[48..52].try_into().unwrap());
        v.sync_serial = u32::from_ne_bytes(bytes[52..56].try_into().unwrap());
        v.write_serial = u32::from_ne_bytes(bytes[56..60].try_into().unwrap());
        v.dirty = u32::from_ne_bytes(bytes[60..64].try_into().unwrap());
        v.sector_size = u32::from_ne_bytes(bytes[64..68].try_into().unwrap());

        // Don't bother deserializing the unused pad field.

        // Traffic Server revved the cache version and we need to update.
        if v.major_version > CACHE_DB_MAJOR_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "unsupported cache directory version {}.{}",
                    v.major_version, v.minor_version
                ),
            ));
        }

        // This is a really old cache file.
        if v.major_version <= CACHE_DB_MAJOR_VERSION_COMPATIBLE {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "incompatible cache directory version {}.{}",
                    v.major_version, v.minor_version
                ),
            ));
        }

        Ok(v)
    }
}

impl fmt::Debug for VolHeaderFooter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use time::format_description::well_known::Rfc3339;
        use time::OffsetDateTime;

        let create_time = OffsetDateTime::from_unix_timestamp(self.create_time).unwrap();
        let create_timestr = create_time.format(&Rfc3339).unwrap();

        f.debug_struct("VolHeaderFooter")
            .field("magic", &format_args!("{:#X}", &self.magic))
            .field(
                "version",
                &format!("{}.{}", self.major_version, self.minor_version),
            )
            .field("create_time", &create_timestr)
            .field("write_pos", &self.write_pos)
            .field("last_write_pos", &self.last_write_pos)
            .field("agg_pos", &self.agg_pos)
            .field("generation", &self.generation)
            .field("phase", &self.phase)
            .field("cycle", &self.cycle)
            .field("sync_serial", &self.sync_serial)
            .field("write_serial", &self.write_pos)
            .field("dirty", &self.dirty)
            .field("sector_size", &self.sector_size)
            .finish()
    }
}

#[derive(Debug)]
pub struct Freelist {
    pub entries: Vec<u16>,
}

impl Freelist {
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Freelist> {
        // Must be an exact multiple of the freelist entry size.
        if (bytes.len() % mem::size_of::<u16>()) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid freelist length",
            ));
        }

        let mut entries: Vec<u16> = Vec::with_capacity(bytes.len() / mem::size_of::<u16>());

        for i in (0..bytes.len()).step_by(mem::size_of::<u16>()) {
            let val = u16::from_ne_bytes(bytes[i..i + 2].try_into().unwrap());
            entries.push(val);
        }

        Ok(Freelist { entries })
    }
}

#[derive(Default, Debug, PartialEq)]
pub struct Dir {
    pub offset: u64,
    pub big: u8,
    pub size: u8,
    pub tag: u16,
    pub phase: bool, // Really 1 or 0.
    pub head: bool,
    pub pinned: bool,
    pub token: bool,
    pub next: u16,
}

impl Dir {
    pub const SIZE_BYTES: usize = 10;

    pub fn from_bytes(bytes: &[u8]) -> io::Result<Dir> {
        if bytes.len() < Dir::SIZE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid directory entry length",
            ));
        }

        // Binary layout of the Dir, from Traffic Server source code. Note
        // that this diagram show big-endian bit layouts. The Traffic Server
        // macros that decode this assume that it is all little-endian u16
        // on disk.
        //
        // 0                               1
        //  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |           Offset(16)          |   Offset(24)  |Big|   Size    |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |        Tag            |P|H|I|T|            Next               |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |          Offset(40)           |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //
        // Offset: Unsigned 40 bits split over 3 fields.
        // Big: Unsigned 2 bits.
        // Size: Unsigned 6 bits.
        // Tag: Unsigned 12 bits.
        // P: Phase bit.
        // H: Head bit.
        // I: Pinned bit.
        // T: Token bit.
        // Next: Unsigned 16 bits.

        let binary_dir: [u8; 10] = bytes[0..10].try_into().unwrap();
        let mut d: Dir = Dir {
            ..Default::default()
        };

        d.big = binary_dir[3] & 0x3u8;
        d.size = binary_dir[3] & 0xFCu8;

        d.phase = (binary_dir[5] & 0x10u8) == 0x10u8;
        d.head = (binary_dir[5] & 0x20u8) == 0x20u8;
        d.pinned = (binary_dir[5] & 0x40u8) == 0x40u8;
        d.token = (binary_dir[5] & 0x80u8) == 0x80u8;

        // Read the "tag" field as a u16, but with the PHIT flags masked.
        d.tag = u16::from_ne_bytes(binary_dir[4..6].try_into().unwrap());
        d.tag = d.tag & 0xF000u16;

        d.next = u16::from_ne_bytes(binary_dir[6..8].try_into().unwrap());

        // Set the first 2 bytes from u16.
        d.offset = u16::from_ne_bytes(binary_dir[0..2].try_into().unwrap()) as u64;
        // Then the next bytes to make 24 bits.
        d.offset = d.offset | ((binary_dir[2] as u64) << 16);
        // Finally the last 2 bytes from u16 to make 40 bits.
        d.offset =
            d.offset | ((u16::from_ne_bytes(binary_dir[8..10].try_into().unwrap()) as u64) << 24);

        Ok(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn span_header_short_slice() {
        let bytes: [u8; SpanHeader::SIZE_BYTES - 1] = [0; SpanHeader::SIZE_BYTES - 1];
        assert!(SpanHeader::from_bytes(&bytes).is_err());
    }

    #[test]
    fn span_header_bad_endianness() {
        let bytes: [u8; SpanHeader::SIZE_BYTES] = if cfg!(target_endian = "little") {
            [
                0xAB, 0xCD, 0x12, 0x37, // magic
                0x00, 0x00, 0x00, 0x00, // num vols
                0x00, 0x00, 0x00, 0x00, // num free
                0x00, 0x00, 0x00, 0x00, // num used
                0x00, 0x00, 0x00, 0x00, // num diskvols
                0x00, 0x00, 0x00, 0x00, // padding
                0x00, 0x00, 0x00, 0x00, // num blocks
                0x00, 0x00, 0x00, 0x00,
            ]
        } else {
            [
                0x37, 0x12, 0xCD, 0xAB, // magic
                0x00, 0x00, 0x00, 0x00, // num vols
                0x00, 0x00, 0x00, 0x00, // num free
                0x00, 0x00, 0x00, 0x00, // num used
                0x00, 0x00, 0x00, 0x00, // num diskvols
                0x00, 0x00, 0x00, 0x00, // padding
                0x00, 0x00, 0x00, 0x00, // num blocks
                0x00, 0x00, 0x00, 0x00,
            ]
        };

        let hdr = SpanHeader::from_bytes(&bytes);
        assert!(SpanHeader::from_bytes(&bytes).is_err());
        assert_eq!(
            "cache is in non-native byte order",
            hdr.err().unwrap().to_string()
        );
    }

    #[test]
    fn span_header_bad_magic() {
        let bytes: [u8; SpanHeader::SIZE_BYTES] = [
            0xF0, 0x0D, 0x12, 0x37, // magic
            0x00, 0x00, 0x00, 0x00, // num vols
            0x00, 0x00, 0x00, 0x00, // num free
            0x00, 0x00, 0x00, 0x00, // num used
            0x00, 0x00, 0x00, 0x00, // num diskvols
            0x00, 0x00, 0x00, 0x00, // padding
            0x00, 0x00, 0x00, 0x00, // num blocks
            0x00, 0x00, 0x00, 0x00,
        ];

        let hdr = SpanHeader::from_bytes(&bytes);
        assert!(SpanHeader::from_bytes(&bytes).is_err());
        assert_eq!("invalid cache header", hdr.err().unwrap().to_string());
    }

    #[test]
    fn span_header_basic() {
        let bytes: [u8; SpanHeader::SIZE_BYTES] = [
            0x37, 0x12, 0xCD, 0xAB, //
            0x01, 0x00, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x00, //
            0x01, 0x00, 0x00, 0x00, //
            0x01, 0x00, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x00, //
        ];

        let wanted = SpanHeader {
            magic: SPAN_HEADER_MAGIC,
            num_volumes: 1,
            num_free: 0,
            num_used: 1,
            num_diskvol_blks: 1,
            num_blocks: 0,
        };

        assert_eq!(wanted, SpanHeader::from_bytes(&bytes).unwrap());
    }

    #[test]
    fn span_block_short_slice() {
        let bytes: [u8; SpanBlock::SIZE_BYTES - 1] = [0; SpanBlock::SIZE_BYTES - 1];
        assert!(SpanBlock::from_bytes(&bytes).is_err());
    }

    #[test]
    fn span_block_basic() {
        let bytes: [u8; SpanBlock::SIZE_BYTES] = [
            0xFF, 0x7F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // offset
            0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // len
            0xFE, 0x7F, 0x00, 0x00, // num
            0x00, 0x00, 0x00, 0x00, // flags
        ];

        let wanted = SpanBlock {
            offset: 32767,
            len: 16384,
            num: 32766,
            flags: 0,
        };

        assert_eq!(wanted, SpanBlock::from_bytes(&bytes).unwrap());
    }
}
