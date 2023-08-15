/// Module disk contains direct transliterations of Traffic Server on-disk structures.
use core::fmt;
use std::io;

/// Basic block size (in bytes) for cache storage.
pub const CACHE_BLOCK_SIZE: u64 = 512;

/// SPAN_HEADER_MAGIC is the magic number used to identify disk header.
pub const SPAN_HEADER_MAGIC: u32 = 0xABCD1237;

/// SpanHeader is the header for a Traffic Server cache storage volume (either a file or a block device).
///
/// Traffic Server calls this type "struct DiskHeader".
/// https://github.com/apache/trafficserver/blob/master/iocore/cache/P_CacheDisk.h#L71-L79
#[derive(Default, PartialEq)]
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
#[derive(Default, PartialEq)]
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

    pub fn size_bytes(self: &Self) -> u64 {
        self.len * CACHE_BLOCK_SIZE
    }

    pub fn size_blocks(self: &Self) -> u64 {
        self.len
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
