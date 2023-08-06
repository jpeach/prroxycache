use core::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::{FileExt, FileTypeExt};
use std::path::{Path, PathBuf};

use super::CACHE_BLOCK_SIZE;

pub const SPAN_BLOCK_TYPE_NONE: u32 = 0; // CACHE_NONE_TYPE
pub const SPAN_BLOCK_TYPE_HTTP: u32 = 1; // CACHE_HTTP_TYPE
pub const SPAN_BLOCK_TYPE_RTSP: u32 = 2; // CACHE_RTSP_TYPE

pub const DISK_HEADER_MAGIC: u32 = 0xABCD1237;

pub const STORE_BLOCK_SIZE: u64 = 8192;

/// SPAN_START_OFFSET is the number of bytes from the start of a storage
/// span to the corresponding SpanHeader. Exactly why there is an offset
/// is not known.
pub const SPAN_START_OFFSET: u64 = 16 /* START_BLOCKS */ * CACHE_BLOCK_SIZE;

// TrafficServer calls this type "struct DiskHeader".
#[derive(Default)]
pub struct SpanHeader {
    // Disk magic, DISK_HEADER_MAGIC.
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
    pub const SIZE_BYTES: usize =
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
        if h.magic == u32::swap_bytes(DISK_HEADER_MAGIC) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "cache is in non-native byte order",
            ));
        }

        if h.magic != DISK_HEADER_MAGIC {
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

// TrafficServer calls this type "struct DiskVolBlock".
#[derive(Default)]
pub struct SpanBlock {
    /// Offset in bytes from the startof the span device to the where?
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

    /// block_type returns the type of the span, block, which is encoded
    /// in the top 3 bits of the flags field.
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

/// Span is a single contiguous block of storage, either a regular file or a raw disk.
///
/// While the TrafficServer cache documentation can the udnerlying
/// storage a span, in the code Span is basically an empty abstraction
/// and the actual work is sibe by a CacheDisk object.
pub struct Span {
    // Total storage size in bytes.
    size_bytes: u64,

    // Storage alignment requirement in bytes. Always 0 for regular files,
    // probed from the disk geometry for block devices.
    #[allow(dead_code)]
    align_bytes: u64,

    file: fs::File,
}

impl Span {
    // Open a span from the given path.
    //
    // A span can be a regular file, a block device, or a directory.
    pub fn open(path: &Path) -> io::Result<Self> {
        let m = std::fs::metadata(path)?;

        if m.is_dir() {
            return Span::from_file(PathBuf::from(path).join("cache.db").as_path());
        }

        if m.file_type().is_block_device() {
            return Span::from_blockdev(path);
        }

        // Attempt opening as a regular file.
        Span::from_file(path)
    }

    fn from_file(path: &Path) -> io::Result<Self> {
        let file = fs::OpenOptions::new().read(true).open(path)?;
        let m = file.metadata()?;

        return Ok(Self {
            file: file,
            align_bytes: 0,
            size_bytes: m.len(),
        });
    }

    fn from_blockdev(path: &Path) -> io::Result<Self> {
        let _file = fs::OpenOptions::new().open(path)?;

        // TODO(jpeach) implement and test on linux.
        // See <http://syhpoon.ca/posts/how-to-get-block-device-size-on-linux-with-rust>.
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    pub fn size_blocks(self: &Self) -> u64 {
        return self.size_bytes / STORE_BLOCK_SIZE;
    }

    pub fn size_bytes(self: &Self) -> u64 {
        return self.size_bytes;
    }

    pub fn read_header(self: &Self) -> io::Result<SpanHeader> {
        let mut header_bytes: [u8; SpanHeader::SIZE_BYTES] = [0; SpanHeader::SIZE_BYTES];

        // TrafficServer always skips the first 8k of each span. There's code that assumes the
        // start offset can change, but it's never set, so likely dead.
        let nbytes = self.file.read_at(&mut header_bytes, SPAN_START_OFFSET)?;
        if nbytes < SpanHeader::SIZE_BYTES {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        SpanHeader::from_bytes(&header_bytes)
    }

    /// read_block reads the nth SpanBlock record from the span. The caller is responsible
    /// for knowing that block_num is a valid block number (starting from index 0).
    pub fn read_block(self: &Self, block_num: usize) -> io::Result<SpanBlock> {
        // Span block records follow immediately after the span header. There
        // could be compiler alignment separating the two, but since the header
        // is aligned and it's size is 32 bytes, the span block records always
        // have 8 byte alignment with no extra padding.

        let block_offset = SPAN_START_OFFSET as usize
            + SpanHeader::SIZE_BYTES
            + (block_num * SpanBlock::SIZE_BYTES);

        let mut block_bytes: [u8; SpanBlock::SIZE_BYTES] = [0; SpanBlock::SIZE_BYTES];

        let nbytes = self.file.read_at(&mut block_bytes, block_offset as u64)?;
        if nbytes < SpanBlock::SIZE_BYTES {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        SpanBlock::from_bytes(&block_bytes)
    }
}
