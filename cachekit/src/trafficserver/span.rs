use core::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::{FileExt, FileTypeExt};
use std::path::{Path, PathBuf};

use super::CACHE_BLOCK_SIZE;

pub const DISK_HEADER_MAGIC: u32 = 0xABCD1237;

pub const STORE_BLOCK_SIZE: u64 = 8192;

/// SPAN_START_OFFSET is the number of bytes from the start of a storage
/// span to the corresponding SpanHeader. Exactly why there is an offset
/// is not known.
pub const SPAN_START_OFFSET: u64 = 16 /* START_BLOCKS */ * CACHE_BLOCK_SIZE;

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

        h.magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        if h.magic == DISK_HEADER_MAGIC {
            h.num_volumes = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
            h.num_free = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
            h.num_used = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
            h.num_diskvol_blks = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
            h.num_blocks = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
            return Ok(h);
        }

        h.magic = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        if h.magic == DISK_HEADER_MAGIC {
            // TODO(jpeach) There's no formal on-disk byte order, so
            // the cache could have been written on a big-endian
            // machine. Unlikely, but possible.
            return Err(io::Error::from(io::ErrorKind::Unsupported));
        }

        Err(io::Error::from(io::ErrorKind::InvalidData))
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
}
