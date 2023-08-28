use std::fs;
use std::io;
use std::os::unix::fs::{FileExt, FileTypeExt};
use std::path::{Path, PathBuf};

use crate::trafficserver::disk;
use crate::trafficserver::disk::{SpanBlock, SpanHeader};
use crate::trafficserver::STORE_BLOCK_SIZE;

/// SPAN_START_OFFSET is the number of bytes from the start of a storage
/// span to the corresponding SpanHeader. Exactly why there is an offset
/// is not known.
pub const SPAN_START_OFFSET: u64 = 16 /* START_BLOCKS */ * disk::CACHE_BLOCK_SIZE;

/// Span is a single contiguous block of storage, either a regular file
/// or a raw disk.
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

    pub fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        self.file.read_at(buf, offset)
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
