use super::disk::{SpanBlock, VolHeaderFooter};
use super::types::{Bytes, StoreBlocks};

// XXX(jpeach) this is a tunable, so we should have a way to parameterize it.
const AVERAGE_OBJECT_SIZE: u64 = 8000;

const ENTRY_SIZE: u64 = 10; // SIZEOF_DIR
const ENTRIES_PER_BUCKET: u64 = 4; // DIR_DEPTH
const MAX_ENTRIES_PER_SEGMENT: u64 = 1 << 16; // 16-bit index
const MAX_BUCKETS_PER_SEGMENT: u64 = MAX_ENTRIES_PER_SEGMENT / ENTRIES_PER_BUCKET;

/// Vol is the description of a cache stripe. The docs call this a stripe,
/// but the code calls this a Vol, so we do to (at least for now).
///
/// All the offsets returned from the Vol are based on the offset of
/// the SpanBlock, and are absolute byte offsets into the underlying
/// storage Span.
pub struct Vol {
    base_offset: u64,
    segment_count: u64,
    buckets_per_segment: u64,
}

impl Vol {
    pub fn from_block(block: &SpanBlock) -> Self {
        let mut segment_count: u64 = 0;
        let mut buckets_per_segment: u64 = 0;

        (segment_count, buckets_per_segment) =
            converge_header_info(segment_count, buckets_per_segment, block);
        (segment_count, buckets_per_segment) =
            converge_header_info(segment_count, buckets_per_segment, block);
        (segment_count, buckets_per_segment) =
            converge_header_info(segment_count, buckets_per_segment, block);

        Vol {
            base_offset: block.offset(),
            segment_count,
            buckets_per_segment,
        }
    }

    pub fn segment_count(self: &Self) -> u64 {
        self.segment_count
    }

    pub fn bucket_count(self: &Self) -> u64 {
        self.segment_count * self.buckets_per_segment
    }

    pub fn content_offset(self: &Self) -> u64 {
        let header_size = 2 * directory_length(self.segment_count, self.buckets_per_segment);
        self.base_offset + header_size
    }

    pub fn first_header_offsets(self: &Self) -> (u64, u64, u64, u64) {
        self.header_offsets(self.base_offset)
    }

    pub fn second_header_offsets(self: &Self) -> (u64, u64, u64, u64) {
        self.header_offsets(
            self.base_offset + directory_length(self.segment_count, self.buckets_per_segment),
        )
    }

    fn header_offsets(self: &Self, base: u64) -> (u64, u64, u64, u64) {
        let header_length: u64 = VolHeaderFooter::SIZE_BYTES as u64;
        let freelist_length: u64 = 2 /* sizeof(uint16_t) */ * (self.segment_count - 1);
        let directory_length: u64 = StoreBlocks::from(Bytes::from(
            self.buckets_per_segment * ENTRIES_PER_BUCKET * self.segment_count * ENTRY_SIZE,
        ))
        .as_bytes();

        let header_block = StoreBlocks::from(Bytes::from(header_length + freelist_length));

        (
            base,                                              // offset to header
            base + header_length,                              // offset to freelist
            base + header_block.as_bytes(),                    // offset to directory
            base + header_block.as_bytes() + directory_length, // offset to footer
        )
    }
}

// Calculate the size of the volume header (aka stripe metadata) based on the segment information.
fn directory_length(segment_count: u64, buckets_per_segment: u64) -> u64 {
    let header_length: u64 = VolHeaderFooter::SIZE_BYTES as u64;
    let freelist_length: u64 = 2 /* sizeof(uint16_t) */ * (segment_count - 1);
    let directory_length: u64 = StoreBlocks::from(Bytes::from(
        buckets_per_segment * ENTRIES_PER_BUCKET * segment_count * ENTRY_SIZE,
    ))
    .as_bytes();
    let footer_length: u64 =
        StoreBlocks::from(Bytes::from(VolHeaderFooter::SIZE_BYTES as u64)).as_bytes();

    StoreBlocks::from(Bytes::from(header_length + freelist_length)).as_bytes()
        + directory_length
        + footer_length
}

// converge_header_info calculates the segment and bucket configuration,
// from which we can derive the offsets of the rest of the stripe header
// components. This needs to be called until the final header size converges
// (experimentally 3 is enough).
//
// In Traffic Server, this is done in Vol::init(), and vol_init_data_internal().
fn converge_header_info(
    mut segment_count: u64,
    mut buckets_per_segment: u64,
    block: &SpanBlock,
) -> (u64, u64) {
    // If we have not initialized the segment count, then the total header
    // is also uninitialized. Otherwise account accounaccount for 2 copies.
    let header_size: u64 = if segment_count == 0 {
        0
    } else {
        2 * directory_length(segment_count, buckets_per_segment)
    };

    // Content size is everything that remains after the header.
    let content_size: u64 = Into::<u64>::into(block.size_bytes()) - header_size;

    let total_entries: u64 = content_size / AVERAGE_OBJECT_SIZE;
    let total_buckets: u64 = total_entries / ENTRIES_PER_BUCKET;

    // Work out how many segment needed to cover all the buckets.
    segment_count = (total_buckets + MAX_BUCKETS_PER_SEGMENT - 1) / (MAX_BUCKETS_PER_SEGMENT);

    // Now reverse that into the number of buckets per segment.
    buckets_per_segment = (total_buckets + segment_count + 1) / segment_count;

    (segment_count, buckets_per_segment)
}
