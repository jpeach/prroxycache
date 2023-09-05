use cachekit::trafficserver::disk;
use cachekit::trafficserver::{Span, Vol};
use clap::Parser;
use std::{fmt, io, mem};

#[derive(Parser, Debug)]
struct Args {
    /// Path to the cache file to inspect.
    path: std::path::PathBuf,
}

struct entry {
    offset: u64,
    data: Option<[u8; 4]>,
    label: Option<String>,
}

impl entry {
    fn from_offset(offset: u64, label: &str) -> Self {
        entry {
            offset,
            data: None,
            label: Some(label.to_string()),
        }
    }
}

impl fmt::Display for entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.data {
            Some(data) => write!(
                f,
                "{:>10} {:02X}{:02X} {:02X}{:02X}",
                self.offset, data[0], data[1], data[2], data[3],
            ),
            None => write!(f, "{:>10} .... ....", self.offset),
        }?;

        match self.label.as_ref() {
            Some(label) => write!(f, "    {}", label),
            None => Ok(()),
        }
    }
}

fn read_freelist(span: &Span, offset: u64, entries: u64) -> io::Result<disk::Freelist> {
    let mut buf = vec![0u8; entries as usize * mem::size_of::<u16>()];

    let freelist = span
        .read_at(buf.as_mut_slice(), offset)
        .and_then(|_| disk::Freelist::from_bytes(buf.as_slice()));

    freelist
}

fn main() {
    let args = Args::parse();

    let cache_file = args.path.as_path().to_str().unwrap();
    let mut indent: &str;

    println!("{}", cache_file);

    let s = Span::open(args.path.as_path()).unwrap();
    let h = s.read_header().unwrap();

    indent = "  ";
    println!(
        "{} total size: {} bytes, {} cache blocks",
        indent,
        s.size_bytes(),
        s.size_blocks()
    );
    println!("{} header: {:?}", indent, h);

    for n in 0..h.num_diskvol_blks {
        indent = "    ";

        let block = s.read_block(n as usize).unwrap();
        println!("{} block: {:?}", indent, block);

        let vol = Vol::from_block(&block);

        println!(
            "{} vol has {} segment(s) with {} buckets, {} per segment",
            indent,
            vol.segment_count(),
            vol.bucket_count(),
            vol.bucket_count() / vol.segment_count()
        );

        println!("");

        // Get the offsets of the first header components.
        let (mut header, mut freelist, mut directory, mut footer) = vol.first_header_offsets();

        let mut volbuf = [0u8; disk::VolHeaderFooter::SIZE_BYTES];
        let mut volheader = s
            .read_at(&mut volbuf, header)
            .and_then(|_| disk::VolHeaderFooter::from_bytes(&volbuf));

        println!(
            "{}",
            entry {
                offset: header,
                data: Some(volbuf[0..4].try_into().unwrap()),
                label: Some(format!("{:?}", volheader)),
            },
        );

        let mut volfooter = s
            .read_at(&mut volbuf, footer)
            .and_then(|_| disk::VolHeaderFooter::from_bytes(&volbuf));

        println!("{}", entry::from_offset(freelist, "freelist"));
        println!("{}", entry::from_offset(directory, "directory"));

        println!(
            "{}",
            entry {
                offset: footer,
                data: Some(volbuf[0..4].try_into().unwrap()),
                label: Some(format!("{:?}", volfooter)),
            }
        );

        let f = read_freelist(&s, freelist, vol.segment_count());
        if f.is_ok() {
            let f = f.unwrap();
            println!("freelist:");
            for i in 0..f.entries.len() {
                print!("{:>10}:{:>5}", i, f.entries[i]);
                if i % 4 == 0 {
                    println!("");
                } else {
                    print!("  ");
                }
            }
        }

        // Get the offsets of the first header components.
        (header, freelist, directory, footer) = vol.second_header_offsets();

        volheader = s
            .read_at(&mut volbuf, header)
            .and_then(|_| disk::VolHeaderFooter::from_bytes(&volbuf));

        println!(
            "{}",
            entry {
                offset: header,
                data: Some(volbuf[0..4].try_into().unwrap()),
                label: Some(format!("{:?}", volheader)),
            },
        );

        // XXX(jpeach) Experimentally, the second footer fails to decode
        // because it is all zero on disk. Maybe Traffic Server doesn't
        // always write the second footer?
        volfooter = s
            .read_at(&mut volbuf, footer)
            .and_then(|_| disk::VolHeaderFooter::from_bytes(&volbuf));

        println!("{}", entry::from_offset(freelist, "freelist"));
        println!("{}", entry::from_offset(directory, "directory"));

        println!(
            "{}",
            entry {
                offset: footer,
                data: Some(volbuf[0..4].try_into().unwrap()),
                label: Some(format!("{:?}", volfooter)),
            }
        );

        println!(
            "{}",
            entry::from_offset(vol.content_offset(), "start of content")
        );
    }
}
