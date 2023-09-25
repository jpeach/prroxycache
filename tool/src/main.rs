use cachekit::trafficserver::disk;
use cachekit::trafficserver::{Span, Vol};
use clap::Parser;
use std::{fmt, io, mem, vec};

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

fn read_directory(span: &Span, dir_offset: u64, dir_count: u64) -> io::Result<Vec<disk::Dir>> {
    let mut bytes = vec![0u8; dir_count as usize * disk::Dir::SIZE_BYTES];

    let nread = span.read_at(&mut bytes, dir_offset)?;
    if nread < bytes.len() {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }

    let mut dirs: Vec<disk::Dir> = Vec::new();

    for i in 0..dir_count {
        let begin = disk::Dir::SIZE_BYTES * i as usize;
        let end = disk::Dir::SIZE_BYTES * (i + 1) as usize;
        let d = disk::Dir::from_bytes(&bytes[begin..end])?;

        dirs.push(d);
    }

    Ok(dirs)
}

fn walk_freelist<F>(directory: &Vec<disk::Dir>, start: u16, mut f: F) -> ()
where
    F: FnMut(&disk::Dir),
{
    let mut next = start;

    while next != 0 {
        f(&directory[next as usize]);
        next = directory[next as usize].next;
    }
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

        let f = read_freelist(&s, freelist, vol.segment_count()).unwrap();
        println!("freelist:");
        for i in 0..f.entries.len() {
            print!("{:>10}:{:>5}", i, f.entries[i]);
            if i % 4 == 0 {
                println!("");
            } else {
                print!("  ");
            }
        }

        let dir_entries =
            read_directory(&s, directory, vol.bucket_count() * disk::ENTRIES_PER_BUCKET).unwrap();

        println!("directory has {} entries", dir_entries.len());
        for i in 0..f.entries.len() {
            let mut free_entries = 0;
            walk_freelist(&dir_entries, f.entries[i], |_dir| free_entries += 1);
            println!("freelist[{}] has {} entries", i, free_entries);
        }

        println!(
            "{}",
            entry {
                offset: footer,
                data: Some(volbuf[0..4].try_into().unwrap()),
                label: Some(format!("{:?}", volfooter)),
            }
        );

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

        println!("{}", entry::from_offset(freelist, "freelist"));
        println!("{}", entry::from_offset(directory, "directory"));

        // XXX(jpeach) Experimentally, the second footer fails to decode
        // because it is all zero on disk. Maybe Traffic Server doesn't
        // always write the second footer?
        volfooter = s
            .read_at(&mut volbuf, footer)
            .and_then(|_| disk::VolHeaderFooter::from_bytes(&volbuf));

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
