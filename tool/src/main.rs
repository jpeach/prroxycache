use cachekit::trafficserver::Span;
use cachekit::trafficserver::VolHeaderFooter;
use clap::Parser;

#[derive(Parser, Debug)]
struct Args {
    /// Path to the cache file to inspect.
    path: std::path::PathBuf,
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

        let b = s.read_block(n as usize).unwrap();
        println!("{} block: {:?}", indent, b);
        println!("{} expecting VolHeader at offset {}", indent, b.offset());

        let mut volbuf = [0u8; VolHeaderFooter::SIZE_BYTES];
        let nbytes = s.read_at(&mut volbuf, b.offset());

        indent = "      ";
        let vh = nbytes.and_then(|_| VolHeaderFooter::from_bytes(&volbuf));
        println!("{} block: {:?}", indent, vh);
    }
}
