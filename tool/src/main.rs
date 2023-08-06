use cachekit::trafficserver::Span;
use clap::Parser;

#[derive(Parser, Debug)]
struct Args {
    /// Path to the cache file to inspect.
    path: std::path::PathBuf,
}

fn main() {
    let args = Args::parse();

    let s = Span::open(args.path.as_path()).unwrap();
    let h = s.read_header().unwrap();

    let cache_file = args.path.as_path().to_str().unwrap();
    let mut indent: &str;

    println!("{}", cache_file);

    indent = "  ";
    println!(
        "{} total size: {} bytes, {} cache blocks",
        indent,
        s.size_bytes(),
        s.size_blocks()
    );
    println!("{} header: {:?}", indent, h);

    indent = "    ";
    for n in 0..h.num_diskvol_blks {
        let b = s.read_block(n as usize);
        println!("{} block: {:?}", indent, b);
    }
}
