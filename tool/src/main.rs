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
    let h = s.read_header();

    println!("{} -> {:?}", args.path.as_path().to_str().unwrap(), h)
}
