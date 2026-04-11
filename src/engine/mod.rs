pub mod parser;
pub mod scanner;

pub use parser::parse_file;
pub use scanner::{
    scan_directory, scan_paths, scan_paths_with_root, ScanResult, DEFAULT_MAX_FILE_SIZE,
};
