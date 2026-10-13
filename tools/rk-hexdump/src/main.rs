use clap::{Parser, Subcommand};
use sys::{Process, WindowsProcess};

#[derive(Subcommand, Debug)]
enum Mode {
    File {
        #[arg(value_name = "FILE")]
        path: String,
        #[arg(long, value_parser = parse_offset, help = "File offset")]
        start: Option<usize>,
        #[arg(long, value_parser = parse_offset, help = "Number of bytes to dump")]
        len: Option<usize>,
        #[arg(long, default_value_t = 16, value_parser = parse_positive_usize)]
        cols: usize,
    },
    Mem {
        #[arg(long)]
        pid: u32,
        #[arg(long, value_parser = parse_offset, help = "Process virtual address")]
        start: usize,
        #[arg(long, value_parser = parse_offset, help = "Number of bytes to dump")]
        len: usize,
        #[arg(long, default_value_t = 16, value_parser = parse_positive_usize)]
        cols: usize,
    },
}

#[derive(Parser, Debug)]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

fn parse_offset(s: &str) -> Result<usize, String> {
    let s = s.trim();
    let (radix, digits) = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => (16, hex),
        None => (10, s),
    };
    usize::from_str_radix(digits, radix).map_err(|error| error.to_string())
}

fn parse_positive_usize(s: &str) -> Result<usize, String> {
    let value = s
        .parse::<usize>()
        .map_err(|error| format!("invalid positive integer: {error}"))?;

    if value == 0 {
        return Err("value must be greater than zero".to_string());
    }

    Ok(value)
}

fn main() {
    let args = Cli::parse();

    let (file_data, data_start, data_len, output_base, cols) = match args.mode {
        Mode::File {
            path,
            start,
            len,
            cols,
        } => {
            let file_data = match std::fs::read(&path) {
                Ok(data) => data,
                Err(error) => {
                    eprintln!("Error: failed to read file {path}: {error}");
                    return;
                }
            };

            let requested_start = start.unwrap_or(0);
            if requested_start > file_data.len() {
                eprintln!("Error: start is out of bounds");
                return;
            }

            let available_len = file_data.len() - requested_start;
            let data_len = len.unwrap_or(available_len);

            if data_len > available_len {
                eprintln!("Error: start + len is out of bounds");
                return;
            }

            (file_data, requested_start, data_len, requested_start, cols)
        }
        Mode::Mem {
            pid,
            start,
            len,
            cols,
        } => {
            if len == 0 {
                eprintln!("Error: len must be greater than zero");
                return;
            }

            let mut buffer = vec![0u8; len];
            let process = match WindowsProcess::open(pid) {
                Ok(process) => process,
                Err(error) => {
                    eprintln!("Error: failed to open process {pid}: {error}");
                    return;
                }
            };

            let bytes_read = match process.read_memory(start, &mut buffer) {
                Ok(bytes_read) => bytes_read,
                Err(error) => {
                    eprintln!("Error: failed to read memory at 0x{start:X}: {error}");
                    return;
                }
            };

            buffer.truncate(bytes_read);
            (buffer, 0, bytes_read, start, cols)
        }
    };

    if data_len == 0 {
        return;
    }

    let data = &file_data[data_start..data_start + data_len];

    for offset in (0..data_len).step_by(cols) {
        let width = cols.min(data_len - offset);
        let row = &data[offset..offset + width];

        let data_part = row
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ");

        let ascii_part = row
            .iter()
            .map(|&byte| {
                if (0x20..=0x7e).contains(&byte) {
                    byte as char
                } else {
                    '.'
                }
            })
            .collect::<String>();

        println!(
            "{:08x}: {:47} | {}",
            output_base + offset,
            data_part,
            ascii_part
        );
    }
}
