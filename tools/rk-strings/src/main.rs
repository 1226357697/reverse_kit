use clap::{Parser,ValueEnum};
use regex::Regex;
use std::collections::HashMap;
use std::fmt::Write;

#[derive(Debug, Clone, ValueEnum)]
enum OffsetFormat{
    None,
    Hex,
    Dec,
}

#[derive(Debug, Clone, ValueEnum)]
enum Encoding {
    Ascii,
    Utf16le,
    All,
}

struct DisplayFormatConfig{
    offset_format: OffsetFormat,
    with_entropy: bool,

}

#[derive(Parser, Debug)]

struct Args {
    #[arg(
        short,
        long,
        default_value_t = 6,
        help = "Minimum length of strings to display"
    )]
    min_len: usize,

    #[arg(
        short = 'r',
        long,
        value_name = "PATTERN",
        help = "Only output strings matching this regex",
        long_help = "Only output strings matching this regex.\n\nCommon patterns:\n  ^[0-9]+$        numbers only\n  https?://       URLs\n  \\.dll$          DLL names\n  [A-Za-z_][A-Za-z0-9_]*  identifiers"
    )]
    regex: Option<String>,

    #[arg(
        short = 'e',
        long = "max_entropy",
        value_name = "MAX",
        help = "Only output strings with entropy <= MAX",
        long_help = "Only output strings with entropy <= MAX.\n\nRaw Shannon entropy is usually around:\n  0.0      repeated chars\n  2.0-4.5  normal readable strings\n  4.5+     random-like strings\n\nFor short strings, entropy is unstable. Use with --min-len 8 or higher."
    )]
    max_entropy: Option<f64>,


    #[arg(
        long,
        value_enum,
        default_value_t = OffsetFormat::Hex,
        value_name = "FORMAT",
        help = "Offset display format"
    )]
    offset_format: OffsetFormat,

    #[arg(
        long,
        default_value_t = true,
        help = "Show Shannon entropy for each string"
    )]
    with_entropy: bool,

    #[arg(
        long,
        value_name = "OFFSET",
        help = "Start scanning at this file offset, accepts decimal or 0x-prefixed hex"
    )]
    start: Option<String>,

    #[arg(
        long,
        value_name = "OFFSET",
        help = "Stop scanning at this file offset, accepts decimal or 0x-prefixed hex"
    )]
    end: Option<String>,

    #[arg(
        long,
        default_value = "false",
        help = "Output results in JSON format"
    )]
    json: bool,

    #[arg(value_name = "FILE")]
    file_path: String,
}

struct StringItem {
    offset: usize,
    value: String,
}

fn is_printable_ascii(byte: u8) -> bool {
    byte >= 32 && byte <= 126
}

fn scan_ascii_strings(base_position: usize, data: &[u8], min_len: usize) -> Vec<StringItem> {
    let mut tmp_string: String = String::new();
    let mut results: Vec<StringItem> = Vec::new();
    let mut string_start: usize = 0;

    for (i, b) in data.iter().enumerate() {
        if is_printable_ascii(*b) {
            if tmp_string.is_empty() {
                string_start = i;
            }
            tmp_string.push(*b as char);
        } else {
            if tmp_string.len() > min_len {
                results.push(StringItem {
                    offset: base_position + string_start,
                    value: tmp_string.to_string(),
                });
            }
            tmp_string.clear();
        }
    }

    if tmp_string.len() > min_len {
        results.push(StringItem {
            offset: base_position + string_start,
            value: tmp_string.to_string(),
        });
    }
    results
}

fn calculate_entropy(s: &str) -> f64 {
    let mut counter: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *counter.entry(c).or_insert(0) += 1;
    }
    let len = s.len() as f64;
    let mut entropy = 0.0;
    for count in counter.values() {
        let p = *count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}


fn parse_offset(value:&str)->Result<usize, String> {
    if let Some(hex) = value.strip_prefix("0x").or_else(||value.strip_prefix("0X")) {
        usize::from_str_radix(hex, 16)
        .map_err(|_| format!("invalid hex offset: {value}"))
    } else {
        value.parse::<usize>()
        .map_err(|_| format!("invalid decimal offset: {value}"))
    }
}

fn format_display_line(item: &StringItem, cfg: &DisplayFormatConfig) -> String {
    let mut s = String::with_capacity(64);

    if matches!(cfg.offset_format, OffsetFormat::Hex | OffsetFormat::None) {
        write!(s, "Offset: 0x{:08X}", item.offset).unwrap();
    } else {
        write!(s, "Offset: {}", item.offset).unwrap();
    };

    if cfg.with_entropy {
        let entropy = calculate_entropy(&item.value);
        write!(s, ", Entropy: {:.2}", entropy).unwrap();
    }


    write!(s, ", String: {}", item.value).unwrap();
    s
}

fn main() {
    let args = Args::parse();
    if args.min_len == 0 {
        eprintln!("Error: Minimum length must be a positive integer");
        return;
    }

    let path = args.file_path;

    let Ok(file_data) = std::fs::read(path) else {
        eprintln!("Error: Failed to read file");
        return;
    };

    let min_len: usize = args.min_len;
    let regex: Option<Regex> = match args.regex {
        Some(pattern) => match Regex::new(&pattern) {
            Ok(re) => Some(re),
            Err(err) => {
                eprintln!("Error: Failed to compile regex: {}", err);
                return;
            }
        },
        None => None,
    };
    let max_entropy: Option<f64> = args.max_entropy;
    
    let start = match args.start {
        Some(s) => match parse_offset(s.as_str()) {
            Ok(offset) => offset,
            Err(_) => {
                eprintln!("Error: Invalid start offset");
                return;
            }
        },
        None => 0,
    };
    let end = match args.end {
        Some(s) => match parse_offset(s.as_str()) {
            Ok(offset) => offset,
            Err(_) => {
                eprintln!("Error: Invalid end offset");
                return;
            }
        },
        None => file_data.len(),
    };

    if end > file_data.len() {
        eprintln!("Error: End offset is out of bounds");
        return;
    }

    if start >= file_data.len() {
        eprintln!("Error: Start offset is out of bounds");
        return;
    }

    if start >= end {
        eprintln!("Error: Start offset must be less than end offset");
        return;
    }


    let scan_result = scan_ascii_strings(start, &file_data[start..end], min_len);
    let display_config = DisplayFormatConfig {
        offset_format: args.offset_format,
        with_entropy: args.with_entropy,
    };
    for item in scan_result {
        // 过滤正则
        if let Some(re) = &regex {
            if !re.is_match(&item.value) {
                continue;
            }
        }

        if let Some(max_entropy) = max_entropy {
            let ent = calculate_entropy(&item.value);
            if ent > max_entropy {
                continue;
            }
        }

        if args.json {
            let json_value = serde_json::json!({
                "offset": item.offset,
                "value": item.value,
                "entropy": calculate_entropy(&item.value)
            });
            println!("{}", json_value);
        } else {
            println!("{}", format_display_line(&item, &display_config));
        }
    }
}
