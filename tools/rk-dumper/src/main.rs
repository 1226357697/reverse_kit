use clap::{Parser, Subcommand};
use sys::{Process, WindowsProcess};
use std::fs::File;
use std::io::Write;


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Subcommand)]
enum DumpMode {
    Memory{

        #[arg(value_parser = parse_hex_string)]
        pid:usize,

        #[arg(value_parser = parse_hex_string)]
        addr:usize,

        #[arg(value_parser = parse_hex_string)]
        len:usize
    },
    PE {
        #[arg(value_parser = parse_hex_string)]
        pid:usize,

        #[arg(value_parser = parse_hex_string)]
        addr:usize,

        #[arg(long, default_value = "false")]
        fix_iat: bool,
    },
}

#[derive(Parser, Debug)]
struct Cli {
    #[command(subcommand)]
    dumpmode: DumpMode,



    #[arg(value_name = "OUTPUT_PATH", default_value = "dump.bin")]
    output_path:String,
}

fn parse_hex_string(s: &str) -> Result<usize, std::num::ParseIntError> {
    if let Ok(addr) = s.strip_prefix("0x").ok_or_else(|| s.strip_prefix("0X")) {
        usize::from_str_radix(addr, 16)
    } else {
        usize::from_str_radix(s, 10)
    }
}


fn dump_pe(process: &WindowsProcess, base: usize, output_path: &str, fix_iat: bool) -> Result<(), Box<dyn std::error::Error>> {
    use goblin::pe::header::*;
    
    let mut header = [0;0x1000];
    let bytes_read = process.read_memory(base, &mut header)?;
    if bytes_read != 0x1000 {
        return Err("Failed to read complete PE header".into());
    }
    let pe_hdr = Header::parse(&header)?;

    let optional_header_offset = pe_hdr.dos_header.pe_pointer as usize
        + SIZEOF_PE_MAGIC
        + SIZEOF_COFF_HEADER;
    let mut offset = optional_header_offset + pe_hdr.coff_header.size_of_optional_header as usize;
    let sections = pe_hdr.coff_header.sections(&header, &mut offset)?;
    


    let mut f = File::create(output_path)?;
    f.write_all(header[..pe_hdr.optional_header.unwrap().windows_fields.size_of_headers as usize].as_ref())?;

    for s in &sections {
            
        let mut data: Vec<u8> = vec![0u8; s.size_of_raw_data as usize];
        let bytes_read = process.read_memory(base + s.virtual_address as usize, &mut data)?;
        if bytes_read != data.len() {
            eprintln!("Section {:?}: only {}/{} bytes read", s.name(), bytes_read, data.len());
            return  Err("uncomplete read".into());
        }

        println!("Section: {:?}", s.name());
        f.write_all(&data)?;
    }

    Ok(())
}


fn main() {
    let cli = Cli::parse();
    
    let output_path = cli.output_path;

    match cli.dumpmode {
        DumpMode::Memory { pid, addr, len } => {
            // Handle memory dump mode
            match WindowsProcess::open(pid as u32) {
                Ok(process) => {
                    let mut buf = vec![0u8; len];
                    // ... rest of the memory dump logic
                    match process.read_memory(addr, &mut buf) {
                        Ok(bytes_read) => {
                            // Handle successful memory read
                            buf.truncate(bytes_read);
                            let mut file = File::create(&output_path).expect(format!("Failed to create output file: {}", &output_path).as_str());
                            if let Err(e) = file.write_all(&buf) {
                                eprintln!("Failed to write to output file: {}", e);
                                return;
                            }
                            println!("Memory dump completed successfully.");
                        }
                        Err(e) => {
                            eprintln!("Failed to read memory from process with PID: {}, cause of {}", pid, e);
                            return;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to open process with PID: {}, cause of {}", pid, e);
                    return;
                }
            }

        }
        DumpMode::PE { pid, addr, fix_iat } => {
            // Handle PE dump mode
            match WindowsProcess::open(pid as u32) {
                Ok(process) => {
                    if let Err(e) = dump_pe(&process, addr, &output_path, fix_iat) {
                        eprintln!("Failed to dump PE file from process with PID: {}, cause of {}", pid, e);
                        return;
                    }
                }
                Err(e) => {
                    eprintln!("Failed to open process with PID: {}, cause of {}", pid, e);
                    return;
                }
            }
        }
    }
    
}
