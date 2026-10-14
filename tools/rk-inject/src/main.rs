use clap::Parser;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use sys::{Process, WindowsProcess};

#[derive(Debug, Parser)]
struct Cli {
    #[arg(value_name = "DLL_PATH", help = "Path to the DLL to inject")]
    dll_path: PathBuf,
    #[arg(value_name = "PID", help = "Process ID to inject into")]
    pid: u32,
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let dll_path = std::fs::canonicalize(&cli.dll_path)?;
    let dll_path: Vec<u16> = dll_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let process = WindowsProcess::open(cli.pid)?;
    let load_library_w = process.get_remote_function("kernel32.dll", "LoadLibraryW")?;

    let dll_path_bytes = unsafe {
        std::slice::from_raw_parts(
            dll_path.as_ptr() as *const u8,
            dll_path.len() * std::mem::size_of::<u16>(),
        )
    };
    let allocated_memory = process.alloc_memory(dll_path_bytes.len())?;

    let result = (|| -> Result<usize, Box<dyn std::error::Error>> {
        let bytes_written = process.write_memory(allocated_memory, dll_path_bytes)?;
        if bytes_written != dll_path_bytes.len() {
            return Err(format!(
                "partial DLL path write: {bytes_written}/{} bytes",
                dll_path_bytes.len()
            )
            .into());
        }

        Ok(process.remote_call(load_library_w, &[allocated_memory])?)
    })();

    let _ = process.free_memory(allocated_memory);

    let module_handle = result?;
    if module_handle == 0 {
        return Err(format!("LoadLibraryA failed in target process {}", cli.pid).into());
    }

    println!(
        "DLL injected successfully into PID {} (module handle: 0x{module_handle:X})",
        cli.pid
    );
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
    }
}
