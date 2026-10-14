use crate::process::*;
use std::io;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Foundation::{WAIT_FAILED, WAIT_OBJECT_0};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};
use windows_sys::Win32::System::Threading::{
    CreateRemoteThread, GetExitCodeThread, INFINITE, LPTHREAD_START_ROUTINE, OpenProcess,
    PROCESS_ALL_ACCESS, WaitForSingleObject,
};

struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

fn wide_string(value: &[u16]) -> String {
    let len = value.iter().position(|&ch| ch == 0).unwrap_or(value.len());
    String::from_utf16_lossy(&value[..len])
}

pub struct WindowsProcess {
    pid: u32,
    handle: HandleGuard,
}

impl WindowsProcess {
    pub fn open(pid: u32) -> io::Result<Self> {
        unsafe {
            let handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
            if handle.is_null() {
                return Err(std::io::Error::last_os_error());
            }
            Ok(Self {
                pid,
                handle: HandleGuard(handle),
            })
        }
    }
}

impl Process for WindowsProcess {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn name(&self) -> std::io::Result<String> {
        todo!()
    }

    fn modules(&self) -> std::io::Result<Vec<ModuleInfo>> {
        let snapshot =
            unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid) };

        if snapshot == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }

        let _snapshot_guard = HandleGuard(snapshot);
        let mut entry = MODULEENTRY32W {
            dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };

        let mut modules = Vec::new();
        let mut ok = unsafe { Module32FirstW(snapshot, &mut entry) };

        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }

        while ok != 0 {
            let path = wide_string(&entry.szExePath);
            modules.push(ModuleInfo {
                name: wide_string(&entry.szModule),
                path: (!path.is_empty()).then_some(path),
                base: entry.modBaseAddr as usize,
                size: entry.modBaseSize as usize,
            });

            ok = unsafe { Module32NextW(snapshot, &mut entry) };
        }

        Ok(modules)
    }

    fn read_memory(&self, addr: usize, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut bytes_read = 0;
        unsafe {
            if ReadProcessMemory(
                self.handle.0,
                addr as *const _,
                buf.as_mut_ptr() as *mut _,
                buf.len(),
                &mut bytes_read,
            ) == 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(bytes_read)
    }

    fn write_memory(&self, addr: usize, buf: &[u8]) -> std::io::Result<usize> {
        let mut bytes_write = 0;
        unsafe {
            if WriteProcessMemory(
                self.handle.0,
                addr as *mut _,
                buf.as_ptr() as *const _,
                buf.len(),
                &mut bytes_write,
            ) == 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(bytes_write)
    }

    fn memory_regions(&self) -> std::io::Result<Vec<MemoryRegion>> {
        todo!()
    }

    fn alloc_memory(&self, size: usize) -> io::Result<usize> {
        let remote_mem = unsafe {
            VirtualAllocEx(
                self.handle.0,
                std::ptr::null_mut(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if remote_mem.is_null() {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(remote_mem as usize)
        }
    }

    fn free_memory(&self, addr: usize) -> io::Result<()> {
        let result = unsafe { VirtualFreeEx(self.handle.0, addr as *mut _, 0, MEM_RELEASE) };

        if result == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn get_remote_function(&self, module_name: &str, function_name: &str) -> io::Result<usize> {
        let module = self
            .modules()?
            .into_iter()
            .find(|module| {
                module.name.eq_ignore_ascii_case(module_name)
                    || module
                        .path
                        .as_deref()
                        .and_then(|path| std::path::Path::new(path).file_name())
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.eq_ignore_ascii_case(module_name))
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("module not found: {module_name}"),
                )
            })?;

        let path = module.path.as_deref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("module path is unavailable: {}", module.name),
            )
        })?;

        let image = std::fs::read(path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("failed to read module image {path}: {error}"),
            )
        })?;

        let pe = goblin::pe::PE::parse(&image).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse PE image {path}: {error}"),
            )
        })?;

        let export = pe
            .exports
            .iter()
            .find(|export| export.name == Some(function_name))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("export not found: {}!{}", module.name, function_name),
                )
            })?;

        if export.reexport.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "forwarded export is not a direct address: {}!{}",
                    module.name, function_name
                ),
            ));
        }

        module.base.checked_add(export.rva).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "remote address overflow for {}!{}",
                    module.name, function_name
                ),
            )
        })
    }

    fn remote_call(&self, func_addr: usize, args: &[usize]) -> io::Result<usize> {
        if args.len() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "CreateRemoteThread supports exactly one argument",
            ));
        }

        let start_routine: LPTHREAD_START_ROUTINE = Some(unsafe { std::mem::transmute(func_addr) });

        let thread = unsafe {
            CreateRemoteThread(
                self.handle.0,
                std::ptr::null(),
                0,
                start_routine,
                args[0] as *const _,
                0,
                std::ptr::null_mut(),
            )
        };

        if thread.is_null() {
            return Err(io::Error::last_os_error());
        }

        let thread_guard = HandleGuard(thread);
        let wait_result = unsafe { WaitForSingleObject(thread_guard.0, INFINITE) };
        if wait_result == WAIT_FAILED {
            return Err(io::Error::last_os_error());
        }
        if wait_result != WAIT_OBJECT_0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("remote thread wait failed: {wait_result}"),
            ));
        }

        let mut exit_code = 0u32;
        let result = unsafe { GetExitCodeThread(thread_guard.0, &mut exit_code) };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(exit_code as usize)
    }
}
