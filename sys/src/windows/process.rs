use crate::process::*;
use std::io;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_VM_READ};

struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

pub struct WindowsProcess {
    pid: u32,
    handle: HandleGuard,
}

impl WindowsProcess {
    pub fn open(pid: u32) -> io::Result<Self> {
        unsafe {
            let handle = OpenProcess(PROCESS_VM_READ, 0, pid);
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
        todo!()
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
        todo!()
    }

    fn memory_regions(&self) -> std::io::Result<Vec<MemoryRegion>> {
        todo!()
    }
}
