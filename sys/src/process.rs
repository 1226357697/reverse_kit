use std::io;

#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub name: String,
    pub path: Option<String>,
    pub base: usize,
    pub size: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryProtection {
    ReadOnly,
    ReadWrite,
    Execute,
    ReadExecute,
    ReadWriteExecute,
    NoAccess,
    Unknown,
}

pub struct MemoryRegion {
    pub base: usize,
    pub size: usize,
    pub protection: MemoryProtection,
}

pub trait Process {
    fn pid(&self) -> u32;

    fn name(&self) -> io::Result<String>;

    fn modules(&self) -> io::Result<Vec<ModuleInfo>>;

    fn read_memory(&self, addr: usize, buf: &mut [u8]) -> io::Result<usize>;

    fn write_memory(&self, addr: usize, buf: &[u8]) -> io::Result<usize>;

    fn memory_regions(&self) -> io::Result<Vec<MemoryRegion>>;
}
