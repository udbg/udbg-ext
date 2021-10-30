
use proto::*;
use std::{ptr, mem};
use std::ops::Deref;

use udbg_base::*;
use winapi::um::{fileapi::*, handleapi::*, winnt::*, ioapiset::*};

pub struct UDbgDriver {
    handle: Handle,
}

pub struct KResult<'a> {
    drv: Option<&'a UDbgDriver>,
    data: KData,
}

impl<'a> KResult<'a> {
    pub fn to_int(&self) -> Result<usize, String> {
        match self.data {
            KData::Int(i) => Ok(i),
            KData::Err(m) => Err(unsafe {
                String::from_utf8_unchecked(m.as_bytes().to_vec())
            }),
            KData::PackFailed => Err("<packfailed>".into()),
            _ => Err("<type>".into()),
        }
    }

    pub fn cast<T: Deserialize<'a>>(&'a self) -> Result<T, String> {
        match &self.data {
            KData::Pack(m) => corepack::from_bytes(m.as_bytes()).map_err(|e| format!("<decode> {:?}", e)),
            KData::Err(m) => Err(unsafe {
                String::from_utf8_unchecked(m.as_bytes().to_vec())
            }),
            KData::PackFailed => Err("<packfailed>".into()),
            _ => Err("<type>".into()),
        }
    }

    pub fn data(&self) -> &KData { &self.data }

    pub fn into_mem(mut self) -> Option<KMemory<'a>> {
        match self.data {
            KData::Pack(m) => {
                let r = Some(KMemory {
                    drv: self.drv, data: m
                });
                self.data = KData::Int(0); r
            },
            _ => None
        }
    }
}

impl Drop for KResult<'_> {
    fn drop(&mut self) {
        match &self.data {
            KData::Err(m) | KData::Pack(m) => {
                if let Some(d) = self.drv {
                    d.free(*m);
                }
            }
            _ => {}
        }
    }
}

pub struct KMemory<'a> {
    drv: Option<&'a UDbgDriver>,
    data: KMem,
}

impl<'a> KMemory<'a> {
    pub fn cast<T: Deserialize<'a>>(&'a self) -> Option<T> {
        corepack::from_bytes(self.data.as_bytes()).ok()
    }
}

impl Deref for KMemory<'_> {
    type Target = KMem;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl Drop for KMemory<'_> {
    fn drop(&mut self) {
        if let Some(d) = self.drv {
            d.free(self.data)
        }
    }
}

impl UDbgDriver {
    pub fn open(path: &str) -> Option<Self> {
        unsafe {
            let handle = CreateFileW(path.to_wide().as_ptr(), GENERIC_READ | GENERIC_WRITE, 0, ptr::null_mut(), OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, ptr::null_mut());
            if handle == INVALID_HANDLE_VALUE { None } else { Some(Self {handle: Handle::from_raw_handle(handle)})}
        }
    }

    #[inline(always)]
    pub fn exec(&self, data: DriverCmd) -> KResult {
        self.ctrl(IO_EXCHANGE_DATA, &data)
    }

    fn free(&self, m: KMem) { self.exec(DriverCmd::Free(m)); }

    fn ctrl<T>(&self, code: u32, input: &T) -> KResult {
        unsafe {
            let data: KData = mem::zeroed();
            let mut rlen = 0u32;
            assert!(DeviceIoControl(
                *self.handle, code, mem::transmute(input), mem::size_of_val(input) as u32,
                mem::transmute(&data), mem::size_of::<KData>() as u32, &mut rlen, ptr::null_mut()
            ) > 0 && rlen as usize == mem::size_of::<KData>());
            KResult {drv: self.into(), data}
        }
    }

    pub fn read_memory(&self, pid: u32, addr: usize, buf: &mut [u8]) -> usize {
        self.exec(DriverCmd::ReadVirtual(ReadWrite::read(pid, addr, buf))).to_int().unwrap_or(0)
    }

    pub fn read_kernel(&self, addr: usize, buf: &mut [u8]) -> usize {
        self.exec(DriverCmd::ReadWriteKernel(ReadWrite::read(0, addr, buf))).to_int().unwrap_or(0)
    }

    pub fn write_kernel(&self, addr: usize, buf: &[u8]) -> usize {
        self.exec(DriverCmd::ReadWriteKernel(ReadWrite::write(0, addr, buf))).to_int().unwrap_or(0)
    }

    pub fn write_virtual(&self, pid: u32, addr: usize, buf: &[u8]) -> usize {
        self.exec(DriverCmd::WriteVirtual(ReadWrite::write(pid, addr, buf))).to_int().unwrap_or(0)
    }

    pub fn enum_module(&self, pid: u32) -> Result<Vec<Module>, String> {
        self.exec(DriverCmd::ModuleList {pid}).cast()
    }
}

pub fn open_driver(path: Option<&str>) -> anyhow::Result<UDbgDriver> {
    if UDbgDriver::open(proto::DEVICE_PATH).is_none() {
        let path = path.map(|p| std::path::Path::new(p).to_path_buf())
                .unwrap_or_else(|| std::env::current_exe().unwrap().with_file_name("driver.dll"));
        udbg_base::sc::load_driver(&path, None, true)?;
    }
    Ok(UDbgDriver::open(proto::DEVICE_PATH).ok_or(anyhow::Error::msg("open driver"))?)
}