
use crate::kernel::*;
use udbg_base::{*, ntdll::*};

use std::sync::Arc;
use std::ptr::*;
use std::time::Duration;
use winapi::um::winnt::{MEM_COMMIT, MEM_FREE, PAGE_READONLY};

#[derive(Deref)]
pub(crate) struct KrnlAdaptor {
    base: UDbgBase,
    #[deref]
    process: Process,
    kt: Arc<UDbgDriver>,
    symgr: Arc<dyn UDbgSymMgr>,
    util: &'static dyn UDbgUtil,
}

#[inline(always)]
pub fn wait_end<T: UDbgAdaptor>(this: Arc<T>) -> EventPumper {
    // use std::time::Duration;
    let wait_end = async move || {
        while this.base().status.get() != UDbgStatus::Ended {
            std::thread::sleep(Duration::from_millis(10));
        }
    };
    Box::pin(wait_end())
}

impl KrnlAdaptor {
    pub fn open(base: UDbgBase, pid: pid_t) -> UDbgResult<Arc<dyn UDbgAdaptor>> {
        base.pid.set(pid);
        if pid == 4 {
            NtKrnlAdaptor::new(base)
        } else {
            let opt = winapi::um::winnt::PROCESS_QUERY_INFORMATION;
            let p = Process::open(pid, Some(opt)).check_errstr("open process")?;
            Self::new(base, p)
        }
    }

    fn new(base: UDbgBase, p: Process) -> UDbgResult<Arc<dyn UDbgAdaptor>> {
        let result = Arc::new(Self {
            base, process: p,
            symgr: udbg_ui().new_symgr(),
            util: udbg_ui().get_util(),
            kt: Arc::new(open_driver(None)?),
        });
        Ok(result)
    }

    pub fn check_all_module(&self) {
        if let Ok(result) = self.kt.enum_module(self.base.pid.get()) {
            for m in result {
                self.symgr.check_load_module(self, m.base, m.size, m.path.as_ref(), null_mut());
            }
        }
    }

    // #[inline]
    // fn shared(&self) -> &mut SharedData { unsafe { transmute(self.shmem.get_ptr()) } }

    // #[inline]
    // pub fn context(&self) -> &mut CONTEXT { &mut self.shared().context }

    // #[inline]
    // fn exception_context(&self) -> Option<&mut CONTEXT> { Some(self.context()) }

    // #[inline]
    // fn exception_record(&self) -> &mut ExceptionRecord {
    //     unsafe { &mut self.shared().info.exception }
    // }

    // fn open_thread(&self, tid: tid_t) -> UDbgResult<Box<WinThread>> {
    //     self.debug.open_thread(tid)
    // }
}

impl ReadMemory for KrnlAdaptor {
    fn read_memory<'a>(&self, addr: usize, data: &'a mut [u8]) -> Option<&'a mut [u8]> {
        let r = self.kt.read_memory(self.base.pid.get(), addr, data);
        if r > 0 {
            Some(&mut data[..r])
        } else { None }
    }
}

impl WriteMemory for KrnlAdaptor {
    fn write_memory(&self, addr: usize, data: &[u8]) -> Option<usize> {
        Some(self.kt.write_virtual(self.base.pid.get(), addr, data))
    }
}

impl UDbgAdaptor for KrnlAdaptor {
    fn base(&self) -> &UDbgBase { &self.base }

    fn virtual_query(&self, address: usize) -> Option<MemoryPage> {
        self.process.virtual_query(address)
    }

    // fn get_reg(&self, reg: &str) -> UDbgResult<CpuReg> {
    //     // self.exception_context()
    //     //     .ok_or(UDbgError::DbgeeIsBusy)
    //     //     .and_then(|c| CommonDebugAdaptor::get_reg(c, reg, None))
    //     Err(UDbgError::NotSupport)
    // }

    fn detach(&self) -> UDbgResult<()> {
        self.base.status.set(UDbgStatus::Ended);
        Ok(())
    }

    fn kill(&self) -> UDbgResult<()> {
        self.base.status.set(UDbgStatus::Ended);
        self.process.terminate().check_errno("")?;
        Ok(())
    }

    fn loop_event(self: Arc<Self>, _state: UEventState) -> EventPumper {
        wait_end(self)
    }

    fn enum_module<'a>(&'a self) -> UDbgResult<Box<dyn Iterator<Item=Arc<dyn UDbgModule+'a>>+'a>> {
        self.check_all_module();
        Ok(self.symgr.enum_module())
    }

    fn symbol_manager(&self) -> Option<&dyn UDbgSymMgr> {
        Some(self.symgr.as_ref())
    }

    fn enum_thread<'a>(&'a self) -> UDbgResult<Box<dyn Iterator<Item=tid_t>+'a>> {
        Ok(Box::new(self.process.enum_thread().map(|e| e.tid())))
    }

    fn open_all_thread(&self) -> Vec<(tid_t, Box<dyn UDbgThread>)> {
        self.util.open_all_thread(&self.process, self.base.pid.get())
    }

    fn enum_memory<'a>(&'a self) -> Result<Box<dyn Iterator<Item = MemoryPage> + 'a>, UDbgError> {
        Ok(Box::new(self.process.enum_memory(0)))
    }

    fn get_memory_map(&self) -> Vec<UiMemory> {
        self.util.get_memory_map(&self.process, self as &dyn UDbgAdaptor)
    }

    fn enum_handle<'a>(&'a self) -> Result<Box<dyn Iterator<Item = UiHandle> + 'a>, UDbgError> {
        self.util.enum_process_handle(self.base.pid.get(), *self.process.handle)
    }
}

unsafe impl Send for KrnlAdaptor {}
unsafe impl Sync for KrnlAdaptor {}

pub(crate) struct NtKrnlAdaptor {
    base: UDbgBase,
    symgr: Arc<dyn UDbgSymMgr>,
    kt: Arc<UDbgDriver>,
}

impl NtKrnlAdaptor {
    fn new(mut base: UDbgBase) -> UDbgResult<Arc<dyn UDbgAdaptor>> {
        base.pid.set(4);
        base.image_path = "System".into();
        let mut result = Arc::new(Self {
            base, kt: Arc::new(open_driver(None)?),
            symgr: udbg_ui().new_symgr(),
        });
        if let Ok(_) = result.check_all_module() {}
        let image_base = result.get_module("ntoskrnl").map(|m| m.data().base).unwrap_or_default();
        Arc::get_mut(&mut result).unwrap().base.image_base = image_base;
        Ok(result)
    }

    pub fn check_all_module(&self) -> UDbgResult<()> {
        for m in system_module_list().map_err(|e| UDbgError::Code(e as usize))? {
            let path = normalize_path(ansi_to_unicode(&m.FullPathName, 0).to_utf8());
            self.symgr.check_load_module(self, m.ImageBase as usize, m.ImageSize as usize, path.as_ref(), null_mut());
        }
        Ok(())
    }
}

impl UDbgAdaptor for NtKrnlAdaptor {
    fn base(&self) -> &UDbgBase { &self.base }

    fn virtual_query(&self, address: usize) -> Option<MemoryPage> {
        Some(MemoryPage {
            base: address & !0xFFF,
            alloc_base: address & !0xFFF,
            size: 0x1000,
            type_: MEM_FREE,
            state: MEM_COMMIT,
            protect: PAGE_READONLY,
            alloc_protect: PAGE_READONLY,
        })
    }

    fn detach(&self) -> Result<(), UDbgError> {
        self.base.status.set(UDbgStatus::Ended);
        Ok(())
    }

    fn kill(&self) -> Result<(), UDbgError> {
        self.base.status.set(UDbgStatus::Ended);
        Ok(())
    }

    fn breakk(&self) -> Result<(), UDbgError> {
        // TODO:
        Err(UDbgError::NotSupport)
    }

    fn loop_event(self: Arc<Self>, _state: UEventState) -> EventPumper {
        wait_end(self)
    }

    fn symbol_manager(&self) -> Option<&dyn UDbgSymMgr> {
        Some(self.symgr.as_ref())
    }

    fn enum_module<'a>(&'a self) -> UDbgResult<Box<dyn Iterator<Item=Arc<dyn UDbgModule+'a>>+'a>> {
        self.check_all_module()?;
        Ok(self.symgr.enum_module())
    }

    fn enum_thread<'a>(&'a self) -> UDbgResult<Box<dyn Iterator<Item=tid_t>+'a>> {
        Ok(Box::new(enum_thread().filter_map(|t| if t.pid() == 4 { Some(t.tid()) } else { None })))
    }

    fn open_all_thread(&self) -> Vec<(tid_t, Box<dyn UDbgThread>)> {
        let mut result = vec![];
        if let Ok(infos) = system_process_information() {
            for p in infos.filter(|p| p.UniqueProcessId as usize == 4) {
                for t in SystemProcessInfo::threads(p).iter() {
                    let tid = t.ClientId.UniqueThread as u32;
                    result.push((tid, Box::new(KrnlThread {
                        data: ThreadData {tid, wow64: false, handle: unsafe { Handle::from_raw_handle(null_mut()) }},
                        si: *t,
                    }) as Box<dyn UDbgThread>));
                }
            }
        }
        result
    }

    fn enum_memory<'a>(&'a self) -> UDbgResult<Box<dyn Iterator<Item = MemoryPage> + 'a>> {
        Err(UDbgError::NotSupport)
    }

    fn get_memory_map(&self) -> Vec<UiMemory> {
        Vec::new()
    }
}

impl ReadMemory for NtKrnlAdaptor {
    fn read_memory<'a>(&self, addr: usize, data: &'a mut [u8]) -> Option<&'a mut [u8]> {
        let r = self.kt.read_kernel(addr, data);
        if r > 0 { Some(&mut data[..r]) } else { None }
    }
}

impl WriteMemory for NtKrnlAdaptor {
    fn write_memory(&self, addr: usize, data: &[u8]) -> Option<usize> {
        let r = self.kt.write_kernel(addr, data);
        if r > 0 { Some(r) } else { None }
    }
}

unsafe impl Send for NtKrnlAdaptor {}
unsafe impl Sync for NtKrnlAdaptor {}

#[derive(Deref)]
pub struct KrnlThread {
    #[deref]
    pub data: ThreadData,
    pub si: SYSTEM_THREAD_INFORMATION,
}

impl UDbgThread for KrnlThread {
    fn entry(&self) -> usize {
        self.si.StartAddress as _
    }

    fn priority(&self) -> Option<i32> {
        Some(self.si.Priority)
    }

    fn status(&self) -> Arc<str> {
        self.si.status().into()
    }
}

pub struct KrnlEngine;

impl UDbgEngine for KrnlEngine {
    fn open(&self, base: UDbgBase, pid: pid_t) -> UDbgResult<Arc<dyn UDbgAdaptor>> {
        Ok(KrnlAdaptor::open(base, pid)?)
    }

    fn attach(&self, base: UDbgBase, pid: pid_t) -> UDbgResult<Arc<dyn UDbgAdaptor>> {
        Ok(KrnlAdaptor::open(base, pid)?)
    }

    fn create(&self, _base: UDbgBase, _path: &str, _cwd: Option<&str>, _args: &[&str]) -> UDbgResult<Arc<dyn UDbgAdaptor>> {
        Err(UDbgError::NotSupport)
    }
}