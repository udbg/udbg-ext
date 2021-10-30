#![allow(improper_ctypes)]
#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

pub mod ffi;

use std::{cell::Cell, mem, ptr::{self, null_mut}};
use std::ffi::*;
use std::sync::Arc;
use std::sync::RwLock;
use std::os::raw::c_char;
use std::collections::HashMap;

use c_str_macro::*;
use ffi::*;
use udbg_base::{*, util::*, regs::*};
use winapi::{shared::minwindef::*, um::{libloaderapi::*, winnt::*, winbase::*}};

const S_OK: HRESULT = 0;
const S_FALSE: HRESULT = 1;

trait HResult {
    fn check_hresult(&self) -> Result<(), HRESULT>;
    fn check_uresult(&self) -> UDbgResult<()> {
        self.check_hresult().map_err(hresult_errcode)
    }
}

#[inline]
fn hresult_errcode(r: HRESULT) -> UDbgError {
    UDbgError::Code(r as u32 as usize)
}

pub unsafe fn mutable<T: Sized>(t: &T) -> &mut T {
    use core::mem::transmute;
    transmute(transmute::<_, usize>(t))
}

impl HResult for HRESULT {
    #[inline]
    fn check_hresult(&self) -> Result<(), HRESULT> {
        if *self == S_OK { Ok(()) } else { Err(*self) }
    }
}

impl IDbgBp {
    pub fn id(&self) -> Result<BpID, HRESULT> {
        let mut result = 0;
        (self.GetId)(self, &mut result).check_hresult()?;
        Ok(result as BpID)
    }

    pub fn flags(&self) -> Result<ULONG, HRESULT> {
        let mut result = 0;
        (self.GetFlags)(self, &mut result).check_hresult()?;
        Ok(result)
    }

    pub fn passcount(&self) -> Result<ULONG, HRESULT> {
        let mut result = 0;
        (self.GetPassCount)(self, &mut result).check_hresult()?;
        Ok(result)
    }

    pub fn match_tid(&self) -> Result<ULONG, HRESULT> {
        let mut result = 0;
        (self.GetMatchThreadId)(self, &mut result).check_hresult()?;
        Ok(result)
    }

    pub fn set_match_tid(&self, tid: u32) -> Result<(), HRESULT> {
        (self.SetMatchThreadId)(self, tid).check_hresult()?;
        Ok(())
    }

    pub fn set_offset(&self, offset: u64) {
        (self.SetOffset)(self, offset);
    }

    #[inline]
    pub fn set_flags(&self, flags: u32) -> Result<(), HRESULT> {
        (self.SetFlags)(self, flags).check_hresult()
    }

    #[inline]
    pub fn add_flags(&self, flags: u32) -> Result<(), HRESULT> {
        (self.AddFlags)(self, flags).check_hresult()
    }

    #[inline]
    pub fn remove_flags(&self, flags: u32) -> Result<(), HRESULT> {
        (self.RemoveFlags)(self, flags).check_hresult()
    }

    pub fn set_data_params(&self, size: u32, params: u32) {
        (self.SetDataParameters)(self, size, params);
    }

    pub fn set_enable(&self, enable: bool) -> Result<(), HRESULT> {
        if enable {
            self.add_flags(DEBUG_BREAKPOINT_ENABLED)
        } else {
            self.remove_flags(DEBUG_BREAKPOINT_ENABLED)
        }
    }
}

#[derive(Deref, Copy, Clone)]
struct IDbgBpWrapper(
    #[deref]
    &'static IDbgBp,
    &'static DbgControl,
);

impl UDbgBreakpoint for IDbgBpWrapper {
    fn get_id(&self) -> BpID {
        self.id().map(|id| id as BpID).unwrap_or(0)
    }
    fn address(&self) -> usize {
        let mut address = 0;
        (self.GetOffset)(self, &mut address);
        address as usize
    }
    fn enabled(&self) -> bool {
        self.flags().unwrap_or_default() & DEBUG_BREAKPOINT_ENABLED > 0
    }
    fn get_type(&self) -> BpType {
        // TODO:
        BpType::Soft
    }
    /// count of this breakpoint hitted
    fn hit_count(&self) -> usize {
        self.passcount().map(|c| c as usize).unwrap_or_default()
    }
    /// set count of the to be used,
    /// when hit_count() > this count, bp will be delete
    fn set_count(&self, count: usize) {}
    /// set the which can hit the bp. if tid == 0, all thread used
    fn set_hit_thread(&self, tid: tid_t) {
        // TODO: Engine TID
        (self.SetMatchThreadId)(self, tid);
    }
    /// current tid setted by set_hit_thread()
    fn hit_tid(&self) -> tid_t {
        self.match_tid().unwrap_or_default()
    }
    /// original bytes written by software breakpoint
    fn origin_bytes<'a>(&'a self) -> Option<&'a [u8]> {
        None
    }

    fn enable(&self, enable: bool) -> UDbgResult<()> {
        self.0.set_enable(enable).map_err(hresult_errcode)
    }

    fn remove(&self) -> UDbgResult<()> {
        (self.1.RemoveBreakpoint)(self.1, self.0).check_uresult()
    }
}

impl DbgControl {
    pub fn add_bp(&self, ty: u32) -> Result<&'static IDbgBp, HRESULT> {
        let mut result = ptr::null_mut();
        const DEBUG_ANY_ID: u32 = 0xffffffff;
        (self.AddBreakpoint)(self, ty, DEBUG_ANY_ID, &mut result).check_hresult()?;
        unsafe { Ok(mem::transmute(result)) }
    }

    #[allow(unused_must_use)]
    pub fn remove_bp(&self, id: BpID) {
        self.get_bp_by_id(id).map(|bp| (self.RemoveBreakpoint)(self, bp));
    }

    pub fn get_bp_by_index(&self, index: usize) -> Result<&'static IDbgBp, HRESULT> {
        let mut result = core::ptr::null_mut();
        (self.GetBreakpointByIndex)(self, index as u32, &mut result).check_hresult()?;
        unsafe { Ok(mem::transmute(result)) }
    }

    pub fn get_bp_by_id(&self, id: BpID) -> Result<&'static IDbgBp, HRESULT> {
        let mut result = core::ptr::null_mut();
        (self.GetBreakpointById)(self, id as ULONG, &mut result).check_hresult()?;
        unsafe { Ok(mem::transmute(result)) }
    }

    pub fn bp_list(&self) -> Vec<&'static IDbgBp> {
        let mut result = vec![];
        for i in 0..10000 {
            match self.get_bp_by_index(i) {
                Ok(r) => result.push(r),
                Err(_) => break,
            }
        }
        result
    }

    pub fn wait_event(&self, flags: u32, timeout: isize) -> HRESULT {
        (self.WaitForEvent)(self, flags, timeout)
    }

    pub fn set_execute_status(&self, status: u32) -> HRESULT {
        (self.SetExecutionStatus)(self, status)
    }

    pub fn execute(&self, cmd: &str) -> HRESULT {
        (self.ExecuteWide)(self, 0, cmd.to_unicode_with_null().as_ptr(), 0)
    }
}

impl DbgSyms {
    pub fn enum_symbol<'a>(&'a self, pat: &str) -> UDbgResult<impl Iterator<Item=(String, u64)>+'a> {
        let pat = pat.to_unicode_with_null();
        let mut handle = 0;
        (self.StartSymbolMatchWide)(self, pat.as_ptr(), &mut handle).check_hresult().map_err(hresult_errcode)?;

        struct SymHandle<'a>(&'a DbgSyms, u64);
        impl<'a> Drop for SymHandle<'a> {
            fn drop(&mut self) {
                (self.0.EndSymbolMatch)(self.0, self.1);
            }
        }
        let h = SymHandle(self, handle);
        Ok(std::iter::from_fn(move || {
            // let handle = h.handle;
            let mut buf = [0; 1000];
            let mut offset = 0;
            if (h.0.GetNextSymbolMatchWide)(h.0, h.1, buf.as_mut_ptr(), buf.len() as u32, None, Some(&mut offset)) == 0 {
                Some((buf.to_utf8(), offset))
            } else { None }
        }))
    }

    pub fn get_module_parameters(&self, count: u32, bases: &[u64], params: &mut [DEBUG_MODULE_PARAMETERS]) -> Result<(), i32> {
        (self.GetModuleParameters)(self, count, bases.as_ptr(), bases.len() as u32, params.as_mut_ptr()).check_hresult()
    }

    pub fn get_module_params(&self, base: u64) -> Result<DEBUG_MODULE_PARAMETERS, i32> {
        unsafe {
            let mut buf = [mem::zeroed(); 1];
            self.get_module_parameters(1, &[base], &mut buf)?;
            Ok(buf[0])
        }
    }

    pub fn get_module_name_string(&self, which: u32, base: u64) -> Result<String, i32> {
        let mut buf = [0; 500];
        (self.GetModuleNameStringWide)(
            self, which, DEBUG_ANY_ID, base, buf.as_mut_ptr(), buf.len() as u32, null_mut()
        ).check_hresult()?;
        Ok(buf.to_utf8())
    }

    pub fn find_module(&self, a: u64) -> Result<(u32, u64), i32> {
        let mut i = 0;
        let mut base = 0;
        (self.GetModuleByOffset)(self, a, 0, &mut i, &mut base).check_hresult()?;
        Ok((i, base))
    }

    pub fn get_module(&self, name: PCWSTR) -> Result<(u32, u64), i32> {
        let mut i = 0;
        let mut base = 0;
        (self.GetModuleByModuleNameWide)(self, name, 0, &mut i, &mut base).check_hresult()?;
        Ok((i, base))
    }
}

impl DbgSysobj {
    pub fn get_cur_systid(&self) -> u32 {
        let mut result = 0;
        (self.GetCurrentThreadSystemId)(self, &mut result);
        result
    }

    pub fn get_cur_syspid(&self) -> u32 {
        let mut result = 0;
        (self.GetCurrentProcessSystemId)(self, &mut result);
        result
    }

    pub fn get_process(&self) -> HANDLE {
        let mut result = 0;
        (self.GetCurrentProcessHandle)(self, &mut result);
        result as HANDLE
    }

    pub fn get_peb(&self) -> u64 {
        let mut result = 0;
        (self.GetCurrentProcessPeb)(self, &mut result);
        result
    }
}

#[repr(C)]
pub struct WinDbg {
     pub client: &'static DbgClient,
     pub ctrl: &'static DbgControl,
     pub spaces: &'static DbgSpaces,
     pub regs: &'static DbgRegs,
     pub syms: &'static DbgSyms,
     pub sysobj: &'static DbgSysobj,
     pub adv: &'static DbgAdv,
}

impl WinDbg {
    pub fn module_from_base(&self, base: u64) -> Option<WDbgModule> {
        let info = self.syms.get_module_params(base).ok()?;
        self.new_module(&info).into()
    }

    pub fn new_module(&self, info: &DEBUG_MODULE_PARAMETERS) -> WDbgModule {
        unsafe {
            let name = self.syms.get_module_name_string(DEBUG_MODNAME_MODULE, info.Base).unwrap_or_default();
            let path = self.syms.get_module_name_string(DEBUG_MODNAME_IMAGE, info.Base).unwrap_or_default();
            let mut h = mem::zeroed();
            (self.spaces.ReadImageNtHeaders)(self.spaces, info.Base, &mut h);
            WDbgModule {
                syms: self.syms,
                param: *info,
                data: sym::ModuleData {
                    base: info.Base as usize,
                    size: info.Size as usize,
                    name: name.into(),
                    path: path.into(),
                    arch: pe::machine_to_arch(h.FileHeader.Machine),
                    entry: h.OptionalHeader.AddressOfEntryPoint as usize,
                    user_module: Cell::new(false),
                }
            }
        }
    }
}

impl UDbgSymMgr for WinDbg {
    fn enum_module<'a>(&'a self) -> Box<dyn Iterator<Item=Arc<dyn UDbgModule+'a>>+'a> {
        unsafe {
            let c = wdbg_module_count(self.syms);
            let mut buf = Vec::with_capacity(c);
            buf.resize(buf.capacity(), mem::zeroed());
            wdbg_module_infos(self.syms, buf.as_mut_ptr(), 0, buf.len());
            let this = self.syms;
            let iter = buf.into_iter()
                .filter(|p| p.Flags & DEBUG_MODULE_UNLOADED == 0)
                .map(move |p| Arc::new(self.new_module(&p)) as Arc<dyn UDbgModule>);
            Box::new(iter)
        }
    }
    fn remove(&self, address: usize) {}
    fn check_load_module(&self, read: &dyn ReadMemory, base: usize, size: usize, path: &str, file: HANDLE) -> bool {
        false
    }
    fn enum_symbol<'a>(&'a self, pat: Option<&str>) -> UDbgResult<Box<dyn Iterator<Item=sym::Symbol>+'a>> {
        Ok(Box::new(
            self.syms.enum_symbol(pat.unwrap_or_default())?.map(|(name, a)| {
                sym::Symbol {
                    offset: a as u32,
                    len: sym::SYM_NOLEN,
                    type_id: 0,
                    flags: 0,
                    name: name.into(),
                }
            })
        ))
    }
    fn find_module(&self, module: usize) -> Option<Arc<dyn UDbgModule>> {
        let base = self.syms.find_module(module as u64).ok()?;
        Some(Arc::new(self.module_from_base(base.1)?))
    }
    fn get_module(&self, module: &str) -> Option<Arc<dyn UDbgModule>> {
        let base = self.syms.get_module(module.to_wide().as_ptr()).ok()?;
        Some(Arc::new(self.module_from_base(base.1)?))
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum WDbgType {
    Normal,
    Dump,
    Kernel,
}

#[derive(Deref)]
pub struct WDbgAdaptor {
    base: UDbgBase,
    #[deref]
    wdbg: WinDbg,
    regs: RwLock<HashMap<Box<str>, usize>>,
    event: Option<UEvent>,
    context: CONTEXT,
    ty: WDbgType,
    paused: Cell<bool>,
    bp: RwLock<(HashMap<u32, usize>, HashMap<usize, IDbgBpWrapper>)>,
}

unsafe impl Send for WDbgAdaptor {}
unsafe impl Sync for WDbgAdaptor {}

extern "C" {
    fn wdbg_new(hmod: HMODULE, d: *mut WinDbg) -> usize;
    fn wdbg_init_callback(d: *const WinDbg, ui: *const WDbgAdaptor);
    fn wdbg_query_virtual(this: &DbgSpaces, address: usize, info: *mut MEMORY_BASIC_INFORMATION64) -> bool;
    fn wdbg_attach_process(this: &DbgClient, pid: usize) -> usize;
    fn wdbg_get_offset(this: &DbgSyms, name: *const u16) -> usize;
    fn wdbg_evaluate(this: *mut DbgControl, expr: *const u16) -> usize;

    fn wdbg_current_process(this: &DbgSysobj) -> usize;

    fn wdbg_get_near_name(this: &DbgSyms, a: usize, max: usize, name: *mut c_char, size: usize, disp: *mut u64) -> usize;
    fn wdbg_module_count(this: &DbgSyms) -> usize;
    fn wdbg_module_names(this: &DbgSyms, base: usize, name: *mut u16, path: *mut u16);
    fn wdbg_module_infos(this: &DbgSyms, infos: *mut DEBUG_MODULE_PARAMETERS, i: usize, count: usize) -> bool;

    fn wdbg_wait_event(this: *mut DbgControl) -> usize;
    fn wdbg_set_status(this: *mut DbgControl, status: usize);
    fn wdbg_get_reg_name(this: *mut DbgRegs, i: usize, name: *mut c_char, size: usize) -> isize;
    fn wdbg_get_reg(this: *mut DbgRegs, i: usize, val: &mut usize) -> usize;
    fn wdbg_set_reg(this: *mut DbgRegs, i: usize, val: usize) -> usize;

    fn wdbg_get_registers(this: &DbgAdv, context: *mut CONTEXT) -> usize;
}

#[no_mangle]
extern "C" fn udbg_output(_: &WDbgAdaptor, mask: u32, s: *const u16) {
    udbg_ui().logc(0, &to_string(s));
}

const DEBUG_STATUS_NO_CHANGE: u32             = 0;
const DEBUG_STATUS_GO: u32                    = 1;
const DEBUG_STATUS_GO_HANDLED: u32            = 2;
const DEBUG_STATUS_GO_NOT_HANDLED: u32        = 3;
const DEBUG_STATUS_STEP_OVER: u32             = 4;
const DEBUG_STATUS_STEP_INTO: u32             = 5;
const DEBUG_STATUS_BREAK: u32                 = 6;
const DEBUG_STATUS_NO_DEBUGGEE: u32           = 7;
const DEBUG_STATUS_STEP_BRANCH: u32           = 8;
const DEBUG_STATUS_IGNORE_EVENT: u32          = 9;
const DEBUG_STATUS_RESTART_REQUESTED: u32     = 10;
const DEBUG_STATUS_REVERSE_GO: u32            = 11;
const DEBUG_STATUS_REVERSE_STEP_BRANCH: u32   = 12;
const DEBUG_STATUS_REVERSE_STEP_OVER: u32     = 13;
const DEBUG_STATUS_REVERSE_STEP_INTO: u32     = 14;
const DEBUG_STATUS_OUT_OF_SYNC: u32           = 15;
const DEBUG_STATUS_WAIT_INPUT: u32            = 16;
const DEBUG_STATUS_TIMEOUT: u32               = 17;

const DEBUG_END_PASSIVE: u32 =          0x00000000;
const DEBUG_END_ACTIVE_TERMINATE: u32 = 0x00000001;
const DEBUG_END_ACTIVE_DETACH: u32 =    0x00000002;
const DEBUG_END_REENTRANT: u32 =        0x00000003;
const DEBUG_END_DISCONNECT: u32 =       0x00000004;

fn reply_to_status(r: UserReply) -> u32 {
    match r {
        // UserReply::Run(false) => DEBUG_STATUS_GO,
        UserReply::Run(true) => DEBUG_STATUS_GO_HANDLED,
        UserReply::StepIn => DEBUG_STATUS_STEP_INTO,
        UserReply::StepOut => DEBUG_STATUS_STEP_OVER,
        UserReply::Native(status) => status as u32,
        _ => DEBUG_STATUS_GO_NOT_HANDLED,
    }
}

#[no_mangle]
unsafe extern "C" fn udbg_on_exception(this: &mut WDbgAdaptor, first: bool, code: u32) -> u32 {
    // reply_to_status(ui.base.on_exception(first, code))
    this.event = Some(UEvent::Exception {first, code});
    DEBUG_STATUS_BREAK
}

#[no_mangle]
extern "C" fn udbg_on_breakpoint(this: &mut WDbgAdaptor, bp: &'static IDbgBp) -> u32 {
    this.event = Some(UEvent::Bp(Arc::new(IDbgBpWrapper(bp, this.ctrl))));
    DEBUG_STATUS_BREAK
}

#[no_mangle]
extern "C" fn udbg_on_engine_state(this: &mut WDbgAdaptor, flags: u32, status: u64) -> u32 {
    udbg_ui().log(format!("[engine state] {} {}", flags, status));
    match flags {
        DEBUG_CES_EXECUTION_STATUS => {
            if this.paused.get() && status as u32 != DEBUG_STATUS_BREAK {
                udbg_ui().user_reply(UserReply::Native(status as usize));
            }
        }
        DEBUG_CES_BREAKPOINTS => {
            let id = status as u32;
            let bp = this.ctrl.get_bp_by_id(status as BpID);
            let mut map = this.bp.write().unwrap();
            if map.0.get(&id).is_some() {
                if bp.is_err() { map.0.remove(&id).map(|a| map.1.remove(&a)); }
            } else {
                if let Ok(bp) = bp {
                    let bp = IDbgBpWrapper(bp, this.wdbg.ctrl);
                    let a = bp.address();
                    if a > 0 {
                        map.0.insert(id, a);
                        map.1.insert(a, bp);
                    }
                }
            }
        }
        _ => {}
    };
    DEBUG_STATUS_GO_NOT_HANDLED
}

fn to_string(p: *const u16) -> String {
    if p.is_null() { return "".into(); }
    let mut len = 0;

    unsafe {
        while *p.offset(len) != 0 { len += 1; }
        core::slice::from_raw_parts(p, len as usize).to_utf8()
    }
}

#[no_mangle]
unsafe extern "C" fn udbg_on_load_module(this: &mut WDbgAdaptor, base: usize, size: usize, name: *const u16, path: *const u16) -> u32 {
    if let Some(m) = this.find_module(base).or_else(|| {
        Some(Arc::new(this.module_from_base(base as u64)?))
    }) {
        this.event = Some(UEvent::ModuleLoad(m));
        DEBUG_STATUS_BREAK
    } else {
        udbg_ui().warn(format!("module load: {} @{:x} not found", to_string(name), base));
        DEBUG_STATUS_GO_NOT_HANDLED
    }
}

#[no_mangle]
unsafe extern "C" fn udbg_on_unload_module(this: &mut WDbgAdaptor, name: *const u16, base: usize) -> u32 {
    if let Some(m) = this.find_module(base).or_else(|| {
        Some(Arc::new(this.module_from_base(base as u64)?))
    }) {
        this.event = Some(UEvent::ModuleUnload(m));
        DEBUG_STATUS_BREAK
    } else {
        udbg_ui().warn(format!("module unload: {} @{:x} not found", to_string(name), base));
        DEBUG_STATUS_GO_NOT_HANDLED
    }
}

#[no_mangle]
extern "C" fn udbg_on_thread_exit(this: &mut WDbgAdaptor, code: u32) -> u32 {
    this.event = Some(UEvent::ThreadExit(code));
    DEBUG_STATUS_BREAK
}

#[no_mangle]
extern "C" fn udbg_on_thread_create(this: &mut WDbgAdaptor, handle: HANDLE, data: u64, start: u64) -> u32 {
    this.event = Some(UEvent::ThreadCreate);
    DEBUG_STATUS_BREAK
}

#[no_mangle]
extern "C" fn udbg_on_create_process(this: &mut WDbgAdaptor,
    ImageFileHandle: u64,
    Handle: u64,
    BaseOffset: u64,
    ModuleSize: ULONG,
    ModuleName: PCWSTR,
    ImageName: PCWSTR,
    CheckSum: ULONG,
    TimeDateStamp: ULONG,
    InitialThreadHandle: u64,
    ThreadDataOffset: u64,
    StartOffse: u64
) -> u32 {
    this.event = Some(UEvent::ProcessCreate);
    DEBUG_STATUS_BREAK
}

#[no_mangle]
extern "C" fn udbg_on_process_exit(this: &mut WDbgAdaptor, code: u32) -> u32 {
    this.event = Some(UEvent::ProcessExit(code));
    DEBUG_STATUS_BREAK
}

impl WDbgAdaptor {
    fn new() -> UDbgResult<WinDbg> {
        unsafe {
            let hmod = LoadLibraryA(c_str!("dbgeng.dll").as_ptr());
            if hmod.is_null() {
                return Err(UDbgError::Text("dbgeng.dll not found".into()));
            }
            #[allow(invalid_value)]
            let mut obj: WinDbg = mem::MaybeUninit::zeroed().assume_init();
            wdbg_new(hmod, &mut obj); Ok(obj)
        }
    }

    fn init_callback(base: UDbgBase, wdbg: WinDbg, ty: WDbgType) -> UDbgResult<Arc<Self>> {
        unsafe {
            base.pid.set(wdbg_current_process(wdbg.sysobj) as pid_t);
            let r = Arc::new(Self {
                event: None, base, wdbg, ty,
                paused: false.into(),
                regs: HashMap::new().into(),
                context: mem::zeroed(),
                bp: Default::default(),
            });
            wdbg_init_callback(&r.wdbg, r.as_ref());
            Ok(r)
        }
    }

    pub fn create(mut base: UDbgBase, path: &str, cwd: Option<&str>, args: Vec<&str>) -> UDbgResult<Arc<Self>> {
        let wdbg = Self::new()?;

        let mut ty = WDbgType::Normal;
        let hresult = if path.ends_with(".dmp") || path.ends_with(".DMP") {
            ty = WDbgType::Dump;
            base.status.set(UDbgStatus::Opened);
            (wdbg.client.OpenDumpFileWide)(wdbg.client, path.to_wide().as_ptr(), ptr::null_mut())
        } else if path.starts_with("com:") {
            ty = WDbgType::Kernel;
            const DEBUG_ATTACH_KERNEL_CONNECTION: u32 = 0x00000000;
            const DEBUG_ATTACH_LOCAL_KERNEL: u32 =      0x00000001;
            const DEBUG_ATTACH_EXDI_DRIVER: u32 =       0x00000002;
            const DEBUG_ATTACH_INSTALL_DRIVER: u32 =    0x00000004;
            (wdbg.client.AttachKernelWide)(wdbg.client, DEBUG_ATTACH_KERNEL_CONNECTION, path.to_wide().as_ptr())
        } else {
            let mut args = args.into_iter().map(ToString::to_string).collect::<Vec<_>>();
            let mut path = path.to_string();
            if path.find(|c: char| c.is_whitespace()).is_some() {
                path = format!("\"{}\"", path);
            }
            args.insert(0, path);
            let cmdline = args.join(" ");
            (wdbg.client.CreateProcessWide)(wdbg.client, 0, cmdline.to_wide().as_ptr(), CREATE_NEW_CONSOLE | DEBUG_PROCESS)
        };
        hresult.check_hresult().map_err(hresult_errcode)?;
        let mut buf = [0u16; 500];
        let mut len = 0u32;
        // (wdbg.syms.GetImagePathWide)(wdbg.syms, buf.as_mut_ptr(), buf.len() as u32, &mut len);
        (wdbg.sysobj.GetCurrentProcessExecutableNameWide)(wdbg.sysobj, buf.as_mut_ptr(), buf.len() as u32, &mut len);
        base.image_path = buf.to_utf8();
        base.pid.set(wdbg.sysobj.get_cur_syspid());
        if base.image_path.is_empty() {
            udbg_ui().warn("GetImagePath failed");
            base.image_path = path.to_string();
        }

        Self::init_callback(base, wdbg, ty)
    }

    pub fn attach(base: UDbgBase, pid: pid_t) -> UDbgResult<Arc<Self>> {
        unsafe {
            let wdbg = Self::new()?;
            let err = wdbg_attach_process(wdbg.client, pid as usize);
            if err > 0 { return Err(UDbgError::Code(err)); }
            Self::init_callback(base, wdbg, WDbgType::Normal)
        }
    }

    pub fn get_mapped_file_name(&self, a: u64) {
        let mut info = 0u32;
        unsafe {
            (self.spaces.GetOffsetInformation)(self.spaces,
                DEBUG_DATA_SPACE_VIRTUAL, DEBUG_OFFSINFO_VIRTUAL_SOURCE, a,
                core::mem::transmute(&mut info),
                core::mem::size_of_val(&info) as _, null_mut()
            );
            if info == DEBUG_VSOURCE_MAPPED_IMAGE {
                // self.syms.GetModuleByModuleNameWide
            }
        }
    }
}

impl ReadMemory for WDbgAdaptor {
    fn read_memory<'a>(&self, addr: usize, data: &'a mut [u8]) -> Option<&'a mut [u8]> {
        let mut r = 0;
        (self.spaces.ReadVirtual)(self.spaces, addr as u64, data.as_mut_ptr(), data.len() as u32,  &mut r).check_hresult().ok()?;
        if r > 0 { Some(&mut data[..r as usize]) } else { None }
    }
}

impl WriteMemory for WDbgAdaptor {
    fn write_memory(&self, addr: usize, data: &[u8]) -> Option<usize> {
        let mut r = 0;
        (self.spaces.WriteVirtual)(self.spaces, addr as u64, data.as_ptr(), data.len() as u32, &mut r).check_hresult().ok()?;
        Some(r as usize)
    }
}

impl UDbgAdaptor for WDbgAdaptor {
    fn base(&self) -> &UDbgBase { &self.base }

    fn detach(&self) -> Result<(), UDbgError> {
        (self.client.DetachCurrentProcess)(self.client);
        Ok(())
    }
    fn breakk(&self) -> Result<(), UDbgError> {
        const DEBUG_INTERRUPT_ACTIVE: u32 = 0;
        if !self.paused.get() {
            (self.ctrl.SetInterrupt)(self.ctrl, DEBUG_INTERRUPT_ACTIVE);
        }
        Ok(())
    }
    fn kill(&self) -> Result<(), UDbgError> {
        if self.base.is_opened() {
            self.base.status.set(UDbgStatus::Ended);
        } else {
            self.breakk()?;
            (self.client.TerminateCurrentProcess)(self.client);
        }
        Ok(())
    }
    fn except_param(&self, i: usize) -> Option<usize> { None }

    // memory infomation
    fn enum_memory<'a>(&'a self) -> Result<Box<dyn Iterator<Item = MemoryPage> + 'a>, UDbgError> {
        // unsafe {
        //     let p = self.sysobj.get_process();
        //     if let Some(p) = Handle::clone_from_raw(p).and_then(|h| Process::from_handle(h)) {
        //         return Ok(Box::new(p.enum_memory(0)));
        //     }
        // }
        if self.ty == WDbgType::Kernel {
            return Err(UDbgError::NotSupport);
        }
        let mut address = 0;
        Ok(Box::new(std::iter::from_fn(move || {
            while let Some(p) = self.virtual_query(address) {
                address += p.size;
                if p.is_commit() { return Some(p); }
            }
            return None;
        })))
    }

    fn virtual_query(&self, address: usize) -> Option<MemoryPage> {
        unsafe {
            let mut mbi = Align16::<MEMORY_BASIC_INFORMATION64>::new();
            let mbi = mbi.as_mut();
            if wdbg_query_virtual(self.spaces, address, mbi) {
                Some(MemoryPage {
                    base: mbi.BaseAddress as usize,
                    alloc_base: mbi.AllocationBase as usize,
                    size: mbi.RegionSize as usize,
                    type_: mbi.Type,
                    state: mbi.State,
                    protect: mbi.Protect,
                    alloc_protect: mbi.AllocationProtect,
                })
            } else if self.ty == WDbgType::Kernel {
                Some(MemoryPage {
                    base: address & !0xFFF,
                    alloc_base: address & !0xFFF,
                    size: 0x1000,
                    type_: MEM_FREE,
                    state: MEM_COMMIT,
                    protect: PAGE_READONLY,
                    alloc_protect: PAGE_READONLY,
                })
            } else { None }
        }
    }

    fn get_memory_map(&self) -> Vec<UiMemory> {
        pub const MF_IMAGE: u32 = 1 << 0;
        pub const MF_MAP: u32 = 1 << 1;
        pub const MF_PRIVATE: u32 = 1 << 2;
        pub const MF_SECTION: u32 = 1 << 3;
        pub const MF_STACK: u32 = 1 << 4;
        pub const MF_HEAP: u32 = 1 << 5;
        pub const MF_PEB: u32 = 1 << 6;

        let mut peb = 0;
        (self.sysobj.GetCurrentProcessPeb)(self.sysobj, &mut peb);
        self.enum_memory().map(|iter| iter.map(|m| {
            let mut usage = String::new();
            let mut flags = match m.type_ {
                MEM_PRIVATE => MF_PRIVATE,
                MEM_IMAGE => MF_IMAGE,
                MEM_MAPPED => MF_MAP, _ => 0,
            };
            if m.base == 0x7FFE0000 {
                usage.push_str("KUSER_SHARED_DATA");
            } else if m.base == peb as usize {
                usage.push_str("PEB");
                flags |= MF_PEB;
            }
            if self.ty != WDbgType::Kernel {
                // TODO:
            }
            UiMemory {
                alloc_base: m.alloc_base,
                base: m.base, size: m.size,
                flags, usage: usage.into(),
                type_: m.type_().into(),
                protect: m.protect().into(),
            }
        }).collect()).unwrap_or_default()
    }
    // size: usize, type: RWX, commit/reverse
    fn virtual_alloc(&self, address: usize, size: usize, ty: &str) -> Result<usize, UDbgError> { Err(UDbgError::NotSupport) }
    fn virtual_free(&self, address: usize) {}

    // thread infomation
    fn get_thread_context(&self, tid: u32) -> Option<Registers> { None }
    fn enum_thread<'a>(&'a self) -> UDbgResult<Box<dyn Iterator<Item=tid_t>+'a>> {
        let mut count = 0;
        (self.sysobj.GetNumberThreads)(self.sysobj, &mut count);
        let mut buf = vec![0; count as usize];
        (self.sysobj.GetThreadIdsByIndex)(self.sysobj, 0, count, core::ptr::null_mut(), buf.as_mut_ptr());
        Ok(Box::new(buf.into_iter()))
    }
    fn open_thread(&self, tid: tid_t) -> Result<Box<dyn UDbgThread>, UDbgError> {
        udbg_ui().log(format!("open thread: {}", tid));
        Ok(Box::new(WDbgThread {
            data: ThreadData{tid, wow64: false, handle: unsafe { Handle::from_raw_handle(null_mut()) }}
        }) as Box<dyn UDbgThread>)
    }

    // breakpoint
    fn add_bp(&self, opt: BpOpt) -> UDbgResult<Arc<(dyn UDbgBreakpoint + 'static)>> {
        if opt.table { return Err(UDbgError::NotSupport); }
        let bp = if let Some(rw) = opt.rw {
            let bp = self.ctrl.add_bp(DEBUG_BREAKPOINT_DATA).map_err(hresult_errcode)?;
            bp.set_data_params(opt.len.map(|l| l.to_int()).unwrap_or(1), match rw {
                HwbpType::Execute => DEBUG_BREAK_EXECUTE,
                HwbpType::Write => DEBUG_BREAK_WRITE,
                HwbpType::Access => DEBUG_BREAK_READ,
            });
            bp
        } else {
            self.ctrl.add_bp(DEBUG_BREAKPOINT_CODE).map_err(hresult_errcode)?
        };
        bp.set_offset(opt.address as u64);
        if opt.temp {
            bp.add_flags(DEBUG_BREAKPOINT_ONE_SHOT).map_err(hresult_errcode)?;
        }
        if let Some(tid) = opt.tid {
            bp.set_match_tid(tid).map_err(hresult_errcode)?;
        }
        if opt.enable {
            bp.set_enable(opt.enable).map_err(hresult_errcode)?;
        }
        Ok(Arc::new(IDbgBpWrapper(bp, self.ctrl)))
    }

    fn get_bp<'a>(&'a self, id: BpID) -> Option<Arc<dyn UDbgBreakpoint + 'a>> {
        // self.ctrl.get_bp_by_id(id).map_err(hresult_errcode)?;
        Some(Arc::new(IDbgBpWrapper(self.ctrl.get_bp_by_id(id).ok()?, self.ctrl)))
    }
    fn get_bp_by_address<'a>(&'a self, a: usize) -> Option<Arc<dyn UDbgBreakpoint + 'a>> {
        self.bp.read().unwrap().1.get(&a).map(|bp| Arc::new(*bp) as Arc<dyn UDbgBreakpoint>)
    }

    fn get_bp_list(&self) -> Vec<BpID> {
        self.ctrl.bp_list().into_iter().map(|bp| bp.id().unwrap_or_default()).collect()
    }
    fn get_breakpoints<'a>(&'a self) -> Vec<Arc<dyn UDbgBreakpoint + 'a>> {
        self.ctrl.bp_list().into_iter().map(|bp| Arc::new(IDbgBpWrapper(bp, self.ctrl)) as Arc<dyn UDbgBreakpoint>).collect()
    }

    // symbol infomation
    fn symbol_manager(&self) -> Option<&dyn UDbgSymMgr> {
        Some(&self.wdbg)
    }

    fn get_address_by_symbol(&self, symbol: &str) -> Option<usize> {
        unsafe {
            let r = wdbg_get_offset(self.syms, symbol.to_wide().as_ptr());
            if r > 0 { Some(r) } else { None }
        }
    }

    fn get_symbol(&self, addr: usize, max_offset: usize) -> Option<SymbolInfo> {
        unsafe {
            let mut buf = [0; 1024];
            let mut disp = 0u64;
            let size = wdbg_get_near_name(self.syms, addr, max_offset, buf.as_mut_ptr(), buf.len(), &mut disp);
            if size > 0 {
                let name = CStr::from_ptr(buf.as_ptr()).to_str().unwrap_or_default();
                let mut iter = name.split("!");
                let m = iter.next();
                let n = iter.next();
                Some(SymbolInfo {
                    module: m.unwrap_or_default().into(),
                    symbol: n.unwrap_or_default().into(),
                    offset: disp as usize,
                    mod_base: self.syms.find_module(addr as u64).ok()?.1 as usize,
                })
            } else { None }
        }
    }
    // fn parse_address(&self, symbol: &str) -> Option<usize> {
    //     unsafe {
    //         self.get_reg(symbol).ok().map(|r| r.as_int()).or_else(|| {
    //             let r = wdbg_evaluate(self.ctrl, symbol.to_wide().as_ptr());
    //             if r > 0 { Some(r) } else { None }
    //         })
    //     }
    // }

    fn get_registers<'a>(&'a self) -> UDbgResult<&'a mut dyn UDbgRegs> {
        unsafe {
            let this = mutable(self);
            let r = wdbg_get_registers(self.adv, &mut this.context);
            if r == 0 {
                Ok(&mut this.context)
            } else { Err(UDbgError::Code(r)) }
        }
    }

    fn enum_handle<'a>(&'a self) -> UDbgResult<Box<dyn Iterator<Item = UiHandle> + 'a>> {
        let handle = self.sysobj.get_process();
        if !handle.is_null() {
            udbg_ui().get_util().enum_process_handle(self.sysobj.get_cur_syspid(), handle)
        } else {
            Err(UDbgError::NotSupport)
        }
    }

    fn do_cmd(&self, cmd: &str) -> UDbgResult<()> {
        self.ctrl.execute(cmd);
        Ok(())
    }

    // extra function
    fn lua_call(&self, s: &llua::State) -> UDbgResult<i32> {
        const DEBUG_SYSVERSTR_SERVICE_PACK: u32 = 0x00000000;
        const DEBUG_SYSVERSTR_BUILD: u32        = 0x00000001;

        let key = s.to_str(2).unwrap_or("");
        match key {
            "sysver" => {
                let mut buf = [0u16; 300];
                (self.ctrl.GetSystemVersionStringWide)(self.ctrl, DEBUG_SYSVERSTR_SERVICE_PACK, buf.as_mut_ptr(), buf.len(), None);
                s.push(buf.to_utf8().as_str());
                (self.ctrl.GetSystemVersionStringWide)(self.ctrl, DEBUG_SYSVERSTR_BUILD, buf.as_mut_ptr(), buf.len(), None);
                s.push(buf.to_utf8().as_str());
                return Ok(2);
            }
            "handle" => {
                let p = self.sysobj.get_process();
                if p.is_null() { s.push_nil(); } else { s.push(p as usize); }
            }
            "peb" => {
                s.push(self.sysobj.get_peb());
            }
            _ => return Ok(0),
        };
        Ok(1)
    }

    fn loop_event(self: Arc<Self>, state: UEventState) -> EventPumper {
        Box::pin((async move || unsafe {
            use std::ops::Deref;

            let wait_event = || {
                self.paused.set(false);
                let r = self.ctrl.wait_event(0, -1);
                self.base.event_tid.set(self.sysobj.get_cur_systid());
                // self.base.pid.set(pid);
                self.paused.set(true);
                // TODO: optimize
                self.get_registers();
                self.base.event_pc.set(self.context.Rip as usize);
                return r;
            };
            let get_event = || mutable(self.deref()).event.take();

            // wait init bp
            loop {
                wait_event();
                match get_event() {
                    Some(mut event) => {
                        let mut initbp = false;
                        if matches!(event, UEvent::Exception {..}) {
                            event = UEvent::InitBp;
                            initbp = true;
                        }
                        let status = reply_to_status(state.on(event).await);
                        self.ctrl.set_execute_status(status);
                        if initbp { break; }
                    }
                    None => break,
                }
            }
            // event looop
            if self.ty == WDbgType::Dump {
                self.paused.set(false);
                // udbg_ui().warn(&format!("wait: {:x}", status));
                while self.base.status.get() != UDbgStatus::Ended {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            } else {
                loop {
                    let r = wait_event();
                    if r != 0 {
                        break;
                    }
                    let event = get_event().unwrap_or(UEvent::Step);
                    let status = reply_to_status(state.on(event).await);
                    self.ctrl.set_execute_status(status);
                }
            }
            (self.client.EndSession)(self.client, DEBUG_END_ACTIVE_TERMINATE);
        })())
    }
}

#[derive(Deref)]
struct WDbgThread {
    #[deref]
    data: ThreadData,
}

impl UDbgThread for WDbgThread {
    fn name(&self) -> Arc<str> { "".into() }
    fn status(&self) -> Arc<str> { "".into() }
}

pub struct WDbgModule {
    data: sym::ModuleData,
    syms: &'static DbgSyms,
    param: DEBUG_MODULE_PARAMETERS,
}

impl UDbgModule for WDbgModule {
    fn data(&self) -> &sym::ModuleData { &self.data }
    fn symbol_status(&self) -> SymbolStatus {
        SymbolStatus::Unload
    }
    fn enum_symbol(&self, pat: Option<&str>) -> UDbgResult<Box<dyn Iterator<Item=sym::Symbol>>> {
        let base = self.data.base as u64;
        Ok(Box::new(self.syms.enum_symbol(&format!("{}!{}", self.data.name, pat.unwrap_or("*")))?.map(move |(name, offset)| {
            sym::Symbol {
                offset: (offset - base) as u32,
                len: sym::SYM_NOLEN,
                type_id: 0, flags: 0,
                name: match name.split_once("!") {
                    Some((_, s)) => s.into(),
                    None => name.into(),
                },
            }
        })))
    }
    fn call(&self, s: &llua::State) -> i32 {
        match s.to_str(2).unwrap_or_default() {
            "pdb_path" => if self.param.SymbolType != DEBUG_SYMTYPE_EXPORT && self.param.SymbolType != DEBUG_SYMTYPE_NONE {
                let path = self.syms.get_module_name_string(DEBUG_MODNAME_SYMBOL_FILE, self.data.base as u64).ok();
                return s.pushx((path, self.param.SymbolType));
            }
            _ => return 0,
        }; 0
    }
}

pub struct WinDbgEng;

impl UDbgEngine for WinDbgEng {
    fn open(&self, base: UDbgBase, pid: pid_t) -> UDbgResult<Arc<dyn UDbgAdaptor>> {
        Ok(WDbgAdaptor::attach(base, pid)?)
    }

    fn attach(&self, base: UDbgBase, pid: pid_t) -> UDbgResult<Arc<dyn UDbgAdaptor>> {
        Ok(WDbgAdaptor::attach(base, pid)?)
    }

    fn create(&self, base: UDbgBase, path: &str, cwd: Option<&str>, args: &[&str]) -> UDbgResult<Arc<dyn UDbgAdaptor>> {
        Ok(WDbgAdaptor::create(base, path, cwd, args.into())?)
    }
}