#![allow(dead_code)]
#![allow(non_snake_case)]
#![feature(async_closure)]
#![feature(bool_to_option)]
#![feature(format_args_capture)]

#[macro_use] extern crate log;
#[macro_use] extern crate derive_more;

mod peutil;
mod kernel;
mod winknl;
mod dbgeng;

use llua::*;
use udbg_base::*;

use proto::*;
use kernel::*;

unsafe extern "C" fn compare_bytes(l: *mut ffi::lua_State) -> i32 {
    use llua::ffi::*;

    let s = State::from_ptr(l);
    let p1 = lua_tostring(s.as_ptr(), lua_upvalueindex(1));
    if p1.is_null() {
        luaL_checkstring(s.as_ptr(), 1);
        luaL_checkstring(s.as_ptr(), 2);
        let p1 = s.to_bytes(1).unwrap();
        let p2 = s.to_bytes(2).unwrap();
        let len = s.to_integer(3);
        let len = if len > 0 { len as usize} else { p1.len().min(p2.len()) };
        s.push_value(1);
        s.push_value(2);
        s.push(len);
        s.push(0);
        s.push_cclosure(Some(compare_bytes), 4);
        return 1;
    } else {
        let p1 = s.to_bytes(lua_upvalueindex(1)).unwrap();
        let p2 = s.to_bytes(lua_upvalueindex(2)).unwrap();
        let len = s.to_integer(lua_upvalueindex(3)) as usize;
        let _i = s.to_integer(lua_upvalueindex(4)) as usize;

        let mut i = _i;
        while i < len && p1[i] == p2[i] { i += 1; }

        let diffpos = i;
        let mut size = 0usize;
        while i < len && p1[i] != p2[i] { i += 1; size += 1; }
        if i >= len && 0 == size { return 0; }

        s.push(i); s.replace(lua_upvalueindex(4));
        s.pushx((diffpos, size))
    }
}

#[no_mangle]
unsafe fn plugin_init() -> Result<(), String> {
    udbg_ui().with_lua(&|s: &State| {
        use udbg_base::{*, sc::*};

        let g = s.global();
        let p = g.getf(cstr!("package"));
        let loaded = p.getf(cstr!("loaded"));
        let t = s.table(0, 8);
        loaded.set("uext", t);

        t.set("compare_bytes", compare_bytes as CFunction);
        t.set("load_driver", RsFn::new(load_driver::<&str>));
        t.set("unload_driver", RsFn::<(),_,_,_>::new(unload_driver));

        t.set("verify_file", RsFn::new(|s: &State, path: &str| {
            wintrust::verify_file(path).map(|(status, signers)| {
                let top = s.get_top();
                s.push(status as u32);
                for signer in signers {
                    s.push(signer.get_signer_name().unwrap_or_default());
                }
                Pushed(s.get_top() - top)
            })
        }));

        t.set("normalize_path", RsFn::new(normalize_path));

        t.set("PEUtil", peutil::PEUtil::init_metatable as InitMetatable);

        impl UserData for UDbgDriver {
            const TYPE_NAME: &'static str = "UDbgDriver";

            fn methods(mt: &ValRef) {
                mt.register_fn("read_kernel", |this: &Self, addr: usize, size: usize| {
                    let mut buf = vec![0u8; size];
                    let len = this.read_kernel(addr, &mut buf);
                    buf.resize(len, 0);
                    buf
                });
                mt.register_fn("write_kernel", Self::write_kernel);

                mt.register_fn("read_virtual", |this: &Self, pid: u32, addr: usize, size: usize| {
                    let mut buf = vec![0u8; size];
                    let len = this.read_memory(pid, addr, &mut buf);
                    buf.resize(len, 0);
                    buf
                });
                mt.register_fn("write_kernel", Self::write_virtual);

                mt.register_fn("script", |this: &Self, text: &[u8]| {
                    this.exec(DriverCmd::Script {ptr: text.as_ptr(), len: text.len()});
                });
            }
        }
        t.set("open_driver", RsFn::new(open_driver));
    });

    udbg_ui().register_engine("krnl", Box::new(winknl::KrnlEngine));
    udbg_ui().register_engine("dbgeng", Box::new(dbgeng::WinDbgEng));

    Ok(())
}

fn push_kresult(s: &State, r: KResult) -> i32 {
    match r.data() {
        KData::Pack(m) => {
            s.push(LLuaMsgPack(m.as_bytes()));
        }
        KData::Err(m) => unsafe {
            s.raise_error(String::from_utf8_unchecked(m.as_bytes().to_vec()));
        }
        KData::Int(i) => {
            s.push(*i);
        }
        _ => return 0,
    }
    return 1;
}