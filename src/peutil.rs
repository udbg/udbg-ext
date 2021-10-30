
use std::error::Error;
use std::sync::Arc;
use udbg_base::*;

use llua::*;
use std::fmt;
use serde::{Deserialize, Deserializer, de::{self, Visitor, MapAccess}};

use winapi::um::winnt::*;
use core::mem::*;
use std::path::Path;
use std::convert::TryFrom;
use std::io::{Write, Seek, SeekFrom};

pub struct ImpFunc<'a> {
    pub hint: u16,
    pub name: &'a [u8],
}

impl<'de: 'a, 'a> Deserialize<'de> for ImpFunc<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ImpVisitor;
        impl<'de> Visitor<'de> for ImpVisitor {
            type Value = ImpFunc<'de>;
        
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("string or map")
            }

            fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Self::Value {hint: 0, name: value.as_bytes()})
            }

            fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(Self::Value {hint: 0, name: v})
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut name = None;
                let mut hint = 0;
                while let Some(key) = map.next_key::<&str>()? {
                    match key {
                        "hint" => { hint = map.next_value()?; }
                        "name" => { name = map.next_value()?; }
                        _ => {}
                    }
                }
                Ok(Self::Value {
                    hint,
                    name: name.ok_or(de::Error::custom("name"))?,
                })
            }
        }
        deserializer.deserialize_any(ImpVisitor)
    }
}

#[derive(Deserialize)]
pub struct ImpEntry<'a> {
    #[serde(default)]
    pub IAT: u32,
    pub name: &'a [u8],
    pub funcs: Vec<ImpFunc<'a>>,
}

impl UserData for PEUtil {
    fn methods(mt: &ValRef) {
        mt.set("__newindex", RsFn::new(|s: &State, this: &mut Self, key: &str| {
            match key {
                "OEP" => this.setOEP(s.args(3)),
                _ => {},
            };
            Pushed(0)
        }));
        mt.set("__call", RsFn::new(|s: &State, this: &Self, key: &str| unsafe {
            Pushed(this.lua_call(key, s))
        }));
        mt.set("from_file", RsFn::new(Self::from_file::<&str>));
        mt.set("from_base", RsFn::new(|base: usize| -> Result<Self, Box<dyn Error>> {
            let t = udbg_ui().target().ok_or("no target")?;
            Ok(PEUtil::from_target(t, base)?)
        }));
        mt.set("write_to_file", RsFn::new(Self::write_to_file::<&str>));
        mt.register_fn("read_data", Self::read_data);
        mt.set("add_section", RsFn::new(Self::add_section));
        mt.set("reloc_section", RsFn::new(Self::reloc_section));
        mt.set("compare_section", RsFn::new(|this: &'static mut Self, mem: &'static mut Self, i: usize|
            this.compare_section_data(mem, i).map(|iter| BoxIter(Box::new(iter)))
        ));
        mt.set("compare_export", RsFn::new(|this: &'static mut Self, mem: &'static mut Self|
            this.compare_export(mem).map(|iter| BoxIter(Box::new(iter)))
        ));
        mt.register_fn("add_imports", |s: &State, this: &mut Self, imports: lserde::DeserValue<Vec<ImpEntry>>| -> Result<(), Box<dyn Error>> {
            s.val(2).rawget("section");
            let section = s.val(-1);
            this.add_import(section.cast().unwrap_or(b".imps"), &imports)?;
            Ok(())
        });
    }
}

pub trait SectionHeader {
    fn name(&self) -> Option<&str>;
    fn virtual_size(&self) -> u32;
    fn max_len(&self) -> u32;
}

impl SectionHeader for IMAGE_SECTION_HEADER {
    fn name(&self) -> Option<&str> {
        let pos = self.Name.iter().position(|x| *x == 0).unwrap_or(self.Name.len());
        std::str::from_utf8(&self.Name[..pos]).ok()
    }

    fn virtual_size(&self) -> u32 {
        unsafe { *self.Misc.VirtualSize() }
    }

    fn max_len(&self) -> u32 {
        self.SizeOfRawData.max(self.virtual_size())
    }
}

fn align_with(size: u32, a: u32) -> u32 {
    let rest = size % a;
    if rest == 0 { size } else { size - rest + a }
}

const NO_SECTIONS: &str = "no sections";

pub struct NtHeader(Result<PIMAGE_NT_HEADERS64, PIMAGE_NT_HEADERS32>);

macro_rules! with_nt {
    ($header:expr, $nt:ident, $proc:block) => {
        match $header {
            Ok($nt) => $proc,
            Err($nt) => $proc,
        }
    };

    ($header:expr, $nt:ident, $proc:block, $proc32: block) => {
        match $header {
            Ok($nt) => $proc,
            Err($nt) => $proc32,
        }
    };
}

impl NtHeader {
    pub fn headers(&self) -> Result<&IMAGE_NT_HEADERS64, &IMAGE_NT_HEADERS32> {
        with_nt!(self.0, nt, {
            Ok(unsafe { nt.as_ref().unwrap() })
        }, {
            Err(unsafe { nt.as_ref().unwrap() })
        })
    }

    pub fn image_base(&self) -> u64 {
        with_nt!(self.headers(), nt, { (*nt).OptionalHeader.ImageBase as _ })
    }
}

// TODO: expand section, write content
pub struct PEUtil {
    pub image_base: u64,
    // IMAGE_DOS_HEADER + IMAGE_NT_HEADERS
    pub header_data: Vec<u8>,
    pub sections: Vec<IMAGE_SECTION_HEADER>,
    pub section_data: Vec<Option<Box<[u8]>>>,
    pub reader: Arc<dyn ReadMemory>,
    pub memview: bool,
    nt_header: NtHeader,
}

impl PEUtil {
    fn new(base: Option<u64>, memview: bool, t: Arc<dyn ReadMemory>) -> Result<Self, String> {
        let dos: IMAGE_DOS_HEADER = t.read_value(0).ok_or("DOS Header")?;
        dos.e_magic.eq(&IMAGE_DOS_SIGNATURE).then_some(0).ok_or("Invalid DOS")?;
        let nt: IMAGE_NT_HEADERS32 = t.read_value(dos.e_lfanew as usize).ok_or("NT Header")?;
        nt.Signature.eq(&IMAGE_NT_SIGNATURE).then_some(0).ok_or("Invalid PE")?;
        let o_secions = dos.e_lfanew as u32 + ntapi::FIELD_OFFSET!(IMAGE_NT_HEADERS64, OptionalHeader) as u32 + nt.FileHeader.SizeOfOptionalHeader as u32;
        let header_data = t.read_bytes(0, o_secions as usize);
        (header_data.len() == o_secions as usize).then_some(()).ok_or("Read Headers")?;
        let mut sections = vec![];
        // read section headers
        for i in 0..nt.FileHeader.NumberOfSections as usize {
            let sec: IMAGE_SECTION_HEADER = t.read_value(o_secions as usize + size_of::<IMAGE_SECTION_HEADER>() * i).ok_or("SectionHeader")?;
            // if sec.VirtualAddress == 0 { break; }
            sections.push(sec);
        }

        let header_ptr = unsafe {
            let dos = header_data.as_ptr().cast::<IMAGE_DOS_HEADER>().as_ref().unwrap();
            let p32 = header_data.as_ptr().add(dos.e_lfanew as usize) as PIMAGE_NT_HEADERS32;
            match p32.as_ref().unwrap().OptionalHeader.Magic {
                IMAGE_NT_OPTIONAL_HDR64_MAGIC => Ok(p32 as _),
                IMAGE_NT_OPTIONAL_HDR32_MAGIC => Err(p32),
                magic => return Err(format!("invalid magic: 0x{:x}", magic)),
            }
        };
        let nt_header = NtHeader(header_ptr);
        let image_base = base.unwrap_or(nt_header.image_base());
        Ok(Self {
            section_data: vec![None; sections.len()],
            memview, reader: t,
            header_data, sections,
            nt_header, image_base,
        })
    }

    unsafe fn lua_call(&self, key: &str, s: &State) -> i32 {
        match key {
            // "pdb_sig" => s.push(pe.get_pdb_signature()),
            // "image_base" => s.push(pe.image_base),
            // "entry" => s.push(pe.entry),
            // "arch" => s.push(pe.get_arch()),
            // "name" => s.push(pe.name),
            "headers" => {
                match self.nt_header.headers() {
                    Ok(nt) => {
                        s.push(nt.as_byte_array());
                        s.push(64); 2
                    }
                    Err(nt) => {
                        s.push(nt.as_byte_array());
                        s.push(32); 2
                    }
                }
            }
            "data_dirs" => {
                s.push(self.data_dirs().as_byte_array()); 1
            }
            "sections" => {
                s.push(self.sections.as_slice().as_byte_array()); 1
            }
            "section" => {
                let sec = if s.is_integer(3) {
                    self.sections.get(s.to_integer(3) as usize)
                } else {
                    let name = s.args::<&[u8]>(3);
                    if name == b"#" {
                        s.push(self.sections.len());
                        return 1;
                    } else {
                        // self.find_section(name)
                        return 0;
                    }
                };
                if let Some(sec) = sec {
                    s.push(sec.name());
                    s.push(sec.VirtualAddress);
                    s.push(sec.virtual_size());
                    s.push(sec.Characteristics);
                    return 4;
                } else { return 0; }
            }
            _ => return 0,
        }
    }

    pub fn from_target(target: Arc<dyn UDbgAdaptor>, base: usize) -> Result<Self, String> {
        struct PEMem {
            base: usize,
            target: Arc<dyn UDbgAdaptor>,
        }

        impl ReadMemory for PEMem {
            fn read_memory<'a>(&self, addr: usize, data: &'a mut [u8]) -> Option<&'a mut [u8]> {
                self.target.read_memory(addr + self.base, data)
            }
        }

        Self::new(Some(base as u64), true, Arc::new(PEMem {target, base}))
    }

    pub fn from_file<P: AsRef<Path>>(path: P, memview: bool) -> Result<Self, Box<dyn Error>> {
        #[derive(Deref)]
        struct PEFile(memmap::Mmap);

        impl ReadMemory for PEFile {
            fn read_memory<'a>(&self, addr: usize, data: &'a mut [u8]) -> Option<&'a mut [u8]> {
                let b = self.len().min(addr);
                let e = self.len().min(b + data.len());
                let s = &self.0[b..e];
                let res = &mut data[..s.len()];
                res.copy_from_slice(s);
                Some(res)
            }
        }

        let f = std::fs::File::open(path)?;
        unsafe {
            let file = PEFile(memmap::Mmap::map(&f)?);
            Ok(Self::new(None, memview, Arc::new(file))?)
        }
    }

    // pub fn from_file(path: impl AsRef<Path>, memview: bool) -> Result<Self, Box<dyn Error>> {
    //     let mut header_data = vec![0u8; size_of::<IMAGE_DOS_HEADER>()];
    //     let mut f = std::fs::File::open(path)?;
    //     // read IMAGE_DOS_HEADER
    //     f.read_exact(&mut header_data)?;
    //     unsafe {
    //         let dos = header_data.as_ptr().cast::<IMAGE_DOS_HEADER>().as_ref().unwrap();
    //         dos.e_magic.eq(&IMAGE_DOS_SIGNATURE).then_some(0).ok_or("Invalid DOS")?;
    //         let mut nt: IMAGE_NT_HEADERS32 = core::mem::zeroed();
    //         f.seek(SeekFrom::Start(dos.e_lfanew as u64))?;
    //         f.read_exact(nt.as_mut_byte_array())?;
    //         nt.Signature.eq(&IMAGE_NT_SIGNATURE).then_some(0).ok_or("Invalid PE")?;
    //         let o_secions = dos.e_lfanew as u32 + ntapi::FIELD_OFFSET!(IMAGE_NT_HEADERS64, OptionalHeader) as u32 + nt.FileHeader.SizeOfOptionalHeader as u32;
    //         header_data.resize(o_secions as usize, 0);

    //         // read IMAGE_DOS_HEADER + IMAGE_NT_HEADERS
    //         f.seek(SeekFrom::Start(0))?;
    //         f.read_exact(&mut header_data)?;

    //         let mut sections = vec![];
    //         // read section headers
    //         for i in 0..nt.FileHeader.NumberOfSections as usize {
    //             let mut sec: IMAGE_SECTION_HEADER = core::mem::zeroed();
    //             f.read_exact(sec.as_mut_byte_array())?;
    //             sections.push(sec);
    //             // udbg_ui().log(format!("read {i} {:?}", sec.name()));
    //         }
    //     }
    // }

    pub fn dos(&self) -> &IMAGE_DOS_HEADER {
        unsafe {
            self.header_data.as_ptr().cast::<IMAGE_DOS_HEADER>().as_ref().unwrap()
        }
    }

    #[inline(always)]
    pub fn headers_ptr(&self) -> Result<PIMAGE_NT_HEADERS64, PIMAGE_NT_HEADERS32> {
        self.nt_header.0
    }

    pub fn setOEP(&mut self, v: u32) {
        match self.headers_ptr() {
            Ok(nt) => unsafe {
                (*nt).OptionalHeader.AddressOfEntryPoint = v;
            }
            Err(nt) => unsafe {
                (*nt).OptionalHeader.AddressOfEntryPoint = v;
            }
        }
    }

    #[inline]
    pub fn is_32(&self) -> bool { self.headers_ptr().is_err() }

    // TODO：HeaderData中SectionHeader剩余空间不够用的情况，延长最后一段
    fn add_section_header(&mut self, name: &[u8], size: u32, Characteristics: u32) -> Result<IMAGE_SECTION_HEADER, String> {
        let mut Name = [0u8; IMAGE_SIZEOF_SHORT_NAME];
        let len = name.len().min(Name.len());
        (&mut Name[..len]).copy_from_slice(&name[..len]);
        const SIZE_OF_SECHDR: usize = size_of::<IMAGE_SECTION_HEADER>();

        unsafe {
            let (NumberOfSections, FileAlignment, SectionAlignment) = with_nt!(self.nt_header.headers(), nt, {
                (nt.FileHeader.NumberOfSections, nt.OptionalHeader.FileAlignment, nt.OptionalHeader.SectionAlignment)
            });
            assert_eq!(NumberOfSections as usize, self.sections.len());

            let header_endoff = self.header_data.len() + self.sections.len() * SIZE_OF_SECHDR;
            let mut first_sec = *self.sections.first().ok_or(NO_SECTIONS)?;
            // increase the PointerToRawData to contain the new section header
            while header_endoff + SIZE_OF_SECHDR > first_sec.PointerToRawData as usize {
                if first_sec.PointerToRawData + FileAlignment > first_sec.VirtualAddress {
                    return Err("over range the header".into());
                }
                for s in self.sections.iter_mut() {
                    s.PointerToRawData += FileAlignment;
                }
                first_sec = self.sections[0];
            }

            let (end_off, end_va) = self.sections.last().map(
                |s| (s.PointerToRawData + s.SizeOfRawData, s.VirtualAddress + s.max_len())
            ).ok_or(NO_SECTIONS)?;
    
            let sec_pos = align_with(end_off, FileAlignment);
            let sec_va = align_with(end_va, SectionAlignment);
            let new_size = align_with(size, FileAlignment);

            let result = IMAGE_SECTION_HEADER {
                Name,
                VirtualAddress: sec_va,
                Misc: transmute(size),
                SizeOfRawData: new_size,
                PointerToRawData: sec_pos,
                PointerToRelocations: 0,
                PointerToLinenumbers: 0,
                NumberOfRelocations: 0,
                NumberOfLinenumbers: 0,
                Characteristics,
            };
            self.sections.push(result);
            with_nt!(self.headers_ptr(), nt, {
                (*nt).FileHeader.NumberOfSections += 1;
                (*nt).OptionalHeader.SizeOfImage += align_with(size, (*nt).OptionalHeader.SectionAlignment);
            });
            Ok(result)
        }
    }

    pub fn set_last_section_size(&mut self, size: u32) -> Result<u32, String> {
        unsafe {
            let (_, FileAlignment, _) = match self.headers_ptr() {
                Ok(nt) => (
                    (*nt).FileHeader.NumberOfSections,
                    (*nt).OptionalHeader.FileAlignment,
                    (*nt).OptionalHeader.SectionAlignment,
                ),
                Err(nt) => (
                    (*nt).FileHeader.NumberOfSections,
                    (*nt).OptionalHeader.FileAlignment,
                    (*nt).OptionalHeader.SectionAlignment,
                ),
            };
            {
                let sec = self.sections.last_mut().ok_or("NO SECTION")?;
                sec.SizeOfRawData = align_with(size, FileAlignment);
                *sec.Misc.VirtualSize_mut() = size;
            }
            let sec = self.sections.last().ok_or("NO SECTION")?;
            match self.headers_ptr() {
                Ok(nt) => {
                    (*nt).OptionalHeader.SizeOfImage = sec.VirtualAddress + sec.SizeOfRawData;
                }
                Err(nt) => {
                    (*nt).OptionalHeader.SizeOfImage += sec.VirtualAddress + sec.SizeOfRawData;
                }
            };

            Ok(sec.SizeOfRawData)
        }
    }

    pub fn add_section(&mut self, name: &[u8], mut data: Vec<u8>, Characteristics: u32) -> Result<(), String> {
        self.add_section_header(name, data.len() as u32, Characteristics)?;
        data.resize(self.sections.last().ok_or("no sections")?.SizeOfRawData as usize, 0);
        self.section_data.push(data.into_boxed_slice().into());
        Ok(())
    }

    pub fn write(&mut self, mut w: impl Write + Seek) -> Result<(), Box<dyn Error>> {
        w.seek(SeekFrom::Start(0))?;
        // writer the header: dos + nt + section headers
        w.write(&self.header_data)?;

        // write the section headers
        for s in self.sections.iter() {
            w.write(s.as_byte_array())?;
        }

        // write the section data
        // TODO: align raw size / raw address
        // TODO: check PointerToRawData > last section's VA
        let sections = self.sections.clone();
        for (i, s) in sections.iter().enumerate() {
            let data = self.get_section_data(i, true).ok_or_else(|| format!("no section data: {i}"))?;
            let pos = s.PointerToRawData.into();
            // udbg_ui().log(format!("{i} pos {pos:x}"));
            w.seek(SeekFrom::Start(pos))?;
            let size = s.SizeOfRawData as usize;
            w.write(&data[..size.min(data.len())])?;
        }
        Ok(())
    }

    pub fn write_to_file<P: AsRef<Path>>(&mut self, path: P) -> Result<(), Box<dyn Error>> {
        let mut f = std::fs::File::create(path)?;
        self.write(&mut f)
    }

    pub fn get_section_i(&self, rva: u32) -> Option<usize> {
        use std::cmp::Ordering;
        self.sections.binary_search_by(|s| {
            if rva >= s.VirtualAddress && rva < (s.VirtualAddress + s.SizeOfRawData) {
                Ordering::Equal
            } else if rva < s.VirtualAddress {
                Ordering::Greater
            } else { Ordering::Less }
        }).ok()
    }

    // #[inline]
    // pub fn get_section_by_rva(&self, rva: u32) -> Option<&IMAGE_SECTION_HEADER> {
    //     let i = self.get_section_i(rva)?;
    //     self.sections.get(i)
    // }

    pub fn to_offset(&self, rva: u32) -> u32 {
        if self.memview {
            rva
        } else {
            self.get_section_i(rva).map(|i| {
                let s = self.sections[i];
                (rva - s.VirtualAddress) + s.PointerToRawData
            }).unwrap_or(rva)
        }
    }

    pub fn read_data(&self, rva: u32, len: usize) -> Vec<u8> {
        return self.reader.read_bytes(self.to_offset(rva) as _, len);
    }

    pub fn get_section_data(&mut self, i: usize, raw: bool) -> Option<&[u8]> {
        let s = self.sections.get(i)?;
        let is_empty = self.section_data.get_mut(i)?.is_none();
        if is_empty {
            let offset = if self.memview { s.VirtualAddress } else { s.PointerToRawData };
            let size = if raw { s.SizeOfRawData } else { s.virtual_size() };
            let data = self.reader.read_bytes(offset as _, size as _);
            if data.is_empty() && size != 0 {
                if s.Characteristics & IMAGE_SCN_MEM_DISCARDABLE > 0 {
                    udbg_ui().warn(format!("discardable section: {:?}", s.name()));
                } else {
                    udbg_ui().error(format!("read section {:?}", s.name()));
                }
            }
            self.section_data[i] = Some(data.into_boxed_slice());
        }
        self.section_data.get(i)?.as_ref().map(Box::as_ref)
    }

    pub fn get_data_by_rva(&mut self, rva: u32) -> Option<&[u8]> {
        let i = self.get_section_i(rva)?;
        let sva = self.sections.get(i)?.VirtualAddress;
        let sd = self.get_section_data(i, true)?;
        let off = (rva - sva) as usize;
        if off <= sd.len() { Some(&sd[off..]) } else { None }
    }

    pub fn data_slice(&mut self, rva: u32, len: usize) -> Option<&[u8]> {
        let d = self.get_data_by_rva(rva)?;
        if len <= d.len() { Some(&d[..len]) } else { None }
    }

    #[inline]
    pub fn ref_rva<T>(&mut self, rva: u32) -> Option<&T> {
        let d = self.data_slice(rva, size_of::<T>())?;
        Some(unsafe { d.as_ptr().cast::<T>().as_ref().unwrap() })
    }

    pub fn data_dirs_ptr(&self) -> PIMAGE_DATA_DIRECTORY {
        (match self.headers_ptr() {
            Ok(nt) => unsafe {
                (*nt).OptionalHeader.DataDirectory.as_ptr()
            }
            Err(nt) => unsafe {
                (*nt).OptionalHeader.DataDirectory.as_ptr()
            }
        }) as usize as _
    }

    pub fn data_dirs(&self) -> &[IMAGE_DATA_DIRECTORY] {
        match self.headers_ptr() {
            Ok(nt) => unsafe {
                &(*nt).OptionalHeader.DataDirectory[..]
            }
            Err(nt) => unsafe {
                &(*nt).OptionalHeader.DataDirectory[..]
            }
        }
    }

    #[inline]
    pub fn get_data_dir(&self, index: impl Into<usize>) -> Option<&IMAGE_DATA_DIRECTORY> {
        self.data_dirs().get(index.into()).filter(|d| d.VirtualAddress != 0)
    }

    pub fn get_imports(&mut self) -> Result<Vec<IMAGE_IMPORT_DESCRIPTOR>, String> {
        let mut data = self.get_data_by_rva(
            self.get_data_dir(IMAGE_DIRECTORY_ENTRY_IMPORT).ok_or("get import")?.VirtualAddress
        ).ok_or("IDT")?;
        let mut result = vec![];

        const IID_LEN: usize = size_of::<IMAGE_IMPORT_DESCRIPTOR>();
        unsafe {
            while data.len() >= IID_LEN {
                let iid = data.as_ptr().cast::<IMAGE_IMPORT_DESCRIPTOR>().read();
                if *iid.u.Characteristics() > 0 || iid.FirstThunk > 0 || iid.ForwarderChain > 0 || iid.Name > 0 {
                    result.push(iid);
                } else {
                    break;
                }
                data = &data[IID_LEN..];
            }
            Ok(result)
        }
    }

    fn build_import_section<THUNK>(&mut self, sec: &IMAGE_SECTION_HEADER, imports: &mut Vec<IMAGE_IMPORT_DESCRIPTOR>, items: &[ImpEntry]) -> Result<Vec<u8>, String>
    where THUNK: TryFrom<u32> + Copy, <THUNK as TryFrom<u32>>::Error: std::fmt::Debug {
        let mut buf = vec![];
        let sva = sec.VirtualAddress;

        unsafe {
            // write all names
            struct TempImp<THUNK: TryFrom<u32>> {
                libname_rva: u32,
                IAT: u32,
                iat: Vec<THUNK>,
                int: Vec<THUNK>,
            }
            let mut imps = vec![];
            for item in items {
                let libname_rva = sva + buf.len() as u32;
                buf.extend_from_slice(item.name);
                buf.push(0);

                let mut iat = vec![];
                let mut int = vec![];
                for func in item.funcs.iter() {
                    let rva = sva + buf.len() as u32;
                    buf.extend_from_slice(&func.hint.to_le_bytes());
                    buf.extend_from_slice(func.name);
                    buf.push(0);
                    let td = THUNK::try_from(rva).unwrap();
                    if item.IAT == 0 {
                        iat.push(td);
                    }
                    int.push(td);
                }
                // ends with zeroed data
                if item.IAT == 0 {
                    iat.push(core::mem::zeroed());
                }
                int.push(core::mem::zeroed());

                imps.push(TempImp {libname_rva, iat, int, IAT: item.IAT});
            }

            // write all IMAGE_THUNK_DATA
            //   align with 8
            for _ in 0 .. (8 - buf.len() % 8) {
                buf.push(0);
            }
            for imp in imps {
                let mut import: IMAGE_IMPORT_DESCRIPTOR = core::mem::zeroed();
                import.Name = imp.libname_rva;

                // write INT
                *import.u.OriginalFirstThunk_mut() = sva + buf.len() as u32;
                buf.extend_from_slice(imp.int.as_slice().as_byte_array());

                // write IAT
                if imp.IAT > 0 {
                    import.FirstThunk = imp.IAT;
                } else {
                    import.FirstThunk = sva + buf.len() as u32;
                    buf.extend_from_slice(imp.iat.as_slice().as_byte_array());
                }

                imports.push(import);
            }
            imports.push(core::mem::zeroed());

            Ok(buf)
        }
    }

    pub fn add_import(&mut self, secname: &[u8], items: &[ImpEntry]) -> Result<(), String> {
        let sec = self.add_section_header(secname, 1, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)?;
        let sva = sec.VirtualAddress;

        unsafe {
            let mut imports = match self.get_imports() {
                Ok(r) => r,
                Err(err) => {
                    udbg_ui().warn(format!("read imports failed: {}", err));
                    Default::default()
                }
            };
            let mut buf = if self.is_32() {
                self.build_import_section::<u32>(&sec, &mut imports, items)
            } else {
                self.build_import_section::<u64>(&sec, &mut imports, items)
            }?;

            // extends the IMAGE_IMPORT_DESCRIPTORs
            let IDT = self.data_dirs_ptr().add(IMAGE_DIRECTORY_ENTRY_IMPORT as usize).as_mut().unwrap();
            IDT.VirtualAddress = sva + buf.len() as u32;
            buf.extend_from_slice(imports.as_slice().as_byte_array());

            // add the section
            let align_size = self.set_last_section_size(buf.len() as u32)?;
            buf.resize(align_size as usize, 0);
            self.section_data.push(buf.into_boxed_slice().into());

            Ok(())
        }
    }

    pub fn reloc_section(&mut self, i: usize, new_base: i64) -> Result<Vec<u8>, String> {
        let s = self.sections.get(i).ok_or("section over range")?;
        let sva = s.VirtualAddress;
        let ssize = s.virtual_size();
        core::mem::drop(s);
        let delta = new_base - self.image_base as i64;
        let mut result = self.get_section_data(i, false).ok_or("get section data")?.to_vec();

        let rlt = self.data_dirs()[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];
        unsafe {
            fn enum_relocs(r: &IMAGE_BASE_RELOCATION) -> &[u16] {
                unsafe {
                    let p = transmute::<_, usize>(r) + size_of_val(r);
                    std::slice::from_raw_parts(transmute::<_, *const u16>(p), (r.SizeOfBlock as usize - size_of_val(r)) / 2)
                }
            }
            // https://stackoverflow.com/questions/17436668/how-are-pe-base-relocations-build-up
            let mut reloc_va = rlt.VirtualAddress;
            while reloc_va - rlt.VirtualAddress < rlt.Size {
                let r: &IMAGE_BASE_RELOCATION = self.ref_rva(reloc_va).ok_or("read reloc")?;
                if r.VirtualAddress >= sva && r.VirtualAddress < sva + ssize {
                    let boff = r.VirtualAddress - sva;  // base offset
                    for reloc in enum_relocs(r) {
                        let off = boff + (reloc & 0x0FFFu16) as u32;
                        if off >= result.len() as u32 {
                            warn!("off > sec.size 0x{:x} 0x{:x}", off, result.len());
                            continue;
                        }
                        let p = result.as_mut_ptr().offset(off as isize);
                        match reloc >> 12 {
                            IMAGE_REL_BASED_DIR64 => {
                                let p = transmute::<_, *mut i64>(p);
                                *p += delta;
                            }
                            IMAGE_REL_BASED_HIGHLOW => {
                                let p = transmute::<_, *mut i32>(p);
                                *p += delta as i32;
                            }
                            IMAGE_REL_BASED_ABSOLUTE => {}
                            rt => { warn!("unknown reloc type {} 0x{:x}", rt, off + r.VirtualAddress); }
                        }
                    }
                }
                reloc_va += r.SizeOfBlock;
            }
            Ok(result)
        }
    }

    pub fn compare_section_data<'a>(&'a mut self, mem: &'a mut Self, i: usize) -> Result<impl Iterator<Item=(usize, usize)> + 'a, String> {
        let sec = self.sections.get(i).ok_or("invalid section")?;
        if sec.SizeOfRawData == 0 {
            return Err("no raw data".into());
        }
        let d2 = mem.read_data(sec.VirtualAddress, sec.SizeOfRawData as _);
        core::mem::drop(sec);
        let d1 = self.reloc_section(i, mem.image_base as i64).map_err(|e| format!("reloc section: {}", e))?;

        if d1.is_empty() { return Err("read section".into()); }
        if d2.is_empty() { return Err("read memory section".into()); }

        let len = d1.len().min(d2.len());
        let mut i = 0;
        Ok(core::iter::from_fn(move || {
            while i < len && d1[i] == d2[i] { i += 1; }
            let diffpos = i;
            let mut size = 0usize;
            while i < len && d1[i] != d2[i] {
                i += 1;
                size += 1;
            }
            if i >= len && 0 == size {
                None
            } else {
                Some((diffpos, size))
            }
        }))
    }

    pub fn compare_export<'a>(&'a mut self, mem: &'a mut Self) -> Result<impl Iterator<Item=usize> + 'a, String> {
        let dd = *self.get_data_dir(IMAGE_DIRECTORY_ENTRY_EXPORT).ok_or("get export dir")?;
        let iet = *self.ref_rva::<IMAGE_EXPORT_DIRECTORY>(dd.VirtualAddress).ok_or("get export dir")?;
        let count = iet.NumberOfFunctions as usize;
        let fd = self.data_slice(iet.AddressOfFunctions, count).ok_or("get functions")?;
        let md = mem.data_slice(iet.AddressOfFunctions, count).ok_or("get memory functions")?;
        let mut i = 0;
        Ok(core::iter::from_fn(move || unsafe {
            while i < count {
                let n = i; i += 1;
                let rva = *fd.as_ptr().add(n * 4).cast::<u32>();
                let mva = *md.as_ptr().add(n * 4).cast::<u32>();
                if rva != mva {
                    return Some(n);
                }
            }
            None
        }))
    }
}