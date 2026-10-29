use std::ffi::c_void;

const PROCESS_VM_READ: u32 = 0x0010;
const PROCESS_VM_WRITE: u32 = 0x0020;
const PROCESS_VM_OPERATION: u32 = 0x0008;
const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_FREE: u32 = 0x10000;
const PAGE_GUARD: u32 = 0x100;
const LIST_MODULES_ALL: u32 = 0x03;
const TH32CS_SNAPPROCESS: u32 = 0x00000002;

#[repr(C)]
struct MemoryBasicInformation {
    base: u64,
    allocation_base: u64,
    allocation_protect: u32,
    alignment: u32,
    region_size: u64,
    state: u32,
    protect: u32,
    kind: u32,
    alignment2: u32,
}

#[repr(C)]
struct ModuleInfo {
    base: u64,
    size: u32,
    _pad: u32,
    entry: u64,
}

#[repr(C)]
struct ProcessEntry32 {
    size: u32,
    cnt_usage: u32,
    pid: u32,
    default_heap_id: usize,
    module_id: u32,
    cnt_threads: u32,
    parent_pid: u32,
    pri_class_base: i32,
    flags: u32,
    exe_file: [u8; 260],
}

#[link(name = "kernel32")]
extern "system" {
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
    fn CloseHandle(handle: *mut c_void) -> i32;
    fn ReadProcessMemory(
        process: *mut c_void,
        address: u64,
        buffer: *mut u8,
        size: usize,
        read: *mut usize,
    ) -> i32;
    fn WriteProcessMemory(
        process: *mut c_void,
        address: u64,
        buffer: *const u8,
        size: usize,
        written: *mut usize,
    ) -> i32;
    fn VirtualProtectEx(
        process: *mut c_void,
        address: u64,
        size: usize,
        protect: u32,
        old: *mut u32,
    ) -> i32;
    fn VirtualAllocEx(
        process: *mut c_void,
        address: u64,
        size: usize,
        kind: u32,
        protect: u32,
    ) -> u64;
    fn VirtualQueryEx(
        process: *mut c_void,
        address: u64,
        info: *mut MemoryBasicInformation,
        length: usize,
    ) -> usize;
    fn K32EnumProcessModulesEx(
        process: *mut c_void,
        modules: *mut u64,
        bytes: u32,
        needed: *mut u32,
        filter: u32,
    ) -> i32;
    fn K32GetModuleFileNameExW(
        process: *mut c_void,
        module: u64,
        name: *mut u16,
        size: u32,
    ) -> u32;
    fn K32GetModuleInformation(
        process: *mut c_void,
        module: u64,
        info: *mut ModuleInfo,
        size: u32,
    ) -> i32;
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> *mut c_void;
    fn Process32First(snapshot: *mut c_void, entry: *mut ProcessEntry32) -> i32;
    fn Process32Next(snapshot: *mut c_void, entry: *mut ProcessEntry32) -> i32;
}

pub struct Region {
    pub base: u64,
    pub executable: bool,
    pub bytes: Vec<u8>,
}

pub struct Image {
    pub base: u64,
    pub end: u64,
    pub regions: Vec<Region>,
}

pub fn find_pid(name: &str) -> Result<u32, String> {
    let wanted = name.to_ascii_lowercase();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot.is_null() || snapshot == (-1isize as *mut c_void) {
            return Err("process snapshot failed".into());
        }
        let mut entry = std::mem::zeroed::<ProcessEntry32>();
        entry.size = std::mem::size_of::<ProcessEntry32>() as u32;
        let mut ok = Process32First(snapshot, &mut entry);
        let mut found = None;
        while ok != 0 {
            let end = entry.exe_file.iter().position(|byte| *byte == 0).unwrap_or(entry.exe_file.len());
            let exe = String::from_utf8_lossy(&entry.exe_file[..end]).to_ascii_lowercase();
            if exe == wanted || exe == format!("{wanted}.exe") {
                found = Some(entry.pid);
                break;
            }
            ok = Process32Next(snapshot, &mut entry);
        }
        CloseHandle(snapshot);
        found.ok_or_else(|| format!("process {name} is not running"))
    }
}

pub fn read_bytes(pid: u32, address: u64, len: usize) -> Result<Vec<u8>, String> {
    unsafe {
        let process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid);
        if process.is_null() {
            return Err(format!("OpenProcess {pid} failed"));
        }
        let mut bytes = vec![0u8; len];
        let mut got = 0usize;
        let ok = ReadProcessMemory(process, address, bytes.as_mut_ptr(), bytes.len(), &mut got);
        CloseHandle(process);
        if ok == 0 || got == 0 {
            return Err(format!("read {address:x} failed"));
        }
        bytes.truncate(got);
        Ok(bytes)
    }
}

pub fn patch(pid: u32, address: u64, expected: &[u8], replacement: &[u8]) -> Result<(), String> {
    if expected.len() != replacement.len() {
        return Err("patch length mismatch".into());
    }
    unsafe {
        let access = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION;
        let process = OpenProcess(access, 0, pid);
        if process.is_null() {
            return Err(format!("OpenProcess {pid} failed"));
        }
        let mut current = vec![0u8; expected.len()];
        let mut got = 0usize;
        let read = ReadProcessMemory(process, address, current.as_mut_ptr(), current.len(), &mut got);
        if read == 0 || got != expected.len() {
            CloseHandle(process);
            return Err(format!("read {address:x} failed"));
        }
        if current != expected {
            CloseHandle(process);
            return Err(format!("bytes at {address:x} are not the alive check"));
        }
        let mut old = 0u32;
        if VirtualProtectEx(process, address, replacement.len(), PAGE_EXECUTE_READWRITE, &mut old) == 0 {
            CloseHandle(process);
            return Err(format!("protect {address:x} failed"));
        }
        let mut wrote = 0usize;
        let ok = WriteProcessMemory(process, address, replacement.as_ptr(), replacement.len(), &mut wrote);
        let mut restored = 0u32;
        VirtualProtectEx(process, address, replacement.len(), old, &mut restored);
        CloseHandle(process);
        if ok == 0 || wrote != replacement.len() {
            return Err(format!("write {address:x} failed"));
        }
        Ok(())
    }
}

/// Allocate executable memory close enough to `hint` for a rel32 jump.
pub fn allocate_near(pid: u32, hint: u64, size: usize) -> Result<u64, String> {
    unsafe {
        let access = PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION;
        let process = OpenProcess(access, 0, pid);
        if process.is_null() {
            return Err(format!("OpenProcess {pid} failed"));
        }
        let mut address = hint & !0xFFFF;
        for _ in 0..512 {
            let mut info = std::mem::zeroed::<MemoryBasicInformation>();
            let wrote = VirtualQueryEx(
                process,
                address,
                &mut info,
                std::mem::size_of::<MemoryBasicInformation>(),
            );
            if wrote == 0 || info.region_size == 0 {
                break;
            }
            let next = info.base.saturating_add(info.region_size);
            if info.state == MEM_FREE && info.region_size as usize >= size {
                let chosen = (info.base + 0xFFFF) & !0xFFFF;
                let room = info.base.saturating_add(info.region_size).saturating_sub(chosen);
                if chosen >= info.base && room as usize >= size {
                    let got = VirtualAllocEx(
                        process,
                        chosen,
                        size,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE,
                    );
                    if got == chosen {
                        CloseHandle(process);
                        return Ok(got);
                    }
                }
            }
            if next <= address {
                break;
            }
            address = next;
        }
        CloseHandle(process);
        Err(format!("no free page near {hint:x}"))
    }
}

pub fn load_module(pid: u32, module_suffix: &str) -> Result<Image, String> {
    unsafe {
        let process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid);
        if process.is_null() {
            return Err(format!("OpenProcess {pid} failed"));
        }
        let image = read_module(process, module_suffix);
        CloseHandle(process);
        image
    }
}

unsafe fn read_module(process: *mut c_void, module_suffix: &str) -> Result<Image, String> {
    let mut modules = [0u64; 512];
    let mut needed = 0u32;
    if K32EnumProcessModulesEx(
        process,
        modules.as_mut_ptr(),
        (modules.len() * std::mem::size_of::<u64>()) as u32,
        &mut needed,
        LIST_MODULES_ALL,
    ) == 0
    {
        return Err("module list failed".into());
    }
    let count = (needed as usize / std::mem::size_of::<u64>()).min(modules.len());
    let mut name = [0u16; 520];
    let suffix = module_suffix.to_ascii_lowercase();
    let mut chosen: Option<(u64, u64)> = None;
    for slot in modules.iter().take(count) {
        name.fill(0);
        if K32GetModuleFileNameExW(process, *slot, name.as_mut_ptr(), name.len() as u32) == 0 {
            continue;
        }
        let len = name.iter().position(|unit| *unit == 0).unwrap_or(name.len());
        let path = String::from_utf16_lossy(&name[..len]).to_ascii_lowercase();
        if !path.ends_with(&suffix) {
            continue;
        }
        let mut info = std::mem::zeroed::<ModuleInfo>();
        if K32GetModuleInformation(
            process,
            *slot,
            &mut info,
            std::mem::size_of::<ModuleInfo>() as u32,
        ) == 0
        {
            continue;
        }
        chosen = Some((info.base, info.base + info.size as u64));
        eprintln!("module {path} {:x}..{:x}", info.base, info.base + info.size as u64);
        break;
    }
    let Some((base, end)) = chosen else {
        return Err(format!("module {module_suffix} was not found"));
    };

    let mut regions = Vec::new();
    let mut address = base;
    while address < end {
        let mut info = std::mem::zeroed::<MemoryBasicInformation>();
        let wrote = VirtualQueryEx(
            process,
            address,
            &mut info,
            std::mem::size_of::<MemoryBasicInformation>(),
        );
        if wrote == 0 || info.region_size == 0 {
            break;
        }
        let next = info.base.saturating_add(info.region_size);
        if next <= address {
            break;
        }
        address = next;
        let bits = info.protect & 0xFF;
        let readable = matches!(bits, 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80);
        if info.state != MEM_COMMIT || !readable || info.protect & PAGE_GUARD != 0 {
            continue;
        }
        if info.base >= end || info.base + info.region_size <= base {
            continue;
        }
        let start = info.base.max(base);
        let stop = (info.base + info.region_size).min(end);
        let mut bytes = vec![0u8; (stop - start) as usize];
        let mut got = 0usize;
        if ReadProcessMemory(process, start, bytes.as_mut_ptr(), bytes.len(), &mut got) == 0 || got == 0 {
            continue;
        }
        bytes.truncate(got);
        let executable = matches!(bits, 0x20 | 0x40 | 0x80);
        regions.push(Region {
            base: start,
            executable,
            bytes,
        });
    }
    Ok(Image { base, end, regions })
}

impl Image {
    pub fn contains_exec(&self, address: u64) -> bool {
        self.regions.iter().any(|region| {
            region.executable
                && address >= region.base
                && address < region.base + region.bytes.len() as u64
        })
    }

    pub fn read_at(&self, addr: u64, len: usize) -> Option<&[u8]> {
        for region in &self.regions {
            let region_end = region.base + region.bytes.len() as u64;
            if addr >= region.base && addr < region_end {
                let off = (addr - region.base) as usize;
                let take = len.min(region.bytes.len() - off);
                return Some(&region.bytes[off..off + take]);
            }
        }
        None
    }
}
