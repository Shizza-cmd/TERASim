//! Runtime patch for the unpacked TERA 115.02 client.
//!
//! `ToGame_SelectCharacter_Create` (`0x1667CC0`) only sends `C_CAN_CREATE_USER`.
//! The lobby tick (`0x18B1740`) is what copies a queued panel into `lobby+0x74`.
//! After the button runs, the tick queues `RaceScene` (`lobby+0x18`) once, and
//! only while the character list is the active panel.

use std::collections::HashSet;
use std::ffi::c_void;
use std::mem::size_of;
use std::time::{Duration, Instant};

use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Decoder, DecoderOptions, FlowControl, Instruction,
    InstructionBlock,
};
use windows::Win32::Foundation::{CloseHandle, GetLastError};
use windows::Win32::System::Diagnostics::Debug::{
    FlushInstructionCache, ReadProcessMemory, WriteProcessMemory,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualProtectEx, VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT,
    MEM_FREE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
};
use windows::Win32::System::ProcessStatus::{
    K32EnumProcessModulesEx, K32GetModuleFileNameExW, K32GetModuleInformation, MODULEINFO,
    LIST_MODULES_ALL,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE,
};

const BUTTON_RVA: u64 = 0x1667CC0;
const TICK_RVA: u64 = 0x18B1740;
const TICK_PROLOGUE: [u8; 5] = [0x48, 0x89, 0x5C, 0x24, 0x10];

pub fn pids(name: &str) -> HashSet<u32> {
    let mut found = HashSet::new();
    let Ok(snapshot) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }) else {
        return found;
    };
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..PROCESSENTRY32W::default()
    };
    if unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok() {
        loop {
            if exe_name(&entry).eq_ignore_ascii_case(name) {
                found.insert(entry.th32ProcessID);
            }
            if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
                break;
            }
        }
    }
    let _ = unsafe { CloseHandle(snapshot) };
    found
}

pub fn wait_for_new(name: &str, existing: &HashSet<u32>, timeout: Duration) -> Result<u32, String> {
    let started = Instant::now();
    loop {
        for pid in pids(name) {
            if !existing.contains(&pid) {
                return Ok(pid);
            }
        }
        if started.elapsed() >= timeout {
            return Err(format!("{name} не появился"));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Wait until WinLicense has decrypted the image, then hook the create button
/// and the lobby tick. The executable on disk is left untouched.
pub fn arm(pid: u32) -> Result<(), String> {
    let access = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION;
    let process = unsafe { OpenProcess(access, false, pid) }
        .map_err(|err| format!("OpenProcess {pid}: {err}"))?;
    let result = arm_process(process, pid);
    let _ = unsafe { CloseHandle(process) };
    result
}

fn arm_process(process: windows::Win32::Foundation::HANDLE, pid: u32) -> Result<(), String> {
    let module = wait_module(process, pid)?;
    let tick = module.base.wrapping_add(TICK_RVA);
    let button = module.base.wrapping_add(BUTTON_RVA);
    let tick_bytes = wait_unpacked(process, tick)?;
    let button_head = read_exact(process, button, 32)?;
    let tick_done = tick_bytes.first() == Some(&0xE9);
    let button_done = button_head.first() == Some(&0xE9);
    if tick_done && button_done {
        return Ok(());
    }
    if tick_done || button_done {
        return Err("патч оборвался на предыдущем запуске, перезапустите клиент".into());
    }
    if tick_bytes.as_slice() != TICK_PROLOGUE {
        return Err(format!(
            "тик лобби {:02x?}, ожидался пролог 115.02",
            tick_bytes
        ));
    }
    let (prologue, stolen) = take_prologue(&button_head, button)?;

    let cave = allocate_near(process, module.end, tick, 0x1000)?;
    let button_code = cave.wrapping_add(0x100);
    let tick_code = cave.wrapping_add(0x200);
    let button_stub = button_stub(button_code, cave, button, &prologue, stolen)?;
    let tick_stub = tick_stub(tick_code, cave, tick)?;

    write_bytes(process, button_code, &button_stub)?;
    write_bytes(process, tick_code, &tick_stub)?;
    jump(process, tick, &TICK_PROLOGUE, tick_code)?;
    jump(process, button, &button_head[..stolen], button_code)?;
    Ok(())
}

struct Module {
    base: u64,
    end: u64,
}

fn wait_module(process: windows::Win32::Foundation::HANDLE, pid: u32) -> Result<Module, String> {
    let started = Instant::now();
    let mut detail = String::from("процесс ещё без образа");
    loop {
        if let Some(module) = image_from_peb(process) {
            return Ok(module);
        }
        match find_module(process, "TERA.exe") {
            Ok(Some(module)) => return Ok(module),
            Ok(None) => {}
            Err(err) => detail = err,
        }
        if started.elapsed() >= Duration::from_secs(30) {
            return Err(format!("модуль TERA.exe в процессе {pid} не найден: {detail}"));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Main image base from the process PEB. The kernel writes it when the image
/// is mapped, before the loader publishes the module list that PSAPI reads.
fn image_from_peb(process: windows::Win32::Foundation::HANDLE) -> Option<Module> {
    #[repr(C)]
    struct ProcessBasic {
        exit_status: isize,
        peb: *mut c_void,
        affinity: usize,
        base_priority: i32,
        pid: usize,
        parent_pid: usize,
    }
    #[link(name = "ntdll")]
    extern "system" {
        fn NtQueryInformationProcess(
            process: *mut c_void,
            class: u32,
            info: *mut ProcessBasic,
            len: u32,
            retlen: *mut u32,
        ) -> i32;
    }

    let mut info = ProcessBasic {
        exit_status: 0,
        peb: std::ptr::null_mut(),
        affinity: 0,
        base_priority: 0,
        pid: 0,
        parent_pid: 0,
    };
    let mut retlen = 0u32;
    let status = unsafe {
        NtQueryInformationProcess(
            process.0,
            0,
            &mut info,
            size_of::<ProcessBasic>() as u32,
            &mut retlen,
        )
    };
    if status < 0 || info.peb.is_null() {
        return None;
    }
    let peb = info.peb as u64;
    let base = read_u64(process, peb.wrapping_add(0x10)).ok()?;
    if base == 0 {
        return None;
    }
    let e_lfanew = read_u32(process, base.wrapping_add(0x3C)).ok()? as u64;
    let size = read_u32(process, base.wrapping_add(e_lfanew).wrapping_add(80)).ok()?;
    if !(0x10_0000..0x1000_0000).contains(&size) {
        return None;
    }
    Some(Module {
        base,
        end: base.wrapping_add(size as u64),
    })
}

fn read_u64(process: windows::Win32::Foundation::HANDLE, address: u64) -> Result<u64, String> {
    let bytes = read_exact(process, address, 8)?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u32(process: windows::Win32::Foundation::HANDLE, address: u64) -> Result<u32, String> {
    let bytes = read_exact(process, address, 4)?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn find_module(process: windows::Win32::Foundation::HANDLE, name: &str) -> Result<Option<Module>, String> {
    let mut modules = [windows::Win32::Foundation::HMODULE::default(); 256];
    let mut needed = 0u32;
    let ok = unsafe {
        K32EnumProcessModulesEx(
            process,
            modules.as_mut_ptr(),
            (modules.len() * size_of::<windows::Win32::Foundation::HMODULE>()) as u32,
            &mut needed,
            LIST_MODULES_ALL.0,
        )
    };
    if !ok.as_bool() {
        let err = unsafe { GetLastError() };
        return Err(format!("список модулей недоступен ({})", err.0));
    }
    let count = (needed as usize / size_of::<windows::Win32::Foundation::HMODULE>()).min(modules.len());
    for module in modules.into_iter().take(count) {
        let mut file = [0u16; 260];
        let wrote = unsafe { K32GetModuleFileNameExW(Some(process), Some(module), &mut file) };
        if wrote == 0 {
            continue;
        }
        let path = String::from_utf16_lossy(&file[..wrote as usize]);
        let exe = path.rsplit(['\\', '/']).next().unwrap_or("");
        if !exe.eq_ignore_ascii_case(name) {
            continue;
        }
        let mut info = MODULEINFO::default();
        let info_ok = unsafe {
            K32GetModuleInformation(process, module, &mut info, size_of::<MODULEINFO>() as u32)
        };
        if !info_ok.as_bool() || info.lpBaseOfDll.is_null() {
            return Err(format!("база {name} не прочитана"));
        }
        let base = info.lpBaseOfDll as u64;
        return Ok(Some(Module {
            base,
            end: base.wrapping_add(info.SizeOfImage as u64),
        }));
    }
    Ok(None)
}

fn wait_unpacked(process: windows::Win32::Foundation::HANDLE, tick: u64) -> Result<Vec<u8>, String> {
    let started = Instant::now();
    loop {
        if let Ok(bytes) = read_exact(process, tick, TICK_PROLOGUE.len()) {
            if bytes.as_slice() == TICK_PROLOGUE || bytes.first() == Some(&0xE9) {
                return Ok(bytes);
            }
        }
        if started.elapsed() >= Duration::from_secs(90) {
            return Err("клиент не распаковался: пролог тика лобби не совпал".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn take_prologue(bytes: &[u8], ip: u64) -> Result<(Vec<Instruction>, usize), String> {
    let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
    let mut insns = Vec::new();
    let mut stolen = 0usize;
    while stolen < 5 {
        let insn = decoder.decode();
        if insn.is_invalid() || insn.len() == 0 || stolen + insn.len() > bytes.len() {
            return Err(format!("пролог кнопки не разобран: {:02x?}", &bytes[..bytes.len().min(16)]));
        }
        let flow = insn.flow_control();
        if !matches!(
            flow,
            FlowControl::Next
                | FlowControl::Call
                | FlowControl::IndirectCall
                | FlowControl::ConditionalBranch
                | FlowControl::UnconditionalBranch
                | FlowControl::IndirectBranch
                | FlowControl::Return
        ) {
            return Err(format!(
                "пролог кнопки прерывается на {:x}",
                insn.ip().wrapping_sub(ip.wrapping_sub(BUTTON_RVA))
            ));
        }
        stolen += insn.len();
        insns.push(insn);
        if !matches!(
            flow,
            FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall | FlowControl::ConditionalBranch
        ) {
            break;
        }
    }
    if stolen < 5 {
        return Err(format!("пролог кнопки короче прыжка: {:02x?}", &bytes[..stolen]));
    }
    Ok((insns, stolen))
}

fn button_stub(
    code: u64,
    flag: u64,
    site: u64,
    prologue: &[Instruction],
    stolen: usize,
) -> Result<Vec<u8>, String> {
    let mut body = prologue.to_vec();
    let back = site.wrapping_add(stolen as u64);
    body.push(Instruction::with_branch(Code::Jmp_rel32_64, back).map_err(|err| err.to_string())?);
    let mut stub = button_prefix(code, flag)?.to_vec();
    stub.extend(relocate(&body, code.wrapping_add(stub.len() as u64))?);
    Ok(stub)
}

fn button_prefix(code: u64, flag: u64) -> Result<[u8; 7], String> {
    let mut bytes = [0xC6, 0x05, 0, 0, 0, 0, 0x01];
    let disp = rel32(flag, code.wrapping_add(7))?;
    bytes[2..6].copy_from_slice(&disp.to_le_bytes());
    Ok(bytes)
}

fn relocate(insns: &[Instruction], ip: u64) -> Result<Vec<u8>, String> {
    let encoded = BlockEncoder::encode(64, InstructionBlock::new(insns, ip), BlockEncoderOptions::NONE)
        .map_err(|err| err.to_string())?;
    Ok(encoded.code_buffer)
}

fn tick_stub(code: u64, flag: u64, site: u64) -> Result<Vec<u8>, String> {
    let mut stub = Vec::new();
    stub.extend_from_slice(&[0x80, 0x3D]);
    let next = code.wrapping_add(stub.len() as u64 + 5);
    stub.extend_from_slice(&rel32(flag, next)?.to_le_bytes());
    stub.push(0x01);
    let skip_flag = stub.len();
    stub.extend_from_slice(&[0x75, 0x00]);
    stub.extend_from_slice(&[0x83, 0xB9, 0x7C, 0x00, 0x00, 0x00, 0x00]);
    let skip_pending = stub.len();
    stub.extend_from_slice(&[0x75, 0x00]);
    stub.extend_from_slice(&[0x48, 0x8B, 0x81, 0x74, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0x48, 0x3B, 0x81, 0x10, 0x00, 0x00, 0x00]);
    let skip_panel = stub.len();
    stub.extend_from_slice(&[0x75, 0x00]);
    stub.extend_from_slice(&[0x48, 0x8B, 0x81, 0x18, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0x48, 0x85, 0xC0]);
    let skip_race = stub.len();
    stub.extend_from_slice(&[0x74, 0x00]);
    stub.extend_from_slice(&[0xC6, 0x05]);
    let next = code.wrapping_add(stub.len() as u64 + 5);
    stub.extend_from_slice(&rel32(flag, next)?.to_le_bytes());
    stub.push(0x00);
    stub.extend_from_slice(&[0x48, 0x89, 0x81, 0x80, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0xC7, 0x81, 0x7C, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0xC7, 0x81, 0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xBF]);
    let original = stub.len();
    for at in [skip_flag, skip_pending, skip_panel, skip_race] {
        let rel = original - (at + 2);
        if rel >= 128 {
            return Err("переход в пещере тика не влезает".into());
        }
        stub[at + 1] = rel as u8;
    }
    stub.extend_from_slice(&TICK_PROLOGUE);
    stub.push(0xE9);
    let next = code.wrapping_add(stub.len() as u64 + 4);
    let disp = rel32(site.wrapping_add(TICK_PROLOGUE.len() as u64), next)?;
    stub.extend_from_slice(&disp.to_le_bytes());
    Ok(stub)
}

fn rel32(target: u64, next: u64) -> Result<i32, String> {
    let disp = target as i128 - next as i128;
    i32::try_from(disp).map_err(|_| "прыжок не влезает в rel32".into())
}

fn jump(
    process: windows::Win32::Foundation::HANDLE,
    site: u64,
    expected: &[u8],
    target: u64,
) -> Result<(), String> {
    let mut replacement = vec![0x90u8; expected.len()];
    replacement[0] = 0xE9;
    let disp = rel32(target, site.wrapping_add(5))?;
    replacement[1..5].copy_from_slice(&disp.to_le_bytes());
    let current = read_exact(process, site, expected.len())?;
    if current.as_slice() != expected {
        return Err(format!("байт по {site:x} уже другие"));
    }
    let mut old = PAGE_EXECUTE_READWRITE;
    unsafe { VirtualProtectEx(process, site as *const _, replacement.len(), PAGE_EXECUTE_READWRITE, &mut old) }
        .map_err(|err| format!("protect {site:x}: {err}"))?;
    let wrote = write_bytes(process, site, &replacement);
    let mut restored = PAGE_EXECUTE_READWRITE;
    let _ = unsafe { VirtualProtectEx(process, site as *const _, replacement.len(), old, &mut restored) };
    wrote?;
    let _ = unsafe { FlushInstructionCache(process, Some(site as *const _), replacement.len()) };
    Ok(())
}

fn write_bytes(process: windows::Win32::Foundation::HANDLE, address: u64, bytes: &[u8]) -> Result<(), String> {
    let mut written = 0usize;
    unsafe {
        WriteProcessMemory(
            process,
            address as *const _,
            bytes.as_ptr() as *const c_void,
            bytes.len(),
            Some(&mut written),
        )
    }
    .map_err(|err| format!("запись {address:x}: {err}"))?;
    if written != bytes.len() {
        return Err(format!("запись {address:x} оборвалась"));
    }
    Ok(())
}

fn read_exact(process: windows::Win32::Foundation::HANDLE, address: u64, len: usize) -> Result<Vec<u8>, String> {
    let mut bytes = vec![0u8; len];
    let mut got = 0usize;
    unsafe {
        ReadProcessMemory(
            process,
            address as *const _,
            bytes.as_mut_ptr() as *mut c_void,
            bytes.len(),
            Some(&mut got),
        )
    }
    .map_err(|_| format!("чтение {address:x} не удалось"))?;
    if got != len {
        return Err(format!("чтение {address:x} неполное"));
    }
    Ok(bytes)
}

fn allocate_near(
    process: windows::Win32::Foundation::HANDLE,
    hint: u64,
    site: u64,
    size: usize,
) -> Result<u64, String> {
    if let Some(address) = scan_free(process, hint, site, size, true) {
        return Ok(address);
    }
    if let Some(address) = scan_free(process, hint, site, size, false) {
        return Ok(address);
    }
    Err("рядом с клиентом нет свободной страницы".into())
}

fn scan_free(
    process: windows::Win32::Foundation::HANDLE,
    hint: u64,
    site: u64,
    size: usize,
    forward: bool,
) -> Option<u64> {
    let mut address = hint & !0xFFFF;
    for _ in 0..2048 {
        let mut info = MEMORY_BASIC_INFORMATION::default();
        let wrote = unsafe {
            VirtualQueryEx(
                process,
                Some(address as *const _),
                &mut info,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if wrote == 0 || info.RegionSize == 0 {
            return None;
        }
        let base = info.BaseAddress as u64;
        let next = if forward {
            base.saturating_add(info.RegionSize as u64)
        } else {
            base.saturating_sub(1)
        };
        if info.State == MEM_FREE && info.RegionSize >= size {
            let chosen = (base.saturating_add(0xFFFF)) & !0xFFFF;
            let room = base.saturating_add(info.RegionSize as u64).saturating_sub(chosen);
            if chosen >= base && room as usize >= size && in_rel32(site, chosen) {
                let got = unsafe {
                    VirtualAllocEx(
                        process,
                        Some(chosen as *const _),
                        size,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE,
                    )
                };
                if got as u64 == chosen {
                    return Some(chosen);
                }
            }
        }
        if forward {
            if next <= address {
                return None;
            }
            address = next;
        } else if base == 0 {
            return None;
        } else {
            address = base.saturating_sub(1) & !0xFFFF;
            if address >= base {
                return None;
            }
        }
    }
    None
}

fn in_rel32(site: u64, cave: u64) -> bool {
    cave.abs_diff(site) < 0x7FFF_0000
}

fn exe_name(entry: &PROCESSENTRY32W) -> String {
    let end = entry.szExeFile.iter().position(|unit| *unit == 0).unwrap_or(entry.szExeFile.len());
    String::from_utf16_lossy(&entry.szExeFile[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn button_store_points_at_the_flag() {
        let flag = 0x10_000u64;
        let code = 0x10_100u64;
        let bytes = button_prefix(code, flag).unwrap();
        let disp = i32::from_le_bytes(bytes[2..6].try_into().unwrap());
        assert_eq!(code.wrapping_add(7).wrapping_add(disp as i64 as u64), flag);
        assert_eq!(bytes[6], 1);
    }

    #[test]
    fn tick_returns_to_the_instruction_after_the_prologue() {
        let code = 0x141900000u64;
        let flag = code;
        let site = 0x1418B1740u64;
        let stub = tick_stub(code, flag, site).unwrap();
        let mut decoder = Decoder::with_ip(64, &stub, code, DecoderOptions::NONE);
        let mut last_jump = 0u64;
        let mut saw_prologue = false;
        while decoder.can_decode() {
            let insn = decoder.decode();
            if insn.is_invalid() {
                break;
            }
            let at = (insn.ip() - code) as usize;
            if at + 5 <= stub.len() && stub[at..at + 5] == TICK_PROLOGUE {
                saw_prologue = true;
            }
            if insn.mnemonic() == iced_x86::Mnemonic::Jmp {
                last_jump = insn.near_branch_target();
            }
        }
        assert!(saw_prologue);
        assert_eq!(last_jump, site + TICK_PROLOGUE.len() as u64);
    }

    #[test]
    fn prologue_keeps_whole_instructions() {
        let ip = 0x1416_67CC0u64;
        let bytes = [0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20];
        let (insns, stolen) = take_prologue(&bytes, ip).unwrap();
        assert_eq!(stolen, 5);
        assert_eq!(insns.len(), 1);
        let stub = button_stub(0x1419_00100, 0x1419_00000, ip, &insns, stolen).unwrap();
        let mut decoder = Decoder::with_ip(64, &stub, 0x1419_00100, DecoderOptions::NONE);
        let store = decoder.decode();
        assert_eq!(store.mnemonic(), iced_x86::Mnemonic::Mov);
        let copied = decoder.decode();
        assert_eq!(copied.len(), 5);
        let back = decoder.decode();
        assert_eq!(back.near_branch_target(), ip + stolen as u64);
    }

    #[test]
    fn prologue_relocates_the_create_button_call() {
        // sub rsp, 28h; call +0x224207. The call starts four bytes in, so the
        // hook has to carry it along and keep its target.
        let ip = 0x141667CC0u64;
        let bytes = [0x48, 0x83, 0xEC, 0x28, 0xE8, 0x07, 0x42, 0x22, 0x00, 0x48];
        let (insns, stolen) = take_prologue(&bytes, ip).unwrap();
        assert_eq!(stolen, 9);
        let stub = button_stub(0x141900100, 0x141900000, ip, &insns, stolen).unwrap();
        let mut decoder = Decoder::with_ip(64, &stub, 0x141900100, DecoderOptions::NONE);
        let mut call_target = None;
        let mut back = None;
        while decoder.can_decode() {
            let insn = decoder.decode();
            if insn.is_invalid() {
                break;
            }
            if insn.flow_control() == FlowControl::Call {
                call_target = Some(insn.near_branch_target());
            }
            if insn.flow_control() == FlowControl::UnconditionalBranch {
                back = Some(insn.near_branch_target());
            }
        }
        assert_eq!(call_target, Some(ip + 9 + 0x224207));
        assert_eq!(back, Some(ip + stolen as u64));
    }

    #[test]
    fn size_of_image_is_at_the_pe32_plus_offset() {
        let bytes = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
        let magic = u16::from_le_bytes(bytes[e_lfanew + 24..e_lfanew + 26].try_into().unwrap());
        assert_eq!(magic, 0x20B, "launcher must be 64-bit to patch TERA.exe");
        let size = u32::from_le_bytes(bytes[e_lfanew + 80..e_lfanew + 84].try_into().unwrap());
        assert!(size > 0x1000);
    }
}
