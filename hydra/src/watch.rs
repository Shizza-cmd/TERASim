use std::ffi::c_void;
use std::io::{self, Write};

use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};

use crate::process::{self, load_module};

const SNAPTHREAD: u32 = 0x00000004;
const THREAD_ACCESS: u32 = 0x001FFFFF;
const CONTEXT_ALL: u32 = 0x0010001F;
const DBG_CONTINUE: u32 = 0x00010002;
const DBG_EXCEPTION_NOT_HANDLED: u32 = 0x80010001;
const EXCEPTION_BREAKPOINT: u32 = 0x80000003;
const EXCEPTION_SINGLE_STEP: u32 = 0x80000004;
const CREATE_THREAD: u32 = 2;
const CREATE_PROCESS: u32 = 3;
const EXIT_PROCESS: u32 = 5;
const EXCEPTION: u32 = 1;

#[repr(C)]
struct DebugEvent {
    code: u32,
    pid: u32,
    tid: u32,
    _pad: u32,
    info: [u8; 160],
}

#[repr(C)]
struct ThreadEntry {
    size: u32,
    usage: u32,
    tid: u32,
    owner: u32,
    base_pri: i32,
    delta_pri: i32,
    flags: u32,
}

#[link(name = "kernel32")]
extern "system" {
    fn GetLastError() -> u32;
    fn OpenThread(access: u32, inherit: i32, tid: u32) -> *mut c_void;
    fn CloseHandle(handle: *mut c_void) -> i32;
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> *mut c_void;
    fn Thread32First(snapshot: *mut c_void, entry: *mut ThreadEntry) -> i32;
    fn Thread32Next(snapshot: *mut c_void, entry: *mut ThreadEntry) -> i32;
    fn GetThreadContext(thread: *mut c_void, context: *mut u8) -> i32;
    fn SetThreadContext(thread: *mut c_void, context: *const u8) -> i32;
    fn DebugActiveProcess(pid: u32) -> i32;
    fn DebugActiveProcessStop(pid: u32) -> i32;
    fn DebugSetProcessKillOnExit(kill: i32) -> i32;
    fn ReadProcessMemory(process: *mut c_void, address: u64, buffer: *mut u8, size: usize, read: *mut usize) -> i32;
    fn WriteProcessMemory(process: *mut c_void, address: u64, buffer: *const u8, size: usize, written: *mut usize) -> i32;
}

#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationProcess(process: *mut c_void, class: u32, info: *mut u8, len: u32, ret: *mut u32) -> i32;
    fn WaitForDebugEvent(event: *mut DebugEvent, millis: u32) -> i32;
    fn ContinueDebugEvent(pid: u32, tid: u32, status: u32) -> i32;
    fn CheckRemoteDebuggerPresent(process: *mut c_void, present: *mut i32) -> i32;
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
}

#[repr(C, align(16))]
struct Context {
    raw: [u8; 1232],
}

fn u64_at(ctx: &Context, offset: usize) -> u64 {
    u64::from_le_bytes(ctx.raw[offset..offset + 8].try_into().unwrap())
}

fn set_u64(ctx: &mut Context, offset: usize, value: u64) {
    ctx.raw[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn u32_at(ctx: &Context, offset: usize) -> u32 {
    u32::from_le_bytes(ctx.raw[offset..offset + 4].try_into().unwrap())
}

fn set_u32(ctx: &mut Context, offset: usize, value: u32) {
    ctx.raw[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn arm(thread: *mut c_void, slot: u64, enable: bool, step: bool) -> bool {
    let mut ctx = Context { raw: [0; 1232] };
    set_u32(&mut ctx, 48, CONTEXT_ALL);
    unsafe {
        if GetThreadContext(thread, ctx.raw.as_mut_ptr()) == 0 {
            return false;
        }
    }
    set_u64(&mut ctx, 72, slot);
    let mut dr7 = u64_at(&ctx, 112);
    dr7 &= !0x000D_0001;
    if enable {
        dr7 |= 1 | (1 << 16) | (3 << 18);
    }
    set_u64(&mut ctx, 112, dr7);
    set_u64(&mut ctx, 104, 0);
    let mut flags = u32_at(&ctx, 68);
    if step {
        flags |= 0x100;
    } else {
        flags &= !0x100;
    }
    set_u32(&mut ctx, 68, flags);
    set_u32(&mut ctx, 48, CONTEXT_ALL);
    unsafe { SetThreadContext(thread, ctx.raw.as_ptr()) != 0 }
}

fn read_context(thread: *mut c_void) -> Option<Context> {
    let mut ctx = Context { raw: [0; 1232] };
    set_u32(&mut ctx, 48, CONTEXT_ALL);
    unsafe {
        if GetThreadContext(thread, ctx.raw.as_mut_ptr()) == 0 {
            return None;
        }
    }
    Some(ctx)
}

fn threads(pid: u32) -> Vec<u32> {
    let mut found = Vec::new();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(SNAPTHREAD, 0);
        if snapshot.is_null() || snapshot == (-1isize as *mut c_void) {
            return found;
        }
        let mut entry = std::mem::zeroed::<ThreadEntry>();
        entry.size = std::mem::size_of::<ThreadEntry>() as u32;
        let mut ok = Thread32First(snapshot, &mut entry);
        while ok != 0 {
            if entry.owner == pid {
                found.push(entry.tid);
            }
            ok = Thread32Next(snapshot, &mut entry);
        }
        CloseHandle(snapshot);
    }
    found
}

fn with_thread<T>(tid: u32, body: impl FnOnce(*mut c_void) -> T) -> Option<T> {
    unsafe {
        let thread = OpenThread(THREAD_ACCESS, 0, tid);
        if thread.is_null() {
            return None;
        }
        let value = body(thread);
        CloseHandle(thread);
        Some(value)
    }
}

fn arm_all(pid: u32, slot: u64) {
    for tid in threads(pid) {
        with_thread(tid, |thread| arm(thread, slot, true, false));
    }
}

fn hide_debugger(process: *mut c_void) {
    if process.is_null() {
        return;
    }
    let mut info = [0u8; 48];
    let status = unsafe { NtQueryInformationProcess(process, 0, info.as_mut_ptr(), 48, std::ptr::null_mut()) };
    if status != 0 {
        eprintln!("peb query failed {status:x}");
        return;
    }
    let peb = u64::from_le_bytes(info[8..16].try_into().unwrap());
    let zero = [0u8];
    let mut written = 0usize;
    unsafe {
        WriteProcessMemory(process, peb + 2, zero.as_ptr(), 1, &mut written);
    }
    let mut flag = [0u8; 4];
    let mut read = 0usize;
    unsafe {
        if ReadProcessMemory(process, peb + 0xbc, flag.as_mut_ptr(), 4, &mut read) != 0 {
            let value = u32::from_le_bytes(flag) & !0x70;
            let bytes = value.to_le_bytes();
            WriteProcessMemory(process, peb + 0xbc, bytes.as_ptr(), 4, &mut written);
        }
    }
    println!("debugger flag cleared");
    let _ = io::stdout().flush();
}

fn qword(pid: u32, address: u64) -> Option<u64> {
    let bytes = process::read_bytes(pid, address, 8).ok()?;
    Some(u64::from_le_bytes(bytes[..8].try_into().ok()?))
}

pub fn run() {
    let pid = match process::find_pid("TERA.exe") {
        Ok(pid) => pid,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    unsafe {
        let process = OpenProcess(0x0400, 0, pid);
        if !process.is_null() {
            let mut present = 0i32;
            if CheckRemoteDebuggerPresent(process, &mut present) != 0 && present != 0 {
                CloseHandle(process);
                eprintln!("TERA is already being debugged. Close x64dbg completely, then run this again.");
                std::process::exit(1);
            }
            CloseHandle(process);
        }
    }
    let image = match load_module(pid, "TERA.exe") {
        Ok(image) => image,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let root = match qword(pid, image.base + 0x3122040) {
        Some(value) => value,
        None => {
            eprintln!("singleton unreadable");
            std::process::exit(1);
        }
    };
    let lobby = match qword(pid, root + 0x1e0) {
        Some(value) if value > 0x10000 => value,
        _ => {
            eprintln!("lobby missing");
            std::process::exit(1);
        }
    };
    let slot = lobby + 0x74;
    let list = qword(pid, lobby + 0x10).unwrap_or(0);
    let active = qword(pid, slot).unwrap_or(0);
    println!(
        "watching pid {pid} lobby {lobby:x} slot {slot:x} list {list:x} active {active:x}"
    );
    println!("leave the character screen and open it again");
    let _ = io::stdout().flush();

    unsafe {
        if DebugActiveProcess(pid) == 0 {
            eprintln!("attach failed {}", GetLastError());
            std::process::exit(1);
        }
        DebugSetProcessKillOnExit(0);
    }
    let mut stepping = false;
    let mut hits = 0u32;
    let started = std::time::Instant::now();
    loop {
        if started.elapsed().as_secs() > 240 || hits >= 12 {
            break;
        }
        let mut event = DebugEvent {
            code: 0,
            pid: 0,
            tid: 0,
            _pad: 0,
            info: [0; 160],
        };
        let waited = unsafe { WaitForDebugEvent(&mut event, 500) };
        if waited == 0 {
            continue;
        }
        let mut status = DBG_CONTINUE;
        match event.code {
            CREATE_PROCESS | CREATE_THREAD => {
                if event.code == CREATE_PROCESS {
                    let process = u64::from_le_bytes(event.info[8..16].try_into().unwrap()) as *mut c_void;
                    hide_debugger(process);
                }
                with_thread(event.tid, |thread| arm(thread, slot, true, false));
            }
            EXCEPTION => {
                let code = u32::from_le_bytes(event.info[0..4].try_into().unwrap());
                if code == EXCEPTION_BREAKPOINT {
                    arm_all(pid, slot);
                } else if code == EXCEPTION_SINGLE_STEP {
                    let ctx = with_thread(event.tid, read_context).flatten();
                    let dr6 = ctx.as_ref().map(|item| u64_at(item, 104)).unwrap_or(0);
                    if dr6 & 1 != 0 {
                        if let Some(ctx) = &ctx {
                            report(&image, pid, slot, ctx);
                            hits += 1;
                        }
                        with_thread(event.tid, |thread| arm(thread, slot, false, true));
                        stepping = true;
                    } else if stepping {
                        with_thread(event.tid, |thread| arm(thread, slot, true, false));
                        stepping = false;
                    } else {
                        status = DBG_EXCEPTION_NOT_HANDLED;
                    }
                } else {
                    status = DBG_EXCEPTION_NOT_HANDLED;
                }
            }
            EXIT_PROCESS => {
                unsafe { ContinueDebugEvent(event.pid, event.tid, DBG_CONTINUE); }
                eprintln!("TERA exited");
                return;
            }
            _ => {}
        }
        unsafe { ContinueDebugEvent(event.pid, event.tid, status); }
    }
    unsafe { DebugActiveProcessStop(pid); }
    println!("detached hits {hits}");
    let _ = io::stdout().flush();
}

fn report(image: &process::Image, pid: u32, slot: u64, ctx: &Context) {
    let rip = u64_at(ctx, 248);
    let rsp = u64_at(ctx, 152);
    let rva = rip.wrapping_sub(image.base);
    let text = decode_one(image, rip);
    let written = qword(pid, slot).unwrap_or(0);
    println!("HIT rva {rva:x} rip {rip:x} value {written:x} {text}");
    if let Ok(stack) = process::read_bytes(pid, rsp, 0x180) {
        let mut shown = 0;
        for chunk in stack.chunks_exact(8) {
            let ptr = u64::from_le_bytes(chunk.try_into().unwrap());
            if image.contains_exec(ptr) {
                println!("  stack {:x}", ptr.wrapping_sub(image.base));
                shown += 1;
                if shown == 8 {
                    break;
                }
            }
        }
    }
    let _ = io::stdout().flush();
}

fn decode_one(image: &process::Image, rip: u64) -> String {
    let Some(bytes) = image.read_at(rip, 16) else {
        return String::new();
    };
    let mut decoder = Decoder::with_ip(64, bytes, rip, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    decoder.decode_out(&mut instruction);
    let mut formatter = NasmFormatter::new();
    let mut text = String::new();
    formatter.format(&instruction, &mut text);
    text
}
