mod process;
mod scan;
mod watch;

use std::env;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind};
use process::{allocate_near, find_pid, load_module, patch, read_bytes};
use std::collections::HashSet;

use scan::{
    ascii_hits, bool_handlers, calls_between, data_opcodes, direct_callees, function_start,
    argument_displacement, argument_slot_stores, child_activations, functions_touching,
    pending_to_active,
    handler_immediate,
    handler_mentions, handler_slots, lobby_panel_switches, mentions_in, pointer_stores,
    self_activations, slot_copies,
    header_stores, immediate_hits, ip_rel_targets, opcode_dispatch, opcode_shifts, opcode_stubs,
    pattern_hits, print_from, print_insns, print_window, xrefs,
};

fn main() {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "help".into());
    let options = Options::parse(args);
    match command.as_str() {
        "scan" => scan(options),
        "imm" => immediates(options),
        "recv" => recv(options),
        "at" => at(options),
        "handlers" => handlers(options),
        "switch" => switchers(options),
        "panel" => panel(options),
        "copies" => copies(options),
        "refs" => refs(options),
        "both" => both(options),
        "force" => force(options),
        "activate" => activate(options),
        "list" => restore_list(options),
        "watch" => watch::run(),
        "pages" => pages(options),
        "ops" => ops(options),
        "trace" => trace(options),
        "scenes" => scenes(options),
        "slot" => slot(options),
        "same" => same_pointer(options),
        "alive" => alive(options),
        "pending" => pending(options),
        "reveal" => reveal(options),
        _ => {
            eprintln!(
                "\
hydra pages --name TERA.exe
hydra ops   --name TERA.exe
hydra trace --name TERA.exe
hydra scan --name TERA.exe [--module TERA.exe] [--opcode 41834]
hydra imm  --name TERA.exe --value 41834
hydra recv --name TERA.exe [--rva 142e750]
Reads an unpacked module from a live process and prints packet build sites,
code references, and the immediates around them."
            );
        }
    }
}

struct Options {
    pid: Option<u32>,
    name: Option<String>,
    module: String,
    opcode: Option<u16>,
    value: Option<u64>,
    rva: Option<u64>,
}

impl Options {
    fn parse(args: impl Iterator<Item = String>) -> Self {
        let mut options = Self {
            pid: None,
            name: None,
            module: "TERA.exe".into(),
            opcode: None,
            value: None,
            rva: None,
        };
        let args: Vec<String> = args.collect();
        let mut index = 0;
        while index < args.len() {
            let key = &args[index];
            let next = args.get(index + 1).cloned();
            match key.as_str() {
                "--pid" => options.pid = next.and_then(|text| text.parse().ok()),
                "--name" => options.name = next,
                "--module" => {
                    if let Some(text) = next {
                        options.module = text;
                    }
                }
                "--opcode" => options.opcode = next.and_then(|text| text.parse().ok()),
                "--value" => {
                    options.value = next.and_then(|text| parse_u64(&text))
                }
                "--rva" => options.rva = next.as_deref().and_then(parse_u64),
                _ => {}
            }
            index += 2;
        }
        options
    }

    fn pid(&self) -> Result<u32, String> {
        if let Some(pid) = self.pid {
            return Ok(pid);
        }
        let name = self.name.as_deref().unwrap_or("TERA.exe");
        find_pid(name)
    }
}

fn scan(options: Options) {
    let pid = match options.pid() {
        Ok(pid) => pid,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let image = match load_module(pid, &options.module) {
        Ok(image) => image,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    eprintln!("image {:x}..{:x}", image.base, image.end);
    let stores = header_stores(&image);
    let focus = options.opcode;
    let shown: Vec<_> = stores
        .iter()
        .filter(|store| focus.map(|opcode| store.opcode == opcode).unwrap_or(true))
        .copied()
        .collect();
    println!("header stores {} shown {}", stores.len(), shown.len());
    for store in &shown {
        let rva = store.address - image.base;
        println!(
            "store rva {:x} opcode {} length {}",
            rva, store.opcode, store.length
        );
    }
    if focus.is_none() {
        return;
    }
    let mut targets = HashSet::new();
    for store in &shown {
        let start = function_start(&image, store.address);
        println!("function {:x} for store {:x}", start, store.address);
        print_window(&image, store.address);
        let mut address = start;
        while address < store.address.saturating_add(0x28) {
            targets.insert(address);
            address += 1;
        }
    }
    let refs = xrefs(&image, &targets);
    println!("xrefs {}", refs.len());
    for xref in refs.iter().take(30) {
        println!(
            "xref {} {:x} -> {:x}",
            xref.kind,
            xref.address - image.base,
            xref.target - image.base
        );
        print_window(&image, xref.address);
    }
}

fn follow_connection(image: &process::Image, pid: u32) {
    let global = image.base.wrapping_add(0x3122040);
    let Some(root_bytes) = image.read_at(global, 8) else {
        println!("connection global unreadable");
        return;
    };
    if root_bytes.len() < 8 {
        println!("connection global short");
        return;
    }
    let root = u64::from_le_bytes(root_bytes[..8].try_into().unwrap());
    println!("connection root {root:x}");
    if root == 0 {
        return;
    }
    dump_object(image, pid, root, "root");
    if let Some(conn) = remote_u64(pid, root.wrapping_add(0x18)) {
        println!("socket object {conn:x}");
        dump_object(image, pid, conn, "socket");
    }
}

fn dump_object(image: &process::Image, pid: u32, object: u64, label: &str) {
    let Some(vt) = remote_u64(pid, object) else {
        println!("{label} vtable unreadable");
        return;
    };
    let rva = vt.wrapping_sub(image.base);
    println!("{label} vtable {vt:x} rva {rva:x}");
    let Ok(bytes) = read_bytes(pid, vt, 8 * 16) else {
        return;
    };
    for index in 0..bytes.len() / 8 {
        let slot = u64::from_le_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap());
        if !image.contains_exec(slot) {
            continue;
        }
        println!("{label} slot {index} {:x}", slot - image.base);
        if index < 8 {
            print_insns(image, slot, 18);
        }
    }
}

fn remote_u64(pid: u32, address: u64) -> Option<u64> {
    let bytes = read_bytes(pid, address, 8).ok()?;
    if bytes.len() < 8 {
        return None;
    }
    Some(u64::from_le_bytes(bytes[..8].try_into().ok()?))
}

fn panel(options: Options) {
    let image = match load(&options) {
        Ok(image) => image,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let slots = handler_slots(&image);
    let by_start: std::collections::HashMap<u64, u16> =
        slots.iter().map(|slot| (slot.address, slot.opcode)).collect();
    if let Some(pid) = options.pid {
        if let Some(root) = remote_u64(pid, image.base.wrapping_add(0x3122040)) {
            if let Some(lobby) = remote_u64(pid, root.wrapping_add(0x1e0)) {
                println!("lobby {lobby:x}");
                let needle = lobby.to_le_bytes();
                let mut sites = Vec::new();
                for region in &image.regions {
                    let bytes = &region.bytes;
                    if bytes.len() < 8 {
                        continue;
                    }
                    let mut index = 0usize;
                    while index + 8 <= bytes.len() {
                        if bytes[index..index + 8] == needle {
                            sites.push(region.base + index as u64);
                        }
                        index += 1;
                    }
                }
                println!("lobby statics {}", sites.len());
                for site in &sites {
                    println!("static {:x}", site - image.base);
                }
                let wanted: HashSet<u64> = sites.into_iter().collect();
                for region in image.regions.iter().filter(|region| region.executable) {
                    let mut decoder = iced_x86::Decoder::with_ip(
                        64,
                        &region.bytes,
                        region.base,
                        iced_x86::DecoderOptions::NONE,
                    );
                    let mut instruction = iced_x86::Instruction::default();
                    while decoder.can_decode() {
                        decoder.decode_out(&mut instruction);
                        if instruction.len() == 0 {
                            break;
                        }
                        if instruction.is_ip_rel_memory_operand()
                            && wanted.contains(&instruction.ip_rel_memory_address())
                        {
                            let start = function_start(&image, instruction.ip());
                            let opcode = by_start.get(&start).copied();
                            println!(
                                "use {:x} function {:x} opcode {}",
                                instruction.ip() - image.base,
                                start - image.base,
                                opcode
                                    .map(|code| code.to_string())
                                    .unwrap_or_else(|| "-".into())
                            );
                            print_window(&image, instruction.ip());
                        }
                    }
                }
                let mut tables = HashSet::new();
                tables.insert(image.base.wrapping_add(0x26c1720));
                tables.insert(image.base.wrapping_add(0x26c1788));
                tables.insert(image.base.wrapping_add(0x165c5d0));
                tables.insert(image.base.wrapping_add(0x165c830));
                tables.insert(image.base.wrapping_add(0x1884fa0));
                let refs = xrefs(&image, &tables);
                println!("vtable refs {}", refs.len());
                let want = image.base.wrapping_add(0x1884fa0);
                for region in image.regions.iter().filter(|region| region.executable) {
                    let mut decoder = iced_x86::Decoder::with_ip(
                        64,
                        &region.bytes,
                        region.base,
                        iced_x86::DecoderOptions::NONE,
                    );
                    let mut instruction = iced_x86::Instruction::default();
                    while decoder.can_decode() {
                        decoder.decode_out(&mut instruction);
                        if instruction.len() == 0 {
                            break;
                        }
                        if matches!(
                            instruction.mnemonic(),
                            iced_x86::Mnemonic::Call | iced_x86::Mnemonic::Jmp
                        ) && instruction.op0_kind() == iced_x86::OpKind::NearBranch64
                            && instruction.near_branch64() == want
                        {
                            println!("ctor caller {:x}", instruction.ip() - image.base);
                        }
                    }
                }
                let pattern = [0xA0u8, 0x4F, 0x88, 0x01];
                for region in &image.regions {
                    let bytes = &region.bytes;
                    let mut index = 0usize;
                    while index + 4 <= bytes.len() {
                        if bytes[index..index + 4] == pattern {
                            println!("rva dword {:x}", region.base + index as u64 - image.base);
                        }
                        index += 1;
                    }
                }
                for xref in &refs {
                    let start = function_start(&image, xref.address);
                    let opcode = by_start.get(&start).copied();
                    println!(
                        "vtable {} {:x} function {:x} opcode {} target {:x}",
                        xref.kind,
                        xref.address - image.base,
                        start - image.base,
                        opcode.map(|code| code.to_string()).unwrap_or_else(|| "-".into()),
                        xref.target - image.base
                    );
                }
            }
        }
        return;
    }
    let activations = child_activations(&image);
    println!("child activations {}", activations.len());
    for (store, disp) in &activations {
        let start = function_start(&image, *store);
        let opcode = by_start.get(&start).copied();
        println!(
            "activate +{disp:x} at {:x} function {:x} opcode {}",
            store - image.base,
            start - image.base,
            opcode.map(|code| code.to_string()).unwrap_or_else(|| "-".into())
        );
        print_window(&image, *store);
    }
    let (switches, calls) = lobby_panel_switches(&image);
    println!("lobby panel switches {}", switches.len());
    let mut setters = HashSet::new();
    for store in &switches {
        let start = function_start(&image, *store);
        setters.insert(start);
        let opcode = by_start.get(&start).copied();
        println!(
            "switch {:x} function {:x} opcode {}",
            store - image.base,
            start - image.base,
            opcode.map(|code| code.to_string()).unwrap_or_else(|| "-".into())
        );
        print_window(&image, *store);
    }
    println!("lobby calls {}", calls.len());
    let mut shown = HashSet::new();
    for (site, target) in &calls {
        if !shown.insert(*target) || !mentions_in(&image, *target, 0x140, 0x74) {
            continue;
        }
        let start = function_start(&image, *site);
        let opcode = by_start.get(&start).copied();
        println!(
            "call {:x} -> {:x} opcode {}",
            site - image.base,
            target - image.base,
            opcode.map(|code| code.to_string()).unwrap_or_else(|| "-".into())
        );
        print_insns(&image, *target, 16);
    }
    println!("setter functions {}", setters.len());
    let refs = xrefs(&image, &setters);
    let mut callers = HashSet::new();
    for xref in &refs {
        if xref.kind != "call" && xref.kind != "jmp" {
            continue;
        }
        let start = function_start(&image, xref.address);
        callers.insert(start);
        if let Some(opcode) = by_start.get(&start) {
            println!(
                "handler {opcode} calls setter {:x}",
                xref.target - image.base
            );
        }
    }
    println!("setter callers {}", callers.len());
    let caller_refs = xrefs(&image, &callers);
    for xref in &caller_refs {
        if xref.kind != "call" && xref.kind != "jmp" {
            continue;
        }
        let start = function_start(&image, xref.address);
        if let Some(opcode) = by_start.get(&start) {
            println!(
                "handler {opcode} reaches setter via {:x}",
                xref.target - image.base
            );
        }
    }
}

fn restore_list(options: Options) {
    let pid = match options.pid() {
        Ok(pid) => pid,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let image = match load_module(pid, &options.module) {
        Ok(image) => image,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let singleton = read_u64(pid, image.base.wrapping_add(0x3122040)).unwrap_or(0);
    let lobby = read_u64(pid, singleton.wrapping_add(0x1E0)).unwrap_or(0);
    let list = read_u64(pid, lobby.wrapping_add(0x10)).unwrap_or(0);
    let active = read_u64(pid, lobby.wrapping_add(0x74)).unwrap_or(0);
    if active == list {
        println!("list panel already active");
        return;
    }
    match patch(pid, lobby.wrapping_add(0x74), &active.to_le_bytes(), &list.to_le_bytes()) {
        Ok(()) => println!("list panel restored"),
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    }
}

fn activate(options: Options) {
    let pid = match options.pid() {
        Ok(pid) => pid,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let image = match load_module(pid, &options.module) {
        Ok(image) => image,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let singleton = match read_u64(pid, image.base.wrapping_add(0x3122040)) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let lobby = match read_u64(pid, singleton.wrapping_add(0x1E0)) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let list = read_u64(pid, lobby.wrapping_add(0x10)).unwrap_or(0);
    let create = read_u64(pid, lobby.wrapping_add(0x20)).unwrap_or(0);
    let active = read_u64(pid, lobby.wrapping_add(0x74)).unwrap_or(0);
    println!("lobby {lobby:x} list {list:x} create {create:x} active {active:x}");
    let vtable = read_u64(pid, create).unwrap_or(0);
    if vtable.wrapping_sub(image.base) != 0x26C1788 {
        eprintln!("create panel vtable is {vtable:x}, not the race panel");
        std::process::exit(1);
    }
    if active == create {
        println!("create panel already active");
        return;
    }
    match patch(pid, lobby.wrapping_add(0x74), &active.to_le_bytes(), &create.to_le_bytes()) {
        Ok(()) => println!("create panel is now active"),
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    }
}

fn read_u64(pid: u32, address: u64) -> Result<u64, String> {
    let bytes = read_bytes(pid, address, 8)?;
    if bytes.len() != 8 {
        return Err(format!("short read at {address:x}"));
    }
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}

fn force(options: Options) {
    let pid = match options.pid() {
        Ok(pid) => pid,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let image = match load_module(pid, &options.module) {
        Ok(image) => image,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let replacement = [0xB8u8, 0x01, 0x00, 0x00, 0x00];
    let sites: [(u64, [u8; 5]); 2] = [
        (0xEAD7CB, [0xE8, 0xB0, 0xB0, 0x9E, 0x00]),
        (0x1673478, [0xE8, 0x03, 0x54, 0x22, 0x00]),
    ];
    for (rva, expected) in sites {
        let address = image.base.wrapping_add(rva);
        match patch(pid, address, &expected, &replacement) {
            Ok(()) => println!("forced {rva:x}"),
            Err(err) => {
                let already = read_bytes(pid, address, 5).ok();
                if already.as_deref() == Some(&replacement) {
                    println!("already forced {rva:x}");
                    continue;
                }
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
    }
}

/// Character select shows its buttons by switching the UI page to EnterLobby
/// after the window. Creation only showed the 3D scene. Ask for the RaceScene
/// page the same way, without touching the active lobby panel.
fn show_race_page(pid: u32, image: &process::Image) -> Result<(), String> {
    let site = image.base.wrapping_add(0x16735F3);
    let original = read_bytes(pid, site, 23)?;
    if original.first() == Some(&0xE9) {
        println!("race page already hooked");
        return Ok(());
    }
    if original.len() != 23
        || original[..11] != [0x45, 0x33, 0xC9, 0x45, 0x33, 0xC0, 0xBA, 0xF2, 0x03, 0x00, 0x00]
        || original[11..14] != [0x48, 0x8B, 0x0D]
        || original[18] != 0xE8
    {
        return Err(format!("create scene branch is not the expected code at {site:x}"));
    }
    let global_disp = i32::from_le_bytes(original[14..18].try_into().unwrap());
    let global = site.wrapping_add(18).wrapping_add(global_disp as i64 as u64);
    let show_disp = i32::from_le_bytes(original[19..23].try_into().unwrap());
    let show = site.wrapping_add(23).wrapping_add(show_disp as i64 as u64);
    let page = image.base.wrapping_add(0x1A9E080);
    let race = image.base.wrapping_add(0x25BC548);
    let resume = image.base.wrapping_add(0x167360A);
    let cave = allocate_near(pid, image.end, 0x1000)?;

    let mut stub = vec![0u8; 64];
    stub[..11].copy_from_slice(&original[..11]);
    stub[11..14].copy_from_slice(&[0x48, 0x8B, 0x0D]);
    write_rel(&mut stub, 14, cave.wrapping_add(18), global);
    stub[18] = 0xE8;
    write_rel(&mut stub, 19, cave.wrapping_add(23), show);
    stub[23..26].copy_from_slice(&[0x48, 0x8D, 0x0D]);
    write_rel(&mut stub, 26, cave.wrapping_add(30), race);
    stub[30..35].copy_from_slice(&[0x33, 0xD2, 0x45, 0x33, 0xC0]);
    stub[35] = 0xE8;
    write_rel(&mut stub, 36, cave.wrapping_add(40), page);
    stub[40] = 0xE9;
    write_rel(&mut stub, 41, cave.wrapping_add(45), resume);

    let mut jump = vec![0x90u8; 23];
    jump[0] = 0xE9;
    write_rel(&mut jump, 1, site.wrapping_add(5), cave);
    patch(pid, cave, &[0u8; 64], &stub)?;
    patch(pid, site, &original, &jump)?;
    println!("race page hooked at {site:x} via {cave:x}");
    Ok(())
}

fn write_rel(bytes: &mut [u8], at: usize, next_ip: u64, target: u64) {
    let disp = target.wrapping_sub(next_ip) as i32;
    bytes[at..at + 4].copy_from_slice(&disp.to_le_bytes());
}

/// Every qword store into `[reg+0x74]`. Zeros are counted. The rest are
/// candidates for the active lobby panel.
fn slot(options: Options) {
    let image = match load(&options) {
        Ok(image) => image,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let stores = pointer_stores(&image, 0x74);
    let mut zeros = 0u32;
    println!("stores {}", stores.len());
    for store in stores {
        let Some(bytes) = image.read_at(store, 15) else {
            continue;
        };
        let mut decoder = Decoder::with_ip(64, bytes, store, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        decoder.decode_out(&mut instruction);
        let zero = match instruction.op1_kind() {
            OpKind::Immediate8 => instruction.immediate8() == 0,
            OpKind::Immediate16 => instruction.immediate16() == 0,
            OpKind::Immediate32 => instruction.immediate32() == 0,
            OpKind::Immediate64 => instruction.immediate64() == 0,
            _ => false,
        };
        if zero {
            zeros += 1;
            continue;
        }
        let start = function_start(&image, store);
        if !mentions_singleton(&image, store) {
            continue;
        }
        println!(
            "store {:x} function {:x}",
            store - image.base,
            start - image.base
        );
        print_window(&image, store);
    }
    println!("zero stores {zeros}");
}

/// `mov [object+0x74], reg` after `mov [object+0x10/0x18/0x20], reg`.
/// The panel pointer is born in the register, then stored to both slots.
fn same_pointer(options: Options) {
    let image = match load(&options) {
        Ok(image) => image,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let mut hits = 0u32;
    let mut leas = 0u32;
    for region in image.regions.iter().filter(|region| region.executable) {
        let mut decoder = Decoder::with_ip(64, &region.bytes, region.base, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        let mut last: std::collections::HashMap<iced_x86::Register, (iced_x86::Register, u64, u64)> =
            std::collections::HashMap::new();
        let mut zeroed: std::collections::HashSet<iced_x86::Register> = std::collections::HashSet::new();
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            if instruction.len() == 0 {
                break;
            }
            if instruction.mnemonic() == Mnemonic::Lea
                && instruction.memory_displacement64() == 0x74
                && !matches!(
                    instruction.memory_base(),
                    iced_x86::Register::None
                        | iced_x86::Register::RIP
                        | iced_x86::Register::RSP
                        | iced_x86::Register::RBP
                )
            {
                leas += 1;
                if leas <= 40 {
                    println!("lea +74 {:x}", instruction.ip() - image.base);
                }
            }
            if matches!(instruction.mnemonic(), Mnemonic::Ret | Mnemonic::Int3) {
                last.clear();
                zeroed.clear();
                continue;
            }
            if instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Memory
                && instruction.memory_index() == iced_x86::Register::None
                && instruction.memory_size().size() == 8
                && instruction.op1_kind() == OpKind::Register
                && !matches!(
                    instruction.memory_base(),
                    iced_x86::Register::None
                        | iced_x86::Register::RIP
                        | iced_x86::Register::RSP
                        | iced_x86::Register::RBP
                )
            {
                let src = instruction.op1_register().full_register();
                let base = instruction.memory_base().full_register();
                let disp = instruction.memory_displacement64();
                if disp == 0x74 && !zeroed.contains(&src) {
                    if let Some((prev_base, prev_disp, prev_at)) = last.get(&src) {
                        if *prev_base == base && matches!(*prev_disp, 0x08 | 0x10 | 0x18 | 0x20 | 0x28 | 0x50 | 0x58 | 0x60) {
                            hits += 1;
                            println!(
                                "same +{prev_disp:x} at {:x} then +74 at {:x}",
                                prev_at - image.base,
                                instruction.ip() - image.base
                            );
                        }
                    }
                }
                if matches!(disp, 0x08 | 0x10 | 0x18 | 0x20 | 0x28 | 0x50 | 0x58 | 0x60 | 0x74) {
                    last.insert(src, (base, disp, instruction.ip()));
                }
            }
            if instruction.mnemonic() == Mnemonic::Xor
                && instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register
                && instruction.op0_register().full_register() == instruction.op1_register().full_register()
            {
                let written = instruction.op0_register().full_register();
                zeroed.insert(written);
                last.remove(&written);
            }
            if instruction.op0_kind() == OpKind::Register {
                let written = instruction.op0_register().full_register();
                if instruction.mnemonic() == Mnemonic::Xor
                    && instruction.op1_kind() == OpKind::Register
                    && written == instruction.op1_register().full_register()
                {
                    // already recorded as zero
                } else if instruction.mnemonic() == Mnemonic::Mov && instruction.op1_kind() == OpKind::Register {
                    let src = instruction.op1_register().full_register();
                    match last.get(&src).copied() {
                        Some(value) => {
                            last.insert(written, value);
                        }
                        None => {
                            last.remove(&written);
                        }
                    }
                    if zeroed.contains(&src) {
                        zeroed.insert(written);
                    } else {
                        zeroed.remove(&written);
                    }
                } else if !matches!(instruction.mnemonic(), Mnemonic::Cmp | Mnemonic::Test) {
                    last.remove(&written);
                    zeroed.remove(&written);
                }
            }
            if instruction.mnemonic() == Mnemonic::Call {
                for reg in [
                    iced_x86::Register::RAX,
                    iced_x86::Register::RCX,
                    iced_x86::Register::RDX,
                    iced_x86::Register::R8,
                    iced_x86::Register::R9,
                    iced_x86::Register::R10,
                    iced_x86::Register::R11,
                ] {
                    last.remove(&reg);
                    zeroed.remove(&reg);
                }
            }
        }
    }
    println!("same stores {hits}");
    println!("lea +74 {leas}");
}

fn mentions_singleton(image: &process::Image, store: u64) -> bool {
    let global = image.base.wrapping_add(0x3122040);
    let start = store.saturating_sub(0x1800).max(image.base);
    let Some(bytes) = image.read_at(start, 0x1a00) else {
        return false;
    };
    let mut decoder = Decoder::with_ip(64, bytes, start, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut steps = 0u32;
    while decoder.can_decode() && steps < 400 {
        decoder.decode_out(&mut instruction);
        if instruction.len() == 0 {
            break;
        }
        steps += 1;
        if instruction.is_ip_rel_memory_operand() && instruction.ip_rel_memory_address() == global {
            return true;
        }
    }
    false
}

/// Methods of the lobby scenes. Select is what the client already shows.
/// A race method that touches the same offsets is the panel switch.
fn scenes(options: Options) {
    let image = match load(&options) {
        Ok(image) => image,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let tables = [
        ("Race", 0x26C1398u64),
        ("Select", 0x26C1720u64),
        ("Custom", 0x26C1788u64),
        ("Logo", 0x26C1A70u64),
        ("Server", 0x26CF2F0u64),
    ];
    let mut methods = HashSet::new();
    let mut rows: Vec<(String, usize, u64)> = Vec::new();
    for (name, rva) in tables {
        let address = image.base.wrapping_add(rva);
        let Some(bytes) = image.read_at(address, 8 * 120) else {
            println!("{name} unreadable");
            continue;
        };
        let mut count = 0usize;
        for index in 0..120 {
            if index > 0
                && tables.iter().any(|(_, other)| *other != rva && *other == rva + index as u64 * 8)
            {
                break;
            }
            let slot = u64::from_le_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap());
            if slot == 0 {
                break;
            }
            count = index + 1;
            if image.contains_exec(slot) {
                methods.insert(slot);
                rows.push((name.into(), index, slot));
            }
        }
        println!("{name} slots {count}");
    }
    let refs = xrefs(&image, &methods);
    for (name, index, slot) in &rows {
        let mut calls = 0u32;
        for xref in &refs {
            if xref.target == *slot && (xref.kind == "call" || xref.kind == "jmp") {
                calls += 1;
            }
        }
        let touches = scene_touches(&image, *slot);
        println!(
            "{name} [{index}] {:x} calls {calls} {touches}",
            slot - image.base
        );
    }
}

fn scene_touches(image: &process::Image, address: u64) -> String {
    let Some(bytes) = image.read_at(address, 0x900) else {
        return "unreadable".into();
    };
    let mut decoder = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut seen = HashSet::new();
    let mut calls = Vec::new();
    let mut steps = 0u32;
    while decoder.can_decode() && steps < 160 {
        decoder.decode_out(&mut instruction);
        if instruction.len() == 0 {
            break;
        }
        steps += 1;
        if instruction.mnemonic() == Mnemonic::Int3 {
            break;
        }
        for index in 0..instruction.op_count() {
            if instruction.op_kind(index) != OpKind::Memory {
                continue;
            }
            if matches!(
                instruction.memory_base(),
                iced_x86::Register::None
                    | iced_x86::Register::RIP
                    | iced_x86::Register::RSP
                    | iced_x86::Register::RBP
            ) {
                continue;
            }
            let disp = instruction.memory_displacement64();
            if matches!(disp, 0x08 | 0x10 | 0x18 | 0x20 | 0x28 | 0x60 | 0x68 | 0x74 | 0x1E0) {
                seen.insert(disp);
            }
        }
        if matches!(instruction.mnemonic(), Mnemonic::Call | Mnemonic::Jmp)
            && instruction.op0_kind() == OpKind::NearBranch64
        {
            let target = instruction.near_branch64().wrapping_sub(image.base);
            if matches!(target, 0x1A9E080 | 0x1673450 | 0x1588880) {
                calls.push(format!("{target:x}"));
            }
        }
    }
    let mut disps: Vec<u64> = seen.into_iter().collect();
    disps.sort_unstable();
    let text: Vec<String> = disps.iter().map(|disp| format!("+{disp:x}")).collect();
    format!("{} {}", text.join(","), calls.join(","))
}

fn pages(options: Options) {
    let image = match load(&options) {
        Ok(image) => image,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    for name in ["RaceScene", "EnterLobby", "CharacterCreate", "CreateCharacter"] {
        let mut places = ascii_hits(&image, name);
        places.extend(wide_hits(&image, name));
        places.sort_unstable();
        places.dedup();
        println!("{name} strings {}", places.len());
        let targets: HashSet<u64> = places.iter().copied().collect();
        for address in &places {
            println!("string {:x}", address - image.base);
        }
        for xref in xrefs(&image, &targets) {
            if xref.kind == "ptr" {
                println!(
                    "ptr {:x} -> {:x}",
                    xref.address - image.base,
                    xref.target - image.base
                );
                continue;
            }
            let start = function_start(&image, xref.address);
            println!(
                "{} {:x} function {:x} -> {:x}",
                xref.kind,
                xref.address - image.base,
                start - image.base,
                xref.target - image.base
            );
            if xref.kind == "lea" {
                print_window(&image, xref.address);
            }
        }
    }
}

fn wide_hits(image: &process::Image, text: &str) -> Vec<u64> {
    let mut pattern = Vec::new();
    for unit in text.encode_utf16() {
        pattern.extend_from_slice(&unit.to_le_bytes());
    }
    let mut found = Vec::new();
    for region in &image.regions {
        let bytes = &region.bytes;
        if bytes.len() < pattern.len() {
            continue;
        }
        let mut offset = 0usize;
        while offset + pattern.len() <= bytes.len() {
            if &bytes[offset..offset + pattern.len()] == pattern {
                found.push(region.base + offset as u64);
                offset += pattern.len();
            } else {
                offset += 1;
            }
        }
    }
    found
}

fn ops(options: Options) {
    let image = match load(&options) {
        Ok(image) => image,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let slots = handler_slots(&image);
    for opcode in [43849u16, 38386, 47769, 54395, 49866, 41834, 21098] {
        match slots.iter().find(|slot| slot.opcode == opcode) {
            Some(slot) => {
                println!("handler {opcode} {:x}", slot.address - image.base);
                print_insns(&image, slot.address, 28);
            }
            None => println!("handler {opcode} none"),
        }
        let hits = immediate_hits(&image, opcode as u64);
        println!("build sites {opcode} {}", hits.len());
        let needle = (opcode as u32).to_le_bytes();
        let mut data_hits = 0u32;
        for region in &image.regions {
            let bytes = &region.bytes;
            let mut offset = 0usize;
            while offset + 4 <= bytes.len() {
                if bytes[offset..offset + 4] == needle {
                    if data_hits < 8 {
                        println!(
                            "data {opcode} {:x}",
                            region.base + offset as u64 - image.base
                        );
                    }
                    data_hits += 1;
                }
                offset += 1;
            }
        }
        println!("data slots {opcode} {data_hits}");
        for address in hits.iter().take(4) {
            println!("site {:x}", address - image.base);
            print_window(&image, *address);
        }
    }
}

/// Remember who writes the active lobby slot, without attaching a debugger.
/// Only instructions that already are a complete `mov [reg+74]` of at least
/// 5 bytes are hooked. The slot itself is not written by this command.
fn trace(options: Options) {
    let pid = match options.pid() {
        Ok(pid) => pid,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let image = match load_module(pid, &options.module) {
        Ok(image) => image,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let note = std::path::Path::new("target/trace74.txt");
    if let Some(previous) = std::fs::read_to_string(note).ok().filter(|text| text.starts_with(&format!("{pid} "))) {
        let address: u64 = previous.split_whitespace().nth(1).and_then(|text| u64::from_str_radix(text, 16).ok()).unwrap_or(0);
        dump_trace(pid, address);
        return;
    }
    let mut sites = Vec::new();
    for store in pointer_stores(&image, 0x74) {
        let rva = store.wrapping_sub(image.base);
        if !(0x160_0000..0x170_0000).contains(&rva) {
            continue;
        }
        let start = function_start(&image, store);
        let lobby_field = mentions_in(&image, start, 0x800, 0x18)
            || mentions_in(&image, start, 0x800, 0x20)
            || mentions_in(&image, start, 0x800, 0x10);
        if !lobby_field {
            continue;
        }
        let Some(stolen) = steal_plain(&image, store) else {
            println!("skip {:x} not a movable mov", store - image.base);
            continue;
        };
        sites.push((store, stolen));
        if sites.len() == 12 {
            break;
        }
    }
    println!("hook sites {}", sites.len());
    if sites.is_empty() {
        return;
    }
    let cave = match allocate_near(pid, image.end, 0x2000) {
        Ok(cave) => cave,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let mut cursor = cave.wrapping_add(0x220);
    for (store, stolen) in &sites {
        let stub = trace_stub(cursor, cave, *store, stolen);
        let zeros = vec![0u8; stub.len()];
        if let Err(err) = patch(pid, cursor, &zeros, &stub) {
            eprintln!("{store:x} stub: {err}");
            std::process::exit(1);
        }
        let mut jump = vec![0x90u8; stolen.len()];
        jump[0] = 0xE9;
        write_rel(&mut jump, 1, store.wrapping_add(5), cursor);
        if let Err(err) = patch(pid, *store, stolen, &jump) {
            eprintln!("{store:x} jump: {err}");
            std::process::exit(1);
        }
        println!("trace {:x} via {:x} bytes {}", store - image.base, cursor, stolen.len());
        cursor = cursor.wrapping_add(0x80);
    }
    let _ = std::fs::create_dir_all("target");
    let _ = std::fs::write(note, format!("{pid} {cave:x}\n"));
    println!("log {cave:x}");
}

fn dump_trace(pid: u32, log: u64) {
    let bytes = match read_bytes(pid, log, 8 + 64 * 8) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let count = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    println!("writes {count}");
    let shown = (count as usize).min(64);
    let start = if count as usize > 64 { (count as usize) % 64 } else { 0 };
    for step in 0..shown {
        let index = (start + step) % 64;
        let at = 8 + index * 8;
        let address = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        if address != 0 {
            println!("write {address:x}");
        }
    }
}

fn steal_plain(image: &process::Image, address: u64) -> Option<Vec<u8>> {
    let bytes = image.read_at(address, 24)?;
    let mut decoder = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE);
    let mut taken = 0usize;
    let mut first = true;
    while taken < 5 {
        let mut instruction = Instruction::default();
        decoder.decode_out(&mut instruction);
        let len = instruction.len();
        if len == 0 || taken + len > 16 {
            return None;
        }
        if instruction.flow_control() != FlowControl::Next || instruction.is_ip_rel_memory_operand() {
            return None;
        }
        if first {
            if instruction.mnemonic() != Mnemonic::Mov
                || instruction.op0_kind() != OpKind::Memory
                || instruction.memory_displacement64() != 0x74
            {
                return None;
            }
            first = false;
        }
        taken += len;
    }
    Some(bytes[..taken].to_vec())
}

fn pending(options: Options) {
    let image = match load(&options) {
        Ok(image) => image,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let copies = pending_to_active(&image);
    println!("pending copies {}", copies.len());
    for (load_at, store_at, _) in &copies {
        println!(
            "load +80 {:x} store +74 {:x}",
            load_at - image.base,
            store_at - image.base
        );
    }
    // The queued panel is published by a later pass. It touches the flag at
    // +0x7C and the pointer at +0x80 on the same register as the +0x74 store.
    println!("commit sites");
    for region in image.regions.iter().filter(|region| region.executable) {
        let mut decoder = Decoder::with_ip(64, &region.bytes, region.base, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        let mut recent: Vec<(u64, iced_x86::Register, u64, u32)> = Vec::new();
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            if instruction.len() == 0 {
                break;
            }
            if matches!(instruction.mnemonic(), Mnemonic::Ret | Mnemonic::Int3) {
                recent.clear();
                continue;
            }
            let base = instruction.memory_base().full_register();
            let disp = instruction.memory_displacement64();
            let size = instruction.memory_size().size() as u32;
            let interesting = instruction.memory_index() == iced_x86::Register::None
                && !matches!(
                    base,
                    iced_x86::Register::None
                        | iced_x86::Register::RIP
                        | iced_x86::Register::RSP
                        | iced_x86::Register::RBP
                )
                && ((disp == 0x74 && size == 8)
                    || (disp == 0x7C && size == 4)
                    || (disp == 0x80 && size == 8));
            if interesting {
                let store = instruction.op0_kind() == OpKind::Memory && disp == 0x74;
                if store {
                    let saw_flag = recent.iter().any(|item| item.1 == base && item.2 == 0x7C);
                    let saw_pending = recent.iter().any(|item| item.1 == base && item.2 == 0x80);
                    if saw_flag && saw_pending {
                        println!("commit {:x}", instruction.ip() - image.base);
                    }
                }
                recent.push((instruction.ip(), base, disp, size));
                if recent.len() > 24 {
                    recent.remove(0);
                }
            }
        }
    }
    let mut targets = HashSet::new();
    targets.insert(image.base.wrapping_add(0x188A750));
    println!("queue calls");
    for xref in xrefs(&image, &targets) {
        let start = xref.address.saturating_sub(0x40).max(image.base);
        let Some(bytes) = image.read_at(start, 0x48) else {
            continue;
        };
        let mut decoder = Decoder::with_ip(64, bytes, start, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        let mut source = String::from("?");
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            if instruction.len() == 0 || instruction.ip() >= xref.address {
                break;
            }
            if instruction.op0_kind() == OpKind::Register
                && instruction.op0_register().full_register() == iced_x86::Register::R8
            {
                source = format!(
                    "{:?} base {:?} disp {:x}",
                    instruction.mnemonic(),
                    instruction.memory_base(),
                    instruction.memory_displacement64()
                );
            }
        }
        println!(
            "{} {:x} r8 {source}",
            xref.kind,
            xref.address - image.base
        );
    }
    for (name, rva) in [("race", 0x26C1398u64), ("select", 0x26C1720u64), ("custom", 0x26C1788u64)] {
        let Some(bytes) = image.read_at(image.base.wrapping_add(rva), 40 * 8) else {
            println!("{name} vtable unreadable");
            continue;
        };
        for slot in [4usize, 5, 9, 15] {
            let at = slot * 8;
            let value = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
            println!("{name} [{slot}] {:x}", value.wrapping_sub(image.base));
        }
    }
    let wanted = [
        image.base.wrapping_add(0x1679BF0),
        image.base.wrapping_add(0x16737EA),
    ];
    println!("code pointers");
    for region in image.regions.iter().filter(|region| region.executable) {
        let mut decoder = Decoder::with_ip(64, &region.bytes, region.base, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            if instruction.len() == 0 {
                break;
            }
            let target = if instruction.is_ip_rel_memory_operand() {
                instruction.ip_rel_memory_address()
            } else if instruction.op0_kind() == OpKind::NearBranch64 {
                instruction.near_branch64()
            } else {
                0
            };
            if wanted.contains(&target) {
                println!(
                    "{:?} {:x} -> {:x}",
                    instruction.mnemonic(),
                    instruction.ip() - image.base,
                    target - image.base
                );
            }
        }
    }
}

/// Ask the lobby tick to commit RaceScene through the client's own queue.
/// The tick at `0x18B1740` copies `lobby+0x80` into `lobby+0x74` once the
/// delay at `+0x88` elapses. This runs once, on that thread, and only when
/// the character list is the active panel.
fn reveal(options: Options) {
    let pid = match options.pid() {
        Ok(pid) => pid,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let image = match load_module(pid, &options.module) {
        Ok(image) => image,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let singleton = match read_u64(pid, image.base.wrapping_add(0x3122040)) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let lobby = match read_u64(pid, singleton.wrapping_add(0x1E0)) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let list = read_u64(pid, lobby.wrapping_add(0x10)).unwrap_or(0);
    let race = read_u64(pid, lobby.wrapping_add(0x18)).unwrap_or(0);
    let active = read_u64(pid, lobby.wrapping_add(0x74)).unwrap_or(0);
    println!("lobby {lobby:x} list {list:x} race {race:x} active {active:x}");
    if active != list || race == 0 {
        eprintln!("character list is not the active panel");
        std::process::exit(1);
    }
    let site = image.base.wrapping_add(0x18B1740);
    let expected = [0x48u8, 0x89, 0x5C, 0x24, 0x10];
    let current = read_bytes(pid, site, 5).unwrap_or_default();
    if current != expected {
        eprintln!("tick prologue is {:02x?}, not the expected mov", current);
        std::process::exit(1);
    }
    let cave = match allocate_near(pid, image.end, 0x1000) {
        Ok(cave) => cave,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let code = cave.wrapping_add(0x100);
    let stub = reveal_stub(code, cave, site);
    let zeros = vec![0u8; stub.len()];
    if let Err(err) = patch(pid, code, &zeros, &stub) {
        eprintln!("stub: {err}");
        std::process::exit(1);
    }
    let mut jump = vec![0xE9, 0, 0, 0, 0];
    write_rel(&mut jump, 1, site.wrapping_add(5), code);
    if let Err(err) = patch(pid, site, &expected, &jump) {
        eprintln!("jump: {err}");
        std::process::exit(1);
    }
    println!("reveal armed at 18b1740 via {code:x}");
}

fn reveal_stub(code: u64, flag: u64, site: u64) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(&[0x80, 0x3D]);
    let next = code.wrapping_add(stub.len() as u64 + 5);
    stub.extend_from_slice(&flag.wrapping_sub(next).to_le_bytes()[..4]);
    stub.push(0x00);
    let jne_at = stub.len();
    stub.extend_from_slice(&[0x75, 0x00]);
    stub.extend_from_slice(&[0x48, 0x8B, 0x81, 0x18, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0x48, 0x85, 0xC0]);
    let jz_at = stub.len();
    stub.extend_from_slice(&[0x74, 0x00]);
    stub.extend_from_slice(&[0xC6, 0x05]);
    let next = code.wrapping_add(stub.len() as u64 + 5);
    stub.extend_from_slice(&flag.wrapping_sub(next).to_le_bytes()[..4]);
    stub.push(0x01);
    stub.extend_from_slice(&[0x48, 0x89, 0x81, 0x80, 0x00, 0x00, 0x00]);
    stub.extend_from_slice(&[0xC7, 0x81, 0x7C, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
    // -1.0 so the delay compare fails immediately and the tick commits this frame.
    stub.extend_from_slice(&[0xC7, 0x81, 0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xBF]);
    let original = stub.len();
    stub[jne_at + 1] = (original - (jne_at + 2)) as u8;
    stub[jz_at + 1] = (original - (jz_at + 2)) as u8;
    stub.extend_from_slice(&[0x48, 0x89, 0x5C, 0x24, 0x10]);
    stub.push(0xE9);
    let next = code.wrapping_add(stub.len() as u64 + 4);
    stub.extend_from_slice(&(site.wrapping_add(5).wrapping_sub(next) as i32).to_le_bytes());
    stub
}

/// Log each new `rcx` seen by the active-panel check at `0x1898880`.
/// The return address of the first call with the character-list panel is the
/// code that runs immediately after that panel becomes active.
fn alive(options: Options) {
    let pid = match options.pid() {
        Ok(pid) => pid,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let image = match load_module(pid, &options.module) {
        Ok(image) => image,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let note = std::path::Path::new("target/alive.txt");
    let saved = std::fs::read_to_string(note).ok().filter(|text| text.starts_with(&format!("{pid} ")));
    let site = image.base.wrapping_add(0x1898880);
    if options.value == Some(0) {
        let Some(text) = saved else {
            eprintln!("alive hook is not installed");
            std::process::exit(1);
        };
        let log = u64::from_str_radix(text.split_whitespace().nth(1).unwrap_or("0"), 16).unwrap_or(0);
        match patch(pid, log, &read_bytes(pid, log, 16).unwrap_or_default(), &[0u8; 16]) {
            Ok(()) => println!("alive log cleared"),
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
        return;
    }
    if let Some(text) = &saved {
        if options.value != Some(2) {
            let log = u64::from_str_radix(text.split_whitespace().nth(1).unwrap_or("0"), 16).unwrap_or(0);
            dump_alive(pid, &image, log);
            return;
        }
    }
    let stolen = match read_bytes(pid, site, 7) {
        Ok(bytes) if bytes.len() == 7 && bytes[0..3] == [0x48, 0x8B, 0x05] => bytes,
        Ok(bytes) if bytes.first() == Some(&0xE9) => recover_load(pid, site, &bytes),
        _ => {
            eprintln!("alive check is not the expected load at {site:x}");
            std::process::exit(1);
        }
    };
    let cave = match allocate_near(pid, image.end, 0x1000) {
        Ok(cave) => cave,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let code = cave.wrapping_add(0x400);
    let stub = alive_stub(code, cave, site, &stolen, image.base.wrapping_add(0x3122040));
    let zeros = vec![0u8; stub.len()];
    if let Err(err) = patch(pid, code, &zeros, &stub) {
        eprintln!("stub: {err}");
        std::process::exit(1);
    }
    let mut jump = vec![0x90u8; 7];
    jump[0] = 0xE9;
    write_rel(&mut jump, 1, site.wrapping_add(5), code);
    let current = read_bytes(pid, site, 7).unwrap_or_else(|_| stolen.clone());
    if let Err(err) = patch(pid, site, &current, &jump) {
        eprintln!("jump: {err}");
        std::process::exit(1);
    }
    let _ = std::fs::create_dir_all("target");
    let _ = std::fs::write(note, format!("{pid} {cave:x}\n"));
    println!("alive hooked at 1898880 via {code:x} log {cave:x}");
}

fn recover_load(pid: u32, site: u64, jump: &[u8]) -> Vec<u8> {
    let disp = i32::from_le_bytes(jump[1..5].try_into().unwrap());
    let cave = site.wrapping_add(5).wrapping_add(disp as i64 as u64);
    let stub = read_bytes(pid, cave, 0x120).unwrap_or_default();
    let Some(at) = stub.windows(3).position(|bytes| bytes == [0x48, 0x8B, 0x05]) else {
        eprintln!("relocated load is missing");
        std::process::exit(1);
    };
    let mut stolen = stub[at..at + 7].to_vec();
    let moved = i32::from_le_bytes(stolen[3..7].try_into().unwrap());
    let target = cave.wrapping_add(at as u64).wrapping_add(7).wrapping_add(moved as i64 as u64);
    let original = target.wrapping_sub(site.wrapping_add(7)) as i32;
    stolen[3..7].copy_from_slice(&original.to_le_bytes());
    stolen
}

fn alive_stub(code: u64, log: u64, site: u64, stolen: &[u8], singleton: u64) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(&[0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53]);
    stub.extend_from_slice(&[0x4C, 0x8B, 0x5C, 0x24, 0x38]);
    stub.extend_from_slice(&[0x48, 0xB8]);
    stub.extend_from_slice(&singleton.to_le_bytes());
    stub.extend_from_slice(&[0x48, 0x8B, 0x00, 0x48, 0x8B, 0x80, 0xE0, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x50, 0x74]);
    stub.extend_from_slice(&[0x49, 0xBA]);
    stub.extend_from_slice(&log.to_le_bytes());
    stub.extend_from_slice(&[0x49, 0x3B, 0x52, 0x08]);
    let je_at = stub.len();
    stub.extend_from_slice(&[0x74, 0x00]);
    stub.extend_from_slice(&[0x49, 0x89, 0x52, 0x08]);
    stub.extend_from_slice(&[0x41, 0x8B, 0x02, 0x83, 0xF8, 48]);
    let jae_at = stub.len();
    stub.extend_from_slice(&[0x73, 0x00]);
    stub.extend_from_slice(&[0x89, 0xC1, 0xC1, 0xE1, 0x04]);
    stub.extend_from_slice(&[0x4D, 0x89, 0x5C, 0x0A, 0x10]);
    stub.extend_from_slice(&[0x49, 0x89, 0x54, 0x0A, 0x18]);
    stub.extend_from_slice(&[0x41, 0xFF, 0x02]);
    let skip = stub.len();
    stub[je_at + 1] = (skip - (je_at + 2)) as u8;
    stub[jae_at + 1] = (skip - (jae_at + 2)) as u8;
    stub.extend_from_slice(&[0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58]);
    let relocated_at = code.wrapping_add(stub.len() as u64);
    stub.extend_from_slice(&relocate_load(stolen, site, relocated_at));
    stub.push(0xE9);
    let next = code.wrapping_add(stub.len() as u64 + 4);
    let disp = site.wrapping_add(stolen.len() as u64).wrapping_sub(next) as i32;
    stub.extend_from_slice(&disp.to_le_bytes());
    stub
}

fn relocate_load(stolen: &[u8], site: u64, new_ip: u64) -> Vec<u8> {
    let mut out = stolen.to_vec();
    let disp = i32::from_le_bytes(stolen[3..7].try_into().unwrap());
    let target = site.wrapping_add(7).wrapping_add(disp as i64 as u64);
    let new_disp = target.wrapping_sub(new_ip.wrapping_add(7)) as i32;
    out[3..7].copy_from_slice(&new_disp.to_le_bytes());
    out
}

fn dump_alive(pid: u32, image: &process::Image, log: u64) {
    let bytes = match read_bytes(pid, log, 0x10 + 48 * 16) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let count = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let lobby = lobby_of(pid, image).unwrap_or(0);
    println!("checks {count} lobby {lobby:x}");
    let shown = (count as usize).min(48);
    for index in 0..shown {
        let at = 0x10 + index * 16;
        let ret = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        let panel = u64::from_le_bytes(bytes[at + 8..at + 16].try_into().unwrap());
        let rva = ret.wrapping_sub(image.base);
        let start = function_start(image, ret).wrapping_sub(image.base);
        let slot = panel_slot(pid, lobby, panel);
        println!("call {rva:x} function {start:x} panel {slot}");
    }
}

fn lobby_of(pid: u32, image: &process::Image) -> Option<u64> {
    let root = read_u64(pid, image.base.wrapping_add(0x3122040)).ok()?;
    let lobby = read_u64(pid, root.wrapping_add(0x1E0)).ok()?;
    if lobby < 0x10000 { None } else { Some(lobby) }
}

fn panel_slot(pid: u32, lobby: u64, panel: u64) -> String {
    if lobby == 0 || panel == 0 {
        return format!("{panel:x}");
    }
    for offset in [0x08u64, 0x10, 0x18, 0x20, 0x28, 0x50, 0x58, 0x60, 0x68] {
        if read_u64(pid, lobby.wrapping_add(offset)).ok() == Some(panel) {
            return format!("+{offset:x}");
        }
    }
    format!("{panel:x}")
}

fn trace_stub(cave: u64, log: u64, site: u64, stolen: &[u8]) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(&[0x50, 0x51, 0x52]);
    stub.push(0x48);
    stub.push(0xB8);
    stub.extend_from_slice(&log.to_le_bytes());
    stub.extend_from_slice(&[0x8B, 0x08, 0xFF, 0x00, 0x83, 0xE1, 0x3F, 0x48, 0x8D, 0x54, 0xC8, 0x08]);
    stub.push(0x48);
    stub.push(0xB8);
    stub.extend_from_slice(&site.to_le_bytes());
    stub.extend_from_slice(&[0x48, 0x89, 0x02, 0x5A, 0x59, 0x58]);
    stub.extend_from_slice(stolen);
    stub.push(0xE9);
    let next = cave + stub.len() as u64 + 4;
    let back = site.wrapping_add(stolen.len() as u64);
    let disp = back.wrapping_sub(next) as i32;
    stub.extend_from_slice(&disp.to_le_bytes());
    stub
}

fn both(options: Options) {
    let image = match load(&options) {
        Ok(image) => image,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let child = options.value.unwrap_or(0x20);
    let slots = handler_slots(&image);
    let by_start: std::collections::HashMap<u64, u16> =
        slots.iter().map(|slot| (slot.address, slot.opcode)).collect();
    let found = functions_touching(&image, child, 0x74);
    println!("functions touching +{child:x} and +74: {}", found.len());
    for start in &found {
        let opcode = by_start.get(start).copied();
        println!(
            "function {:x} opcode {}",
            start - image.base,
            opcode.map(|code| code.to_string()).unwrap_or_else(|| "-".into())
        );
    }
}

fn refs(options: Options) {
    let Some(rva) = options.rva else {
        eprintln!("refs needs --rva");
        std::process::exit(1);
    };
    let image = match load(&options) {
        Ok(image) => image,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let mut targets = HashSet::new();
    targets.insert(image.base.wrapping_add(rva));
    let found = xrefs(&image, &targets);
    println!("refs {}", found.len());
    for xref in &found {
        println!(
            "{} {:x} -> {:x}",
            xref.kind,
            xref.address - image.base,
            xref.target - image.base
        );
    }
}

fn copies(options: Options) {
    let image = match load(&options) {
        Ok(image) => image,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let slots = handler_slots(&image);
    let by_start: std::collections::HashMap<u64, u16> =
        slots.iter().map(|slot| (slot.address, slot.opcode)).collect();
    let hits = slot_copies(&image);
    println!("slot copies {}", hits.len());
    let mut targets = HashSet::new();
    for hit in &hits {
        let start = function_start(&image, hit.address);
        targets.insert(start);
        let opcode = by_start.get(&start).copied();
        println!(
            "copy +{:x} at {:x} function {:x} opcode {}",
            hit.source,
            hit.address - image.base,
            start - image.base,
            opcode.map(|code| code.to_string()).unwrap_or_else(|| "-".into())
        );
    }
    let refs = xrefs(&image, &targets);
    for xref in &refs {
        if xref.kind != "call" && xref.kind != "jmp" {
            continue;
        }
        let start = function_start(&image, xref.address);
        if let Some(opcode) = by_start.get(&start) {
            println!(
                "handler {opcode} calls {:x} at {:x}",
                xref.target - image.base,
                xref.address - image.base
            );
        }
    }
    let selves = self_activations(&image);
    println!("self activations {}", selves.len());
    let mut setters = HashSet::new();
    for (function, store, parent) in &selves {
        setters.insert(*function);
        let opcode = by_start.get(function).copied();
        println!(
            "self +{parent:x} store {:x} function {:x} opcode {}",
            store - image.base,
            function - image.base,
            opcode.map(|code| code.to_string()).unwrap_or_else(|| "-".into())
        );
    }
    let self_refs = xrefs(&image, &setters);
    for xref in &self_refs {
        if xref.kind != "call" && xref.kind != "jmp" {
            continue;
        }
        let start = function_start(&image, xref.address);
        if let Some(opcode) = by_start.get(&start) {
            println!(
                "handler {opcode} activates via {:x}",
                xref.target - image.base
            );
        }
    }
    let stores = argument_slot_stores(&image);
    println!("argument stores {}", stores.len());
    let mut setters = HashSet::new();
    let mut source_of = std::collections::HashMap::new();
    for store in &stores {
        setters.insert(store.function);
        source_of.insert(store.function, store.source);
        println!(
            "setter {:x} store {:x} {} -> [reg+74]",
            store.function - image.base,
            store.store - image.base,
            format!("{:?}", store.source).trim_start_matches("R")
        );
    }
    let calls = xrefs(&image, &setters);
    for xref in &calls {
        if xref.kind != "call" && xref.kind != "jmp" {
            continue;
        }
        let Some(source) = source_of.get(&xref.target) else {
            continue;
        };
        let Some(disp) = argument_displacement(&image, xref.address, *source) else {
            continue;
        };
        let start = function_start(&image, xref.address);
        let opcode = by_start.get(&start).copied();
        println!(
            "activate +{disp:x} setter {:x} call {:x} function {:x} opcode {}",
            xref.target - image.base,
            xref.address - image.base,
            start - image.base,
            opcode.map(|code| code.to_string()).unwrap_or_else(|| "-".into())
        );
    }
}

fn switchers(options: Options) {
    let image = match load(&options) {
        Ok(image) => image,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let slots = handler_slots(&image);
    let by_start: std::collections::HashMap<u64, u16> =
        slots.iter().map(|slot| (slot.address, slot.opcode)).collect();
    println!("handlers {}", slots.len());
    let stores = pointer_stores(&image, 0x74);
    println!("active-panel stores {}", stores.len());
    for store in &stores {
        let start = function_start(&image, *store);
        let opcode = by_start.get(&start).copied();
        println!(
            "store {:x} function {:x} opcode {}",
            store - image.base,
            start - image.base,
            opcode.map(|code| code.to_string()).unwrap_or_else(|| "-".into())
        );
        if opcode.is_some() {
            print_insns(&image, start, 24);
        }
    }
    println!("create-area calls");
    for slot in &slots {
        let targets = calls_between(&image, slot.address, 0x1660000, 0x1690000);
        if targets.is_empty() {
            continue;
        }
        let shown: Vec<String> = targets.iter().map(|target| format!("{target:x}")).collect();
        println!("call {} {} {}", slot.opcode, slot.address - image.base, shown.join(" "));
    }
}

fn handlers(options: Options) {
    let image = match load(&options) {
        Ok(image) => image,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let slots = handler_slots(&image);
    println!("handlers {}", slots.len());
    for opcode in [19901u16, 39197, 43140, 58624, 41834] {
        match slots.iter().find(|slot| slot.opcode == opcode) {
            Some(slot) => {
                println!("handler {opcode} {:x}", slot.address - image.base);
                print_insns(&image, slot.address, 25);
            }
            None => println!("handler {opcode} empty"),
        }
    }
    let flags = bool_handlers(&image, &slots);
    let lobby: Vec<_> = slots
        .iter()
        .copied()
        .filter(|slot| handler_mentions(&image, slot.address, 0x1e0))
        .collect();
    let panel: Vec<_> = slots
        .iter()
        .copied()
        .filter(|slot| handler_mentions(&image, slot.address, 0x74))
        .collect();
    println!("panel handlers {}", panel.len());
    for slot in &panel {
        println!("panel {} {:x}", slot.opcode, slot.address - image.base);
    }
    for value in [0x3f2u64, 0xcba] {
        let hits: Vec<_> = slots
            .iter()
            .copied()
            .filter(|slot| handler_immediate(&image, slot.address, value))
            .collect();
        println!("immediate {value} handlers {}", hits.len());
        for slot in &hits {
            println!("imm {value} {} {:x}", slot.opcode, slot.address - image.base);
        }
    }
    println!("session handlers {}", lobby.len());
    for slot in &lobby {
        println!("session {} {:x}", slot.opcode, slot.address - image.base);
        print_insns(&image, slot.address, 18);
    }
    println!("bool handlers {}", flags.len());
    for slot in flags.iter().take(40) {
        println!("bool {} {:x}", slot.opcode, slot.address - image.base);
        print_insns(&image, slot.address, 16);
    }
}

fn at(options: Options) {
    let Some(rva) = options.rva else {
        eprintln!("at needs --rva");
        std::process::exit(1);
    };
    let image = match load(&options) {
        Ok(image) => image,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    print_from(&image, image.base.wrapping_add(rva), 220);
}

fn recv(options: Options) {
    let image = match load(&options) {
        Ok(image) => image,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let anchors = [19901u16, 39197, 43140, 58624];
    let pattern = [0xB9u8, 0x1D, 0x99, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x28, 0xE9];
    let raw = pattern_hits(&image, &pattern);
    println!("raw 39197 stubs {}", raw.len());
    for address in raw.iter().take(4) {
        println!("raw rva {:x}", address - image.base);
    }
    let stubs = opcode_stubs(&image, false);
    println!("function stubs {}", stubs.len());
    let mut opcodes: Vec<u16> = stubs.iter().map(|stub| stub.opcode).collect();
    opcodes.sort_unstable();
    opcodes.dedup();
    println!(
        "stub opcodes {} {:?}",
        opcodes.len(),
        opcodes.iter().take(80).collect::<Vec<_>>()
    );
    for opcode in &anchors {
        let hits: Vec<_> = stubs.iter().filter(|stub| stub.opcode == *opcode).collect();
        if hits.is_empty() {
            println!("anchor {opcode} absent");
            continue;
        }
        for stub in hits {
            println!(
                "anchor {opcode} rva {:x} jmp {:x}",
                stub.address - image.base,
                stub.jump - image.base
            );
        }
    }
    let mut targets = HashSet::new();
    for stub in &stubs {
        targets.insert(stub.address);
    }
    let refs = xrefs(&image, &targets);
    let calls = refs.iter().filter(|xref| xref.kind == "call" || xref.kind == "jmp").count();
    let pointers = refs.iter().filter(|xref| xref.kind == "ptr").count();
    println!("stub xrefs {} calls {calls} pointers {pointers}", refs.len());
    for xref in refs.iter().filter(|xref| xref.kind == "call" || xref.kind == "jmp").take(12) {
        println!(
            "stub {} {:x} -> {:x}",
            xref.kind,
            xref.address - image.base,
            xref.target - image.base
        );
        print_window(&image, xref.address);
    }
    for opcode in anchors {
        let rows = data_opcodes(&image, opcode);
        println!("data {opcode} rows {}", rows.len());
        for row in rows.iter().take(6) {
            println!(
                "data rva {:x} +{} -> {:x}",
                row.address - image.base,
                row.delta,
                row.pointer - image.base
            );
        }
    }
    let shifts = opcode_shifts(&image);
    let indexed: Vec<_> = shifts.iter().filter(|site| site.indexed_at != 0).collect();
    println!("header shifts {} indexed {}", shifts.len(), indexed.len());
    for site in indexed.iter().take(8) {
        println!(
            "shift rva {:x} index {:x}",
            site.address - image.base,
            site.indexed_at - image.base
        );
        print_window(&image, site.address);
    }
    let sites = opcode_dispatch(&image);
    println!("opcode readers {}", sites.len());
    for site in sites.iter().take(12) {
        println!(
            "reader rva {:x} index {:x}",
            site.address - image.base,
            site.indexed_at - image.base
        );
        print_window(&image, site.address);
    }
    if let Some(rva) = options.rva {
        let target = image.base.wrapping_add(rva);
        println!("function at rva {rva:x}");
        print_insns(&image, target, 60);
        for callee in direct_callees(&image, target) {
            println!("callee {:x}", callee - image.base);
            print_insns(&image, callee, 40);
        }
        if let Some(logger) = stubs.first().map(|stub| stub.jump) {
            println!("logger {:x}", logger - image.base);
            print_insns(&image, logger, 30);
            for slot in ip_rel_targets(&image, logger) {
                println!("logger slot {:x}", slot - image.base);
                let mut one = HashSet::new();
                one.insert(slot);
                let refs = xrefs(&image, &one);
                println!("logger slot xrefs {}", refs.len());
                let stub_sites: HashSet<u64> = stubs.iter().map(|stub| stub.address).collect();
                for xref in refs.iter().filter(|xref| xref.kind != "ptr").take(15) {
                    println!(
                        "slot {} {:x}",
                        xref.kind,
                        xref.address - image.base
                    );
                    if xref.address != logger + 0xb {
                        let start = function_start(&image, xref.address);
                        println!("slot function {:x}", start - image.base);
                        print_from(&image, start, 160);
                    }
                }
                let mut logger_set = HashSet::new();
                logger_set.insert(logger);
                let writers = xrefs(&image, &logger_set);
                let other: Vec<_> = writers
                    .iter()
                    .filter(|xref| !stub_sites.contains(&xref.address) && xref.kind != "ptr")
                    .collect();
                let mut filter = HashSet::new();
                filter.insert(image.base.wrapping_add(0x12cc990));
                let callers = xrefs(&image, &filter);
                println!("filter callers {}", callers.len());
                for xref in callers.iter().filter(|xref| xref.kind != "ptr").take(8) {
                    println!("filter {} {:x}", xref.kind, xref.address - image.base);
                    print_window(&image, xref.address);
                }
                println!("logger writers {} other {}", writers.len(), other.len());
                for xref in other.iter().take(10) {
                    println!("writer {} {:x}", xref.kind, xref.address - image.base);
                    print_window(&image, xref.address);
                }
            }
        }
        if let Some(pid) = options.pid.or_else(|| options.pid().ok()) {
            follow_connection(&image, pid);
        }
        println!("lookup continue");
        print_from(&image, image.base.wrapping_add(0x142e81d), 35);
        for name in ["WSARecv", "recv", "WSASend"] {
            let hits = ascii_hits(&image, name);
            println!("string {name} {}", hits.len());
            let mut targets = HashSet::new();
            for address in hits.iter().take(4) {
                println!("string {name} rva {:x}", address - image.base);
                targets.insert(*address);
            }
            for xref in xrefs(&image, &targets).into_iter().take(6) {
                println!(
                    "string {name} {} {:x}",
                    xref.kind,
                    xref.address - image.base
                );
                print_window(&image, xref.address);
            }
        }
        let mut one = HashSet::new();
        one.insert(target);
        let refs = xrefs(&image, &one);
        println!("rva {rva:x} xrefs {}", refs.len());
        for xref in refs.iter().filter(|xref| xref.kind != "ptr").take(12) {
            println!(
                "rva {} {:x} -> {:x}",
                xref.kind,
                xref.address - image.base,
                xref.target - image.base
            );
            print_window(&image, xref.address);
        }
    }
}

fn load(options: &Options) -> Result<process::Image, String> {
    let pid = options.pid()?;
    let image = load_module(pid, &options.module)?;
    eprintln!("image {:x}..{:x}", image.base, image.end);
    Ok(image)
}

fn parse_u64(text: &str) -> Option<u64> {
    if let Some(hex) = text.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else if text.chars().any(|unit| matches!(unit, 'a'..='f' | 'A'..='F')) {
        u64::from_str_radix(text, 16).ok()
    } else {
        text.parse().ok()
    }
}

fn immediates(options: Options) {
    let Some(value) = options.value else {
        eprintln!("imm needs --value");
        std::process::exit(1);
    };
    let pid = match options.pid() {
        Ok(pid) => pid,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let image = match load_module(pid, &options.module) {
        Ok(image) => image,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let hits = immediate_hits(&image, value);
    println!("immediate {value} hits {}", hits.len());
    for address in hits.iter().take(40) {
        println!("imm {:x}", address - image.base);
        print_window(&image, *address);
    }
}
