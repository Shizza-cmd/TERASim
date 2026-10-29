use iced_x86::{
    Decoder, DecoderOptions, Formatter, Instruction, Mnemonic, NasmFormatter, OpKind, Register,
};

use crate::process::Image;

#[derive(Clone, Copy)]
pub struct HeaderStore {
    pub address: u64,
    pub length: u16,
    pub opcode: u16,
}

pub fn header_stores(image: &Image) -> Vec<HeaderStore> {
    let mut found = Vec::new();
    for region in image.regions.iter().filter(|region| region.executable) {
        let mut decoder = Decoder::with_ip(64, &region.bytes, region.base, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            if instruction.len() == 0 {
                break;
            }
            if let Some(store) = header_store(&instruction) {
                found.push(store);
            }
        }
    }
    found.sort_by_key(|store| (store.opcode, store.address));
    found
}

fn header_store(instruction: &Instruction) -> Option<HeaderStore> {
    if instruction.mnemonic() != Mnemonic::Mov || !instruction.is_ip_rel_memory_operand() {
        return None;
    }
    let immediate = match instruction.op1_kind() {
        OpKind::Immediate32 => instruction.immediate32(),
        OpKind::Immediate32to64 => instruction.immediate32(),
        _ => return None,
    };
    let length = immediate as u16;
    let opcode = (immediate >> 16) as u16;
    if !(4..=96).contains(&length) || opcode == 0 {
        return None;
    }
    Some(HeaderStore {
        address: instruction.ip(),
        length,
        opcode,
    })
}

pub fn function_start(image: &Image, address: u64) -> u64 {
    let window = 0x2000u64;
    let from = address.saturating_sub(window).max(image.base);
    let Some(bytes) = image.read_at(from, (address - from) as usize) else {
        return address;
    };
    let mut index = bytes.len();
    while index >= 2 {
        index -= 1;
        if bytes[index] == 0xCC && bytes[index - 1] == 0xCC {
            return from + index as u64 + 1;
        }
    }
    address
}

pub struct Xref {
    pub address: u64,
    pub kind: &'static str,
    pub target: u64,
}

pub fn xrefs(image: &Image, targets: &std::collections::HashSet<u64>) -> Vec<Xref> {
    let mut found = Vec::new();
    for region in image.regions.iter().filter(|region| region.executable) {
        let mut decoder = Decoder::with_ip(64, &region.bytes, region.base, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            if instruction.len() == 0 {
                break;
            }
            if matches!(instruction.mnemonic(), Mnemonic::Call | Mnemonic::Jmp)
                && instruction.op0_kind() == OpKind::NearBranch64
            {
                let target = instruction.near_branch64();
                if targets.contains(&target) {
                    let kind = if instruction.mnemonic() == Mnemonic::Call {
                        "call"
                    } else {
                        "jmp"
                    };
                    found.push(Xref {
                        address: instruction.ip(),
                        kind,
                        target,
                    });
                }
            }
            if instruction.mnemonic() == Mnemonic::Lea && instruction.is_ip_rel_memory_operand() {
                let target = instruction.ip_rel_memory_address();
                if targets.contains(&target) {
                    found.push(Xref {
                        address: instruction.ip(),
                        kind: "lea",
                        target,
                    });
                }
            }
        }
    }
    for region in &image.regions {
        let bytes = &region.bytes;
        let mut offset = region.base.wrapping_neg() & 7;
        while offset + 8 <= bytes.len() as u64 {
            let index = offset as usize;
            let pointer = u64::from_le_bytes(bytes[index..index + 8].try_into().unwrap());
            if targets.contains(&pointer) {
                found.push(Xref {
                    address: region.base + offset,
                    kind: "ptr",
                    target: pointer,
                });
            }
            offset += 8;
        }
    }
    found.sort_by_key(|xref| xref.address);
    found.dedup_by_key(|xref| (xref.address, xref.target));
    found
}

pub fn immediate_hits(image: &Image, value: u64) -> Vec<u64> {
    let mut found = Vec::new();
    for region in image.regions.iter().filter(|region| region.executable) {
        let mut decoder = Decoder::with_ip(64, &region.bytes, region.base, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            if instruction.len() == 0 {
                break;
            }
            if instruction_immediate(&instruction) == Some(value) {
                found.push(instruction.ip());
            }
        }
    }
    found
}

pub fn print_window(image: &Image, focus: u64) {
    let start = focus.saturating_sub(0x60).max(image.base);
    let Some(bytes) = image.read_at(start, 0x120) else {
        println!("unreadable {focus:x}");
        return;
    };
    let mut decoder = Decoder::with_ip(64, bytes, start, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    let mut instruction = Instruction::default();
    let mut text = String::new();
    let mut seen_focus = false;
    let mut after = 0u32;
    while decoder.can_decode() && after < 18 {
        decoder.decode_out(&mut instruction);
        if instruction.len() == 0 || instruction.ip() + instruction.len() as u64 <= focus.saturating_sub(0x28) {
            continue;
        }
        if instruction.ip() > focus {
            seen_focus = true;
            after += 1;
        }
        if instruction.ip() == focus {
            seen_focus = true;
        }
        if !seen_focus && instruction.ip() + 0x30 < focus {
            continue;
        }
        text.clear();
        formatter.format(&instruction, &mut text);
        let mark = if instruction.ip() == focus { ">" } else { " " };
        let imm = instruction_immediate(&instruction)
            .filter(|value| (1..=0xffff).contains(value))
            .map(|value| format!("  ; {value}"))
            .unwrap_or_default();
        println!("{mark} {:x}  {text}{imm}", instruction.ip());
    }
}

pub struct OpcodeStub {
    pub address: u64,
    pub opcode: u16,
    pub jump: u64,
}

/// Tail calls shaped as `mov ecx, opcode; add rsp, 28h; jmp logger`.
/// `strict` keeps only those that begin a function (the byte before is int3).
pub fn opcode_stubs(image: &Image, strict: bool) -> Vec<OpcodeStub> {
    let mut found = Vec::new();
    for region in image.regions.iter().filter(|region| region.executable) {
        let mut decoder = Decoder::with_ip(64, &region.bytes, region.base, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        let mut mov: Option<(u64, u16)> = None;
        let mut added = false;
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            if instruction.len() == 0 {
                break;
            }
            if !added
                && instruction.mnemonic() == Mnemonic::Mov
                && matches!(register_op(&instruction, 0), Some(Register::ECX | Register::RCX))
                && matches!(
                    instruction.op1_kind(),
                    OpKind::Immediate32 | OpKind::Immediate32to64
                )
            {
                let value = instruction.immediate32();
                if (1..=0xffff).contains(&value) {
                    let address = instruction.ip();
                    let starts_function = image
                        .read_at(address.wrapping_sub(1), 1)
                        .is_some_and(|bytes| bytes[0] == 0xCC);
                    if !strict || starts_function {
                        mov = Some((address, value as u16));
                        continue;
                    }
                }
            }
            if mov.is_some()
                && !added
                && instruction.mnemonic() == Mnemonic::Add
                && register_op(&instruction, 0) == Some(Register::RSP)
                && instruction_immediate(&instruction) == Some(0x28)
            {
                added = true;
                continue;
            }
            if added && instruction.mnemonic() == Mnemonic::Jmp && instruction.op0_kind() == OpKind::NearBranch64
            {
                if let Some((address, opcode)) = mov {
                    found.push(OpcodeStub {
                        address,
                        opcode,
                        jump: instruction.near_branch64(),
                    });
                }
            }
            mov = None;
            added = false;
        }
    }
    found.sort_by_key(|stub| (stub.opcode, stub.address));
    found
}

pub struct DispatchSite {
    pub address: u64,
    pub indexed_at: u64,
}

/// `movzx reg, word [packet+2]`, the opcode field, followed by an indexed jump or call.
pub fn opcode_dispatch(image: &Image) -> Vec<DispatchSite> {
    let mut found = Vec::new();
    for region in image.regions.iter().filter(|region| region.executable) {
        let mut decoder = Decoder::with_ip(64, &region.bytes, region.base, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            if instruction.len() == 0 {
                break;
            }
            if !reads_opcode_word(&instruction) {
                continue;
            }
            let address = instruction.ip();
            let Some(bytes) = image.read_at(address, 0x80) else {
                continue;
            };
            let mut follow = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE);
            let mut next = Instruction::default();
            let mut steps = 0u32;
            while follow.can_decode() && steps < 16 {
                follow.decode_out(&mut next);
                if next.len() == 0 {
                    break;
                }
                steps += 1;
                if steps == 1 {
                    continue;
                }
                let indexed = matches!(next.mnemonic(), Mnemonic::Jmp | Mnemonic::Call)
                    && next.op0_kind() == OpKind::Memory
                    && next.memory_index() != Register::None;
                if indexed {
                    found.push(DispatchSite {
                        address,
                        indexed_at: next.ip(),
                    });
                    break;
                }
            }
        }
    }
    found
}

fn reads_opcode_word(instruction: &Instruction) -> bool {
    if !matches!(instruction.mnemonic(), Mnemonic::Movzx | Mnemonic::Mov)
        || instruction.op1_kind() != OpKind::Memory
    {
        return false;
    }
    instruction.memory_index() == Register::None
        && instruction.memory_displacement64() == 2
        && instruction.memory_size().size() == 2
        && !matches!(instruction.memory_base(), Register::None | Register::RIP)
}

pub struct ShiftSite {
    pub address: u64,
    pub indexed_at: u64,
}

/// `shr reg, 16` pulls the opcode out of the dword header the client itself writes.
pub fn opcode_shifts(image: &Image) -> Vec<ShiftSite> {
    let mut found = Vec::new();
    for region in image.regions.iter().filter(|region| region.executable) {
        let mut decoder = Decoder::with_ip(64, &region.bytes, region.base, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        let mut loaded: Option<Register> = None;
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            if instruction.len() == 0 {
                break;
            }
            if instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Memory
                && instruction.memory_size().size() == 4
                && instruction.memory_index() == Register::None
            {
                loaded = register_op(&instruction, 0);
                continue;
            }
            if loaded.is_some()
                && instruction.mnemonic() == Mnemonic::Shr
                && register_op(&instruction, 0) == loaded
                && instruction_immediate(&instruction) == Some(16)
            {
                let address = instruction.ip();
                let indexed_at = indexed_branch_after(image, address).unwrap_or(0);
                found.push(ShiftSite { address, indexed_at });
            }
            if !matches!(
                instruction.mnemonic(),
                Mnemonic::Movzx | Mnemonic::Mov | Mnemonic::And
            ) {
                loaded = None;
            }
        }
    }
    found
}

fn indexed_branch_after(image: &Image, address: u64) -> Option<u64> {
    let bytes = image.read_at(address, 0x60)?;
    let mut follow = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE);
    let mut next = Instruction::default();
    let mut steps = 0u32;
    while follow.can_decode() && steps < 12 {
        follow.decode_out(&mut next);
        if next.len() == 0 {
            break;
        }
        steps += 1;
        if steps == 1 {
            continue;
        }
        if matches!(next.mnemonic(), Mnemonic::Jmp | Mnemonic::Call)
            && next.op0_kind() == OpKind::Memory
            && next.memory_index() != Register::None
        {
            return Some(next.ip());
        }
    }
    None
}

#[derive(Clone, Copy)]
pub struct HandlerSlot {
    pub opcode: u16,
    pub address: u64,
}

const HANDLER_TABLE: u64 = 0x3122060;

pub fn handler_slots(image: &Image) -> Vec<HandlerSlot> {
    let Some(bytes) = read_exact(image, image.base.wrapping_add(HANDLER_TABLE), 65536 * 8) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for opcode in 0..65536u32 {
        let index = opcode as usize * 8;
        let pointer = u64::from_le_bytes(bytes[index..index + 8].try_into().unwrap());
        if image.contains_exec(pointer) {
            found.push(HandlerSlot {
                opcode: opcode as u16,
                address: pointer,
            });
        }
    }
    found
}

fn read_exact(image: &Image, mut address: u64, len: usize) -> Option<Vec<u8>> {
    let mut out = vec![0u8; len];
    let mut filled = 0usize;
    while filled < len {
        let chunk = image.read_at(address, len - filled)?;
        if chunk.is_empty() {
            return None;
        }
        out[filled..filled + chunk.len()].copy_from_slice(chunk);
        filled += chunk.len();
        address += chunk.len() as u64;
    }
    Some(out)
}

/// Handlers that read one byte at packet+4 and return without much other work.
pub fn bool_handlers(image: &Image, slots: &[HandlerSlot]) -> Vec<HandlerSlot> {
    slots
        .iter()
        .copied()
        .filter(|slot| looks_like_bool_handler(image, slot.address))
        .collect()
}

fn looks_like_bool_handler(image: &Image, address: u64) -> bool {
    let Some(bytes) = image.read_at(address, 0x80) else {
        return false;
    };
    let mut decoder = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut steps = 0u32;
    let mut saw_byte = false;
    let mut calls = 0u32;
    while decoder.can_decode() && steps < 24 {
        decoder.decode_out(&mut instruction);
        if instruction.len() == 0 {
            break;
        }
        steps += 1;
        if instruction.mnemonic() == Mnemonic::Call {
            calls += 1;
        }
        if reads_packet_byte(&instruction) {
            saw_byte = true;
        }
        if instruction.mnemonic() == Mnemonic::Ret {
            return saw_byte && calls <= 1;
        }
        if instruction.mnemonic() == Mnemonic::Int3 {
            break;
        }
    }
    false
}

fn reads_packet_byte(instruction: &Instruction) -> bool {
    if !matches!(instruction.mnemonic(), Mnemonic::Movzx | Mnemonic::Mov) {
        return false;
    }
    if instruction.op_count() < 2 || instruction.op1_kind() != OpKind::Memory {
        return false;
    }
    instruction.memory_base() == Register::RCX
        && instruction.memory_index() == Register::None
        && instruction.memory_displacement64() == 4
        && instruction.memory_size().size() == 1
}

pub fn handler_immediate(image: &Image, address: u64, value: u64) -> bool {
    let Some(bytes) = image.read_at(address, 0x180) else {
        return false;
    };
    let mut decoder = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut steps = 0u32;
    while decoder.can_decode() && steps < 50 {
        decoder.decode_out(&mut instruction);
        if instruction.len() == 0 {
            break;
        }
        steps += 1;
        if instruction_immediate(&instruction) == Some(value) {
            return true;
        }
        if instruction.mnemonic() == Mnemonic::Ret || instruction.mnemonic() == Mnemonic::Int3 {
            break;
        }
    }
    false
}

pub fn child_activations(image: &Image) -> Vec<(u64, u64)> {
    let mut found = Vec::new();
    for region in image.regions.iter().filter(|region| region.executable) {
        let mut decoder = Decoder::with_ip(64, &region.bytes, region.base, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        let mut loaded: Option<(Register, Register, u64, u32)> = None;
        let mut age = 0u32;
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            if instruction.len() == 0 {
                break;
            }
            age = age.saturating_add(1);
            if age > 12 {
                loaded = None;
            }
            if matches!(instruction.mnemonic(), Mnemonic::Ret | Mnemonic::Int3) {
                loaded = None;
                age = 0;
            }
            if instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Memory
                && instruction.memory_index() == Register::None
                && !matches!(
                    instruction.memory_base(),
                    Register::None | Register::RIP | Register::RSP | Register::RBP
                )
                && matches!(instruction.memory_displacement64(), 0x10 | 0x18 | 0x20 | 0x28 | 0x48)
                && instruction.memory_size().size() == 8
            {
                loaded = Some((
                    instruction.op0_register(),
                    instruction.memory_base(),
                    instruction.memory_displacement64(),
                    0,
                ));
                age = 0;
                continue;
            }
            if let Some((dest, base, disp, _)) = loaded {
                if instruction.mnemonic() == Mnemonic::Mov
                    && instruction.op0_kind() == OpKind::Memory
                    && instruction.memory_base() == base
                    && instruction.memory_index() == Register::None
                    && !matches!(
                        instruction.memory_base(),
                        Register::None | Register::RIP | Register::RSP | Register::RBP
                    )
                    && instruction.memory_displacement64() == 0x74
                    && instruction.memory_size().size() == 8
                    && instruction.op1_kind() == OpKind::Register
                    && instruction.op1_register() == dest
                {
                    found.push((instruction.ip(), disp));
                }
            }
        }
    }
    found
}

pub fn lobby_panel_switches(image: &Image) -> (Vec<u64>, Vec<(u64, u64)>) {
    let mut found = Vec::new();
    let mut calls = Vec::new();
    for region in image.regions.iter().filter(|region| region.executable) {
        let mut decoder = Decoder::with_ip(64, &region.bytes, region.base, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        let mut holding = Vec::new();
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            if instruction.len() == 0 {
                break;
            }
            let mut kept = None;
            if instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Memory
                && instruction.memory_index() == Register::None
                && instruction.memory_displacement64() == 0x1e0
                && instruction.memory_size().size() == 8
            {
                kept = Some(instruction.op0_register());
                if !holding.contains(&instruction.op0_register()) {
                    holding.push(instruction.op0_register());
                }
            } else if instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register
                && holding.contains(&instruction.op1_register())
            {
                kept = Some(instruction.op0_register());
                if !holding.contains(&instruction.op0_register()) {
                    holding.push(instruction.op0_register());
                }
            }
            if instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Memory
                && holding.contains(&instruction.memory_base())
                && instruction.memory_index() == Register::None
                && instruction.memory_displacement64() == 0x74
                && instruction.memory_size().size() == 8
            {
                found.push(instruction.ip());
            }
            if instruction.mnemonic() == Mnemonic::Call
                && instruction.op0_kind() == OpKind::NearBranch64
                && holding.contains(&Register::RCX)
            {
                calls.push((instruction.ip(), instruction.near_branch64()));
            }
            if instruction.op0_kind() == OpKind::Register {
                let written = instruction.op0_register();
                if kept != Some(written) {
                    holding.retain(|reg| *reg != written);
                }
            }
            if matches!(instruction.mnemonic(), Mnemonic::Call | Mnemonic::Ret | Mnemonic::Int3) {
                holding.retain(|reg| {
                    !matches!(
                        reg,
                        Register::RAX
                            | Register::RCX
                            | Register::RDX
                            | Register::R8
                            | Register::R9
                            | Register::R10
                            | Register::R11
                    )
                });
            }
            if matches!(instruction.mnemonic(), Mnemonic::Ret | Mnemonic::Int3) {
                holding.clear();
            }
        }
    }
    (found, calls)
}

pub fn mentions_in(image: &Image, address: u64, len: usize, displacement: u64) -> bool {
    let Some(bytes) = image.read_at(address, len) else {
        return false;
    };
    let mut decoder = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        if instruction.len() == 0 {
            break;
        }
        let hit = (instruction.op_count() > 0
            && instruction.op0_kind() == OpKind::Memory
            && instruction.memory_displacement64() == displacement)
            || (instruction.op_count() > 1
                && instruction.op1_kind() == OpKind::Memory
                && instruction.memory_displacement64() == displacement);
        if hit {
            return true;
        }
        if instruction.mnemonic() == Mnemonic::Int3 {
            break;
        }
    }
    false
}

pub fn pointer_stores(image: &Image, displacement: u64) -> Vec<u64> {
    let mut found = Vec::new();
    for region in image.regions.iter().filter(|region| region.executable) {
        let mut decoder = Decoder::with_ip(64, &region.bytes, region.base, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            if instruction.len() == 0 {
                break;
            }
            if instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Memory
                && instruction.memory_index() == Register::None
                && instruction.memory_displacement64() == displacement
                && instruction.memory_size().size() == 8
                && !matches!(
                    instruction.memory_base(),
                    Register::None | Register::RIP | Register::RSP | Register::RBP
                )
            {
                found.push(instruction.ip());
            }
        }
    }
    found
}

pub fn calls_between(image: &Image, address: u64, low: u64, high: u64) -> Vec<u64> {
    let Some(bytes) = image.read_at(address, 0x160) else {
        return Vec::new();
    };
    let mut decoder = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut found = Vec::new();
    let mut steps = 0u32;
    while decoder.can_decode() && steps < 45 {
        decoder.decode_out(&mut instruction);
        if instruction.len() == 0 {
            break;
        }
        steps += 1;
        if instruction.mnemonic() == Mnemonic::Call && instruction.op0_kind() == OpKind::NearBranch64 {
            let target = instruction.near_branch64().wrapping_sub(image.base);
            if (low..high).contains(&target) {
                found.push(target);
            }
        }
        if instruction.mnemonic() == Mnemonic::Ret || instruction.mnemonic() == Mnemonic::Int3 {
            break;
        }
    }
    found
}

pub fn handler_mentions(image: &Image, address: u64, displacement: u64) -> bool {
    let Some(bytes) = image.read_at(address, 0x120) else {
        return false;
    };
    let mut decoder = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut steps = 0u32;
    while decoder.can_decode() && steps < 40 {
        decoder.decode_out(&mut instruction);
        if instruction.len() == 0 {
            break;
        }
        steps += 1;
        if instruction.op_count() > 0
            && matches!(instruction.op0_kind(), OpKind::Memory)
            && instruction.memory_displacement64() == displacement
        {
            return true;
        }
        if instruction.op_count() > 1
            && instruction.op1_kind() == OpKind::Memory
            && instruction.memory_displacement64() == displacement
        {
            return true;
        }
        if instruction.mnemonic() == Mnemonic::Ret || instruction.mnemonic() == Mnemonic::Int3 {
            break;
        }
    }
    false
}

pub fn direct_callees(image: &Image, address: u64) -> Vec<u64> {
    let start = function_start(image, address);
    let Some(bytes) = image.read_at(start, 0x600) else {
        return Vec::new();
    };
    let mut decoder = Decoder::with_ip(64, bytes, start, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut found = Vec::new();
    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        if instruction.len() == 0 {
            break;
        }
        if matches!(instruction.mnemonic(), Mnemonic::Call | Mnemonic::Jmp)
            && instruction.op0_kind() == OpKind::NearBranch64
        {
            found.push(instruction.near_branch64());
        }
        if instruction.mnemonic() == Mnemonic::Int3 || instruction.ip() > address && instruction.mnemonic() == Mnemonic::Ret
        {
            break;
        }
    }
    found.sort_unstable();
    found.dedup();
    found
}

pub fn ascii_hits(image: &Image, text: &str) -> Vec<u64> {
    pattern_hits_all(image, text.as_bytes())
}

fn pattern_hits_all(image: &Image, pattern: &[u8]) -> Vec<u64> {
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

pub fn pattern_hits(image: &Image, pattern: &[u8]) -> Vec<u64> {
    let mut found = Vec::new();
    for region in image.regions.iter().filter(|region| region.executable) {
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

pub fn ip_rel_targets(image: &Image, address: u64) -> Vec<u64> {
    let Some(bytes) = image.read_at(address, 0x80) else {
        return Vec::new();
    };
    let mut decoder = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut found = Vec::new();
    let mut shown = 0u32;
    while decoder.can_decode() && shown < 12 {
        decoder.decode_out(&mut instruction);
        if instruction.len() == 0 {
            break;
        }
        shown += 1;
        if instruction.is_ip_rel_memory_operand() {
            found.push(instruction.ip_rel_memory_address());
        }
        if instruction.mnemonic() == Mnemonic::Ret {
            break;
        }
    }
    found.sort_unstable();
    found.dedup();
    found
}

pub fn print_from(image: &Image, address: u64, count: u32) {
    let Some(bytes) = image.read_at(address, 0x400) else {
        println!("unreadable {address:x}");
        return;
    };
    let mut decoder = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    let mut instruction = Instruction::default();
    let mut text = String::new();
    let mut shown = 0u32;
    while decoder.can_decode() && shown < count {
        decoder.decode_out(&mut instruction);
        if instruction.len() == 0 {
            break;
        }
        text.clear();
        formatter.format(&instruction, &mut text);
        println!("  {:x}  {text}", instruction.ip());
        shown += 1;
    }
}

pub fn print_insns(image: &Image, focus: u64, count: u32) {
    let start = function_start(image, focus);
    let Some(bytes) = image.read_at(start, 0x600) else {
        println!("unreadable {focus:x}");
        return;
    };
    let mut decoder = Decoder::with_ip(64, bytes, start, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    let mut instruction = Instruction::default();
    let mut text = String::new();
    let mut shown = 0u32;
    while decoder.can_decode() && shown < count {
        decoder.decode_out(&mut instruction);
        if instruction.len() == 0 {
            break;
        }
        text.clear();
        formatter.format(&instruction, &mut text);
        let mark = if instruction.ip() == focus { ">" } else { " " };
        println!("{mark} {:x}  {text}", instruction.ip());
        shown += 1;
        if instruction.mnemonic() == Mnemonic::Int3 {
            break;
        }
        if instruction.mnemonic() == Mnemonic::Ret && instruction.ip() >= focus {
            break;
        }
    }
}

pub struct DataOpcode {
    pub address: u64,
    pub pointer: u64,
    pub delta: u64,
}

/// A u16 opcode in non-executable bytes with a module code pointer within 24 bytes.
pub fn data_opcodes(image: &Image, opcode: u16) -> Vec<DataOpcode> {
    let needle = opcode.to_le_bytes();
    let mut found = Vec::new();
    for region in image.regions.iter().filter(|region| !region.executable) {
        let bytes = &region.bytes;
        let mut offset = 0usize;
        while offset + 2 <= bytes.len() {
            if bytes[offset] != needle[0] || bytes[offset + 1] != needle[1] {
                offset += 2;
                continue;
            }
            let address = region.base + offset as u64;
            let mut delta = 2u64;
            while delta <= 24 {
                if let Some(pointer) = read_u64(image, address + delta) {
                    if image.contains_exec(pointer) {
                        found.push(DataOpcode {
                            address,
                            pointer,
                            delta,
                        });
                        break;
                    }
                }
                delta += 2;
            }
            offset += 2;
        }
    }
    found
}

fn read_u64(image: &Image, address: u64) -> Option<u64> {
    let bytes = image.read_at(address, 8)?;
    if bytes.len() < 8 {
        return None;
    }
    Some(u64::from_le_bytes(bytes[..8].try_into().ok()?))
}

fn register_op(instruction: &Instruction, index: u32) -> Option<Register> {
    if instruction.op_kind(index) == OpKind::Register {
        Some(instruction.op_register(index))
    } else {
        None
    }
}

#[derive(Clone, Copy)]
pub struct SlotCopy {
    pub address: u64,
    pub source: u64,
}

/// `mov [object+0x74], value` where `value` was loaded from `[object+source]`
/// in the same function. `object` may have been copied between registers.
pub struct ArgumentStore {
    pub function: u64,
    pub store: u64,
    pub base: Register,
    pub source: Register,
}

/// Stores into `[base+0x74]` whose source register is still the incoming argument.
pub fn argument_slot_stores(image: &Image) -> Vec<ArgumentStore> {
    let mut found = Vec::new();
    for region in image.regions.iter().filter(|region| region.executable) {
        let mut decoder = Decoder::with_ip(64, &region.bytes, region.base, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            if instruction.len() == 0 {
                break;
            }
            if instruction.mnemonic() != Mnemonic::Mov
                || instruction.op0_kind() != OpKind::Memory
                || instruction.memory_index() != Register::None
                || instruction.memory_displacement64() != 0x74
                || instruction.memory_size().size() != 8
                || instruction.op1_kind() != OpKind::Register
            {
                continue;
            }
            let source = instruction.op1_register().full_register();
            let base = instruction.memory_base().full_register();
            if matches!(base, Register::None | Register::RIP | Register::RSP | Register::RBP) {
                continue;
            }
            let start = function_start(image, instruction.ip());
            if register_defined(image, start, instruction.ip(), source) {
                continue;
            }
            found.push(ArgumentStore {
                function: start,
                store: instruction.ip(),
                base,
                source,
            });
        }
    }
    found
}

fn register_defined(image: &Image, start: u64, stop: u64, watched: Register) -> bool {
    let Some(bytes) = image.read_at(start, (stop - start) as usize) else {
        return true;
    };
    let mut decoder = Decoder::with_ip(64, bytes, start, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    while decoder.can_decode() && instruction.ip() < stop {
        decoder.decode_out(&mut instruction);
        if instruction.len() == 0 || instruction.ip() >= stop {
            break;
        }
        if written_register(&instruction) == Some(watched) {
            return true;
        }
        if instruction.mnemonic() == Mnemonic::Call
            && matches!(
                watched,
                Register::RAX | Register::RCX | Register::RDX | Register::R8 | Register::R9 | Register::R10 | Register::R11
            )
        {
            return true;
        }
    }
    false
}

/// `[owner+0x74] = this`, where `owner` was loaded from `[this+parent]`.
pub fn self_activations(image: &Image) -> Vec<(u64, u64, u64)> {
    let mut found = Vec::new();
    for region in image.regions.iter().filter(|region| region.executable) {
        let mut decoder = Decoder::with_ip(64, &region.bytes, region.base, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            if instruction.len() == 0 {
                break;
            }
            if instruction.mnemonic() != Mnemonic::Mov
                || instruction.op0_kind() != OpKind::Memory
                || instruction.memory_index() != Register::None
                || instruction.memory_displacement64() != 0x74
                || instruction.memory_size().size() != 8
                || instruction.op1_kind() != OpKind::Register
            {
                continue;
            }
            let source = instruction.op1_register().full_register();
            let base = instruction.memory_base().full_register();
            if matches!(base, Register::None | Register::RIP | Register::RSP | Register::RBP) {
                continue;
            }
            let start = function_start(image, instruction.ip());
            if let Some(parent) = parent_displacement(image, start, instruction.ip(), source, base) {
                found.push((start, instruction.ip(), parent));
            }
        }
    }
    found
}

fn parent_displacement(
    image: &Image,
    start: u64,
    stop: u64,
    source: Register,
    base: Register,
) -> Option<u64> {
    let bytes = image.read_at(start, (stop - start) as usize)?;
    let mut decoder = Decoder::with_ip(64, bytes, start, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut origin: std::collections::HashMap<Register, Option<Register>> = std::collections::HashMap::new();
    let mut loaded: std::collections::HashMap<Register, (Register, u64)> = std::collections::HashMap::new();
    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        if instruction.len() == 0 || instruction.ip() >= stop {
            break;
        }
        if let Some(dest) = written_register(&instruction) {
            if instruction.mnemonic() == Mnemonic::Mov && instruction.op1_kind() == OpKind::Register {
                let src = instruction.op1_register().full_register();
                let copied = origin_of(&origin, src);
                let load = loaded.get(&src).copied();
                origin.insert(dest, copied);
                match load {
                    Some(value) => {
                        loaded.insert(dest, value);
                    }
                    None => {
                        loaded.remove(&dest);
                    }
                }
            } else if instruction.mnemonic() == Mnemonic::Mov
                && instruction.op1_kind() == OpKind::Memory
                && instruction.memory_index() == Register::None
                && instruction.memory_size().size() == 8
                && instruction.memory_displacement64() % 8 == 0
                && instruction.memory_displacement64() <= 0x80
                && !matches!(
                    instruction.memory_base(),
                    Register::None | Register::RIP | Register::RSP | Register::RBP
                )
            {
                let owner = origin_of(&origin, instruction.memory_base().full_register());
                let disp = instruction.memory_displacement64();
                origin.insert(dest, None);
                match owner {
                    Some(owner) => {
                        loaded.insert(dest, (owner, disp));
                    }
                    None => {
                        loaded.remove(&dest);
                    }
                }
            } else {
                origin.insert(dest, None);
                loaded.remove(&dest);
            }
        }
        if instruction.mnemonic() == Mnemonic::Call {
            for reg in [
                Register::RAX,
                Register::RCX,
                Register::RDX,
                Register::R8,
                Register::R9,
                Register::R10,
                Register::R11,
            ] {
                origin.insert(reg, None);
                loaded.remove(&reg);
            }
        }
    }
    let this_ptr = origin_of(&origin, source)?;
    let (owner, disp) = loaded.get(&base).copied()?;
    if owner == this_ptr {
        Some(disp)
    } else {
        None
    }
}

fn origin_of(
    origin: &std::collections::HashMap<Register, Option<Register>>,
    reg: Register,
) -> Option<Register> {
    match origin.get(&reg) {
        None => Some(reg),
        Some(value) => *value,
    }
}

/// Displacement copied into the argument register at `call`, if it came from `[base+disp]`.
pub fn argument_displacement(image: &Image, call: u64, argument: Register) -> Option<u64> {
    let start = call.saturating_sub(0x80).max(image.base);
    let bytes = image.read_at(start, (call - start) as usize)?;
    let mut decoder = Decoder::with_ip(64, bytes, start, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut held: std::collections::HashMap<Register, (Register, u64)> = std::collections::HashMap::new();
    let mut alias: std::collections::HashMap<Register, Register> = std::collections::HashMap::new();
    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        if instruction.len() == 0 || instruction.ip() >= call {
            break;
        }
        if let Some(dest) = written_register(&instruction) {
            if instruction.mnemonic() == Mnemonic::Mov && instruction.op1_kind() == OpKind::Register {
                let src = instruction.op1_register().full_register();
                let copied = held.get(&src).copied();
                let origin = root(&alias, src);
                held.remove(&dest);
                alias.remove(&dest);
                if let Some(value) = copied {
                    held.insert(dest, value);
                }
                alias.insert(dest, origin);
            } else if instruction.mnemonic() == Mnemonic::Mov
                && instruction.op1_kind() == OpKind::Memory
                && instruction.memory_index() == Register::None
                && instruction.memory_size().size() == 8
                && instruction.memory_displacement64() % 8 == 0
                && instruction.memory_displacement64() <= 0x70
                && !matches!(
                    instruction.memory_base(),
                    Register::None | Register::RIP | Register::RSP | Register::RBP
                )
            {
                let origin = root(&alias, instruction.memory_base().full_register());
                let disp = instruction.memory_displacement64();
                held.remove(&dest);
                alias.remove(&dest);
                held.insert(dest, (origin, disp));
            } else {
                held.remove(&dest);
                alias.remove(&dest);
            }
        }
        if instruction.mnemonic() == Mnemonic::Call {
            for reg in [
                Register::RAX,
                Register::RCX,
                Register::RDX,
                Register::R8,
                Register::R9,
                Register::R10,
                Register::R11,
            ] {
                held.remove(&reg);
                alias.remove(&reg);
            }
        }
    }
    held.get(&argument).map(|(_, disp)| *disp)
}

/// Functions that both load an 8-byte field `child` and store an 8-byte field `slot`.
pub fn functions_touching(image: &Image, child: u64, slot: u64) -> Vec<u64> {
    let mut found = Vec::new();
    for region in image.regions.iter().filter(|region| region.executable) {
        let mut decoder = Decoder::with_ip(64, &region.bytes, region.base, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        let mut start = region.base;
        let mut saw_child = false;
        let mut saw_slot = false;
        let mut closed = true;
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            if instruction.len() == 0 {
                break;
            }
            if instruction.mnemonic() == Mnemonic::Int3 {
                if !closed && saw_child && saw_slot {
                    found.push(start);
                }
                saw_child = false;
                saw_slot = false;
                closed = true;
                continue;
            }
            if closed {
                start = instruction.ip();
                closed = false;
            }
            let child_hit = memory_disp(&instruction, child);
            let slot_hit = memory_disp(&instruction, slot);
            saw_child |= child_hit;
            saw_slot |= slot_hit;
            if instruction.mnemonic() == Mnemonic::Ret && saw_child && saw_slot {
                found.push(start);
                saw_child = false;
                saw_slot = false;
                closed = true;
            }
        }
    }
    found
}

fn memory_disp(instruction: &Instruction, disp: u64) -> bool {
    let hit = |index: u32| {
        instruction.op_kind(index) == OpKind::Memory
            && instruction.memory_index() == Register::None
            && instruction.memory_displacement64() == disp
            && instruction.memory_size().size() == 8
            && !matches!(
                instruction.memory_base(),
                Register::None | Register::RIP | Register::RSP | Register::RBP
            )
    };
    (instruction.op_count() > 0 && hit(0)) || (instruction.op_count() > 1 && hit(1))
}

pub fn slot_copies(image: &Image) -> Vec<SlotCopy> {
    use std::collections::HashMap;
    let mut found = Vec::new();
    for region in image.regions.iter().filter(|region| region.executable) {
        let mut decoder = Decoder::with_ip(64, &region.bytes, region.base, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        let mut held: HashMap<Register, (Register, u64)> = HashMap::new();
        let mut alias: HashMap<Register, Register> = HashMap::new();
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            if instruction.len() == 0 {
                break;
            }
            if matches!(instruction.mnemonic(), Mnemonic::Ret | Mnemonic::Int3) {
                held.clear();
                alias.clear();
                continue;
            }
            if instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Memory
                && instruction.memory_index() == Register::None
                && instruction.memory_displacement64() == 0x74
                && instruction.memory_size().size() == 8
                && instruction.op1_kind() == OpKind::Register
                && !matches!(
                    instruction.memory_base(),
                    Register::None | Register::RIP | Register::RSP | Register::RBP
                )
            {
                let src = instruction.op1_register().full_register();
                let base = root(&alias, instruction.memory_base().full_register());
                if let Some((origin, disp)) = held.get(&src).copied() {
                    if origin == base && disp != 0x74 {
                        found.push(SlotCopy {
                            address: instruction.ip(),
                            source: disp,
                        });
                    }
                }
            }
            if let Some(dest) = written_register(&instruction) {
                if instruction.mnemonic() == Mnemonic::Mov
                    && instruction.op1_kind() == OpKind::Register
                {
                    let src = instruction.op1_register().full_register();
                    let copied = held.get(&src).copied();
                    let origin = root(&alias, src);
                    held.remove(&dest);
                    alias.remove(&dest);
                    if let Some(value) = copied {
                        held.insert(dest, value);
                    }
                    alias.insert(dest, origin);
                } else if instruction.mnemonic() == Mnemonic::Mov
                    && instruction.op1_kind() == OpKind::Memory
                    && instruction.memory_index() == Register::None
                    && instruction.memory_size().size() == 8
                    && (0..0x70).contains(&instruction.memory_displacement64())
                    && instruction.memory_displacement64() % 8 == 0
                    && !matches!(
                        instruction.memory_base(),
                        Register::None | Register::RIP | Register::RSP | Register::RBP
                    )
                {
                    let origin = root(&alias, instruction.memory_base().full_register());
                    let disp = instruction.memory_displacement64();
                    held.remove(&dest);
                    alias.remove(&dest);
                    held.insert(dest, (origin, disp));
                } else {
                    held.remove(&dest);
                    alias.remove(&dest);
                }
            }
            if instruction.mnemonic() == Mnemonic::Call {
                for reg in [
                    Register::RAX,
                    Register::RCX,
                    Register::RDX,
                    Register::R8,
                    Register::R9,
                    Register::R10,
                    Register::R11,
                ] {
                    held.remove(&reg);
                    alias.remove(&reg);
                }
            }
        }
    }
    found
}

fn root(alias: &std::collections::HashMap<Register, Register>, reg: Register) -> Register {
    alias.get(&reg).copied().unwrap_or(reg)
}

fn written_register(instruction: &Instruction) -> Option<Register> {
    if instruction.op_count() == 0 || instruction.op0_kind() != OpKind::Register {
        return None;
    }
    match instruction.mnemonic() {
        Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Bt => None,
        _ => Some(instruction.op0_register().full_register()),
    }
}

/// A qword loaded from `+0x80` and later stored to `+0x74`.
/// `0x188A750` queues the next panel at lobby+0x80; this is the copy into the
/// slot the alive check reads.
pub fn pending_to_active(image: &Image) -> Vec<(u64, u64, u64)> {
    let mut found = Vec::new();
    for region in image.regions.iter().filter(|region| region.executable) {
        let mut decoder = Decoder::with_ip(64, &region.bytes, region.base, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        // dest register -> (load address, displacement it was loaded from)
        let mut loaded: std::collections::HashMap<Register, (u64, u64)> =
            std::collections::HashMap::new();
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            if instruction.len() == 0 {
                break;
            }
            if matches!(instruction.mnemonic(), Mnemonic::Ret | Mnemonic::Int3) {
                loaded.clear();
                continue;
            }
            if instruction.mnemonic() == Mnemonic::Mov
                && instruction.memory_index() == Register::None
                && instruction.memory_size().size() == 8
                && !matches!(
                    instruction.memory_base(),
                    Register::None | Register::RIP | Register::RSP | Register::RBP
                )
            {
                if instruction.op0_kind() == OpKind::Register
                    && instruction.op1_kind() == OpKind::Memory
                    && instruction.memory_displacement64() == 0x80
                {
                    loaded.insert(
                        instruction.op0_register().full_register(),
                        (instruction.ip(), 0x80),
                    );
                } else if instruction.op0_kind() == OpKind::Memory
                    && instruction.op1_kind() == OpKind::Register
                    && instruction.memory_displacement64() == 0x74
                {
                    let src = instruction.op1_register().full_register();
                    if let Some((load_at, _)) = loaded.get(&src).copied() {
                        found.push((load_at, instruction.ip(), instruction.memory_displacement64()));
                    }
                }
            }
            if let Some(written) = written_register(&instruction) {
                if instruction.mnemonic() == Mnemonic::Mov && instruction.op1_kind() == OpKind::Register {
                    let src = instruction.op1_register().full_register();
                    if let Some(value) = loaded.get(&src).copied() {
                        loaded.insert(written, value);
                    } else {
                        loaded.remove(&written);
                    }
                } else {
                    loaded.remove(&written);
                }
            }
            if instruction.mnemonic() == Mnemonic::Call {
                for reg in [
                    Register::RAX,
                    Register::RCX,
                    Register::RDX,
                    Register::R8,
                    Register::R9,
                    Register::R10,
                    Register::R11,
                ] {
                    loaded.remove(&reg);
                }
            }
        }
    }
    found
}

fn instruction_immediate(instruction: &Instruction) -> Option<u64> {
    for index in 0..instruction.op_count() {
        let value = match instruction.op_kind(index) {
            OpKind::Immediate8 => instruction.immediate8() as u64,
            OpKind::Immediate8to16 => instruction.immediate8to16() as u16 as u64,
            OpKind::Immediate8to32 => instruction.immediate8to32() as u32 as u64,
            OpKind::Immediate8to64 => instruction.immediate8to64() as u64,
            OpKind::Immediate16 => instruction.immediate16() as u64,
            OpKind::Immediate32 => instruction.immediate32() as u64,
            OpKind::Immediate32to64 => instruction.immediate32to64() as u64,
            OpKind::Immediate64 => instruction.immediate64(),
            _ => continue,
        };
        return Some(value);
    }
    None
}
