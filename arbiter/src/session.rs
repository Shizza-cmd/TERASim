use std::collections::HashSet;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::crypt::Cipher;
use crate::opcode::Opcodes;
use crate::characters::{NameStatus, NewCharacter, Roster};
use crate::packets::{
    self, contains_version, frame, next_frame, parse_create_user, parse_login, parse_username,
    s_account_package_list, s_can_create_user, s_check_username, s_check_version, s_create_user,
    s_get_user_list, s_load_client_account_setting, s_loading_screen, s_login_account_info,
    s_login_arbiter, ticket_matches, UserListEntry, Take,
};
use crate::tickets::Tickets;

const KEY_LEN: usize = 128;
const MAX_PACKET: usize = 0xffff;

pub fn handle(
    mut stream: TcpStream,
    opcodes: Opcodes,
    tickets: Arc<Tickets>,
    characters: Arc<Roster>,
) {
    let peer = stream
        .peer_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "unknown".into());
    println!("connected {peer}");
    if let Err(err) = session(&mut stream, &opcodes, &tickets, &characters) {
        println!("closed {peer}: {err}");
    }
}

fn session(
    stream: &mut TcpStream,
    opcodes: &Opcodes,
    tickets: &Tickets,
    characters: &Roster,
) -> Result<(), String> {
    stream
        .set_nodelay(true)
        .map_err(|err| err.to_string())?;
    stream.write_all(&[1, 0, 0, 0]).map_err(|err| err.to_string())?;
    println!("sent init 1,0,0,0");

    let client1 = read_key(stream, "client key 1")?;
    let server1 = random_key();
    stream.write_all(&server1).map_err(|err| err.to_string())?;

    let client2 = read_key(stream, "client key 2")?;
    let server2 = random_key();
    stream.write_all(&server2).map_err(|err| err.to_string())?;

    let client1_key: [u8; 128] = client1.as_slice().try_into().unwrap();
    let client2_key: [u8; 128] = client2.as_slice().try_into().unwrap();

    let mut cipher = Cipher::new(&client1_key, &client2_key, &server1, &server2);
    let mut plain = Vec::new();
    let mut raw = [0u8; 4096];
    let mut account: Option<String> = None;
    let mut naming = false;
    let mut seen = HashSet::new();
    let mut arm_probe = false;
    let mut hold_list = false;

    loop {
        loop {
            match next_frame(&mut plain) {
                Take::NeedMore => break,
                Take::BadLength(len) => {
                    return Err(format!("bad frame length {len}"));
                }
                Take::Frame(packet) => {
                    if packet.len() > MAX_PACKET {
                        return Err("frame exceeds limit".into());
                    }
                    dispatch(
                        stream,
                        &mut cipher,
                        opcodes,
                        tickets,
                        characters,
                        &packet,
                        &mut account,
                        &mut naming,
                        &mut seen,
                        &mut arm_probe,
                        &mut hold_list,
                    )?;
                }
            }
        }
        if arm_probe {
            arm_probe = false;
            let account_name = account.as_deref().unwrap();
            probe_replies(
                stream,
                &mut cipher,
                opcodes,
                characters,
                account_name,
                &mut plain,
                &seen,
            )?;
            stream
                .set_read_timeout(None)
                .map_err(|err| err.to_string())?;
            continue;
        }

        let n = stream.read(&mut raw).map_err(|err| err.to_string())?;
        if n == 0 {
            return Err("client closed the socket".into());
        }
        let mut chunk = raw[..n].to_vec();
        cipher.decrypt(&mut chunk);
        plain.extend_from_slice(&chunk);
    }
}

fn dispatch(
    stream: &mut TcpStream,
    cipher: &mut Cipher,
    opcodes: &Opcodes,
    tickets: &Tickets,
    characters: &Roster,
    packet: &[u8],
    account: &mut Option<String>,
    naming: &mut bool,
    seen: &mut HashSet<u16>,
    arm_probe: &mut bool,
    hold_list: &mut bool,
) -> Result<(), String> {
    let opcode = u16::from_le_bytes([packet[2], packet[3]]);
    let name = opcodes.name(opcode);
    seen.insert(opcode);
    println!("frame {name} opcode={opcode} bytes={}", packet.len());

    if name == "C_CHECK_VERSION" {
        if contains_version(packet) {
            println!("C_CHECK_VERSION protocol {}", packets::PROTOCOL_VERSION);
        } else {
            println!("C_CHECK_VERSION layout does not contain {}", packets::PROTOCOL_VERSION);
            println!("payload {}", hex(&packet[4..]));
        }
        send(stream, cipher, &s_check_version(require(opcodes, "S_CHECK_VERSION")?))?;
        return Ok(());
    }

    if name == "C_LOGIN_ARBITER" {
        let parsed = parse_login(packet);
        let language = parsed.as_ref().map(|item| item.language).unwrap_or(6);
        let presented = parsed.as_ref().map(|item| item.ticket.as_slice()).unwrap_or(b"");
        match tickets.find(|ticket| ticket_matches(presented, ticket)) {
            Some(name) => {
                println!("ticket accepted for {name}");
                *account = Some(name);
                send_login(stream, cipher, opcodes, characters, account.as_deref().unwrap(), language)?;
            }
            None => {
                println!(
                    "ticket rejected bytes={} text={} packet={}",
                    presented.len(),
                    String::from_utf8_lossy(presented),
                    hex(packet)
                );
                send(
                    stream,
                    cipher,
                    &s_login_arbiter(require(opcodes, "S_LOGIN_ARBITER")?, false, language),
                )?;
                return Err("ticket rejected".into());
            }
        }
        return Ok(());
    }

    if account.is_some() && name == "C_GET_USER_LIST" {
        if *hold_list {
            *hold_list = false;
            println!("held character list");
            return Ok(());
        }
        send_characters(stream, cipher, opcodes, characters, account.as_deref().unwrap())?;
        return Ok(());
    }

    if account.is_some() && name == "C_CAN_CREATE_USER" {
        let ok = characters.allows(account.as_deref().unwrap());
        if ok && opcodes.code("S_CAN_CREATE_USER").is_none() && probe_enabled() {
            *naming = true;
            *arm_probe = true;
            println!("can create: {ok}, probing replies");
            return Ok(());
        }
        reply_bool(stream, cipher, opcodes, "S_CAN_CREATE_USER", ok)?;
        *naming = true;
        *hold_list = ok;
        println!("can create: {ok}");
        return Ok(());
    }

    if account.is_some() && name == "C_CHECK_USERNAME" {
        let status = match parse_username(packet) {
            Some(checked) => characters.check(&checked) as u8,
            None => 2,
        };
        reply_byte(stream, cipher, opcodes, "S_CHECK_USERNAME", status)?;
        println!("check name -> {status}");
        return Ok(());
    }

    if account.is_some() && name == "C_CREATE_USER" {
        create_character(stream, cipher, opcodes, characters, account.as_deref().unwrap(), packet)?;
        return Ok(());
    }

    if name.starts_with("UNKNOWN_") && account.is_some() && *naming {
        if let Some(checked) = lone_username(packet) {
            let status = characters.check(&checked) as u8;
            reply_byte(stream, cipher, opcodes, "S_CHECK_USERNAME", status)?;
            println!("learned C_CHECK_USERNAME {opcode} -> {status}");
            return Ok(());
        }
        if let Some(parsed) = parse_create_user(packet) {
            if characters.check(&parsed.name) != NameStatus::Invalid
                && (parsed.gender == 0 || parsed.gender == 1)
                && (0..=5).contains(&parsed.race)
                && (0..=12).contains(&parsed.class_id)
            {
                println!("learned C_CREATE_USER {opcode}");
                create_character(
                    stream,
                    cipher,
                    opcodes,
                    characters,
                    account.as_deref().unwrap(),
                    packet,
                )?;
                return Ok(());
            }
        }
        let end = packet.len().min(28);
        println!("payload {}", hex(&packet[4..end]));
    }

    Ok(())
}

fn lone_username(packet: &[u8]) -> Option<String> {
    if !(8..=80).contains(&packet.len()) {
        return None;
    }
    let offset = u16::from_le_bytes([packet[4], packet[5]]) as usize;
    let name = parse_username(packet)?;
    let width = name.encode_utf16().count() * 2 + 2;
    if offset.checked_add(width)? != packet.len() {
        return None;
    }
    if name.is_empty() || name.chars().all(|ch| ch.is_alphabetic()) {
        Some(name)
    } else {
        None
    }
}

fn create_character(
    stream: &mut TcpStream,
    cipher: &mut Cipher,
    opcodes: &Opcodes,
    characters: &Roster,
    account: &str,
    packet: &[u8],
) -> Result<(), String> {
    let Some(parsed) = parse_create_user(packet) else {
        reply_bool(stream, cipher, opcodes, "S_CREATE_USER", false)?;
        println!("create user rejected: short packet");
        return Ok(());
    };
    println!(
        "create packet name={} gender={} race={} class={} random={}",
        parsed.name, parsed.gender, parsed.race, parsed.class_id, parsed.random_name
    );
    let draft = NewCharacter {
        name: parsed.name,
        gender: parsed.gender,
        race: parsed.race,
        class_id: parsed.class_id,
        appearance: parsed.appearance,
        second: parsed.second,
        appearance2: parsed.appearance2,
        details: parsed.details,
        shape: parsed.shape,
    };
    match characters.create(account, draft) {
        Ok(character) => {
            println!(
                "created {} id={} race={} class={} gender={}",
                character.name, character.id, character.race, character.class_id, character.gender
            );
            reply_bool(stream, cipher, opcodes, "S_CREATE_USER", true)?;
            send_characters(stream, cipher, opcodes, characters, account)?;
        }
        Err(reason) => {
            println!("create user rejected: {reason:?}");
            reply_bool(stream, cipher, opcodes, "S_CREATE_USER", false)?;
        }
    }
    Ok(())
}

fn send_characters(
    stream: &mut TcpStream,
    cipher: &mut Cipher,
    opcodes: &Opcodes,
    characters: &Roster,
    account: &str,
) -> Result<(), String> {
    let list = characters.list(account);
    let entries: Vec<UserListEntry> = list
        .iter()
        .enumerate()
        .map(|(index, character)| character.list_entry(index as i32 + 1))
        .collect();
    send(
        stream,
        cipher,
        &s_get_user_list(require(opcodes, "S_GET_USER_LIST")?, &entries),
    )?;
    println!("sent {} characters", entries.len());
    Ok(())
}

fn reply_bool(
    stream: &mut TcpStream,
    cipher: &mut Cipher,
    opcodes: &Opcodes,
    name: &str,
    value: bool,
) -> Result<(), String> {
    let Some(opcode) = opcodes.code(name) else {
        println!("opcode map has no {name}");
        return Ok(());
    };
    let packet = if name == "S_CREATE_USER" {
        s_create_user(opcode, value)
    } else {
        s_can_create_user(opcode, value)
    };
    send(stream, cipher, &packet)
}

fn reply_byte(
    stream: &mut TcpStream,
    cipher: &mut Cipher,
    opcodes: &Opcodes,
    name: &str,
    value: u8,
) -> Result<(), String> {
    let Some(opcode) = opcodes.code(name) else {
        println!("opcode map has no {name}");
        return Ok(());
    };
    send(stream, cipher, &s_check_username(opcode, value))
}

fn send_login(
    stream: &mut TcpStream,
    cipher: &mut Cipher,
    opcodes: &Opcodes,
    characters: &Roster,
    account: &str,
    language: u32,
) -> Result<(), String> {
    send(
        stream,
        cipher,
        &s_login_arbiter(require(opcodes, "S_LOGIN_ARBITER")?, true, language),
    )?;
    send(
        stream,
        cipher,
        &s_login_account_info(require(opcodes, "S_LOGIN_ACCOUNT_INFO")?),
    )?;
    if let Some(opcode) = opcodes.code("S_LOADING_SCREEN_CONTROL_INFO") {
        send(stream, cipher, &s_loading_screen(opcode))?;
    }
    if let Some(opcode) = opcodes.code("S_ACCOUNT_PACKAGE_LIST") {
        send(stream, cipher, &s_account_package_list(opcode))?;
    }
    if let Some(opcode) = opcodes.code("S_LOAD_CLIENT_ACCOUNT_SETTING") {
        send(stream, cipher, &s_load_client_account_setting(opcode))?;
    }
    send_characters(stream, cipher, opcodes, characters, account)?;
    println!("sent login replies");
    Ok(())
}

fn send(stream: &mut TcpStream, cipher: &mut Cipher, packet: &[u8]) -> Result<(), String> {
    let mut owned = packet.to_vec();
    cipher.encrypt(&mut owned);
    stream.write_all(&owned).map_err(|err| err.to_string())
}

fn require(opcodes: &Opcodes, name: &str) -> Result<u16, String> {
    opcodes
        .code(name)
        .ok_or_else(|| format!("opcode map has no {name}"))
}

fn read_key(stream: &mut TcpStream, label: &str) -> Result<Vec<u8>, String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|err| err.to_string())?;
    let mut buf = vec![0u8; KEY_LEN];
    let mut got = 0;
    while got < KEY_LEN {
        match stream.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(err) if err.kind() == ErrorKind::TimedOut || err.kind() == ErrorKind::WouldBlock => {
                break;
            }
            Err(err) => return Err(err.to_string()),
        }
    }
    stream.set_read_timeout(None).map_err(|err| err.to_string())?;
    if got != KEY_LEN {
        return Err(format!("{label} was {got} bytes: {}", hex(&buf[..got])));
    }
    println!("{label}: {got}");
    Ok(buf)
}

fn random_key() -> [u8; 128] {
    let mut key = [0u8; 128];
    getrandom::getrandom(&mut key).expect("random key");
    key
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

const PROBE_CMD: &str = "target/probe-cmd.txt";
const PROBE_STATE: &str = "target/probe-state.txt";

fn probe_enabled() -> bool {
    std::env::var("TERA_PROBE").ok().as_deref() == Some("1")
}

fn probe_replies(
    stream: &mut TcpStream,
    cipher: &mut Cipher,
    opcodes: &Opcodes,
    characters: &Roster,
    account: &str,
    plain: &mut Vec<u8>,
    seen: &HashSet<u16>,
) -> Result<(), String> {
    let _ = std::fs::write(PROBE_CMD, "");
    note("PROBE ready");
    let mut baseline = seen.clone();
    for packet in wait_frames(stream, cipher, plain, Duration::from_millis(100))? {
        note_packet(opcodes, &packet, &mut baseline);
    }
    loop {
        let command = match std::fs::read_to_string(PROBE_CMD) {
            Ok(text) => text.trim().to_string(),
            Err(_) => String::new(),
        };
        if command.is_empty() {
            for packet in wait_frames(stream, cipher, plain, Duration::from_millis(40))? {
                handle_probe_packet(stream, cipher, opcodes, characters, account, &packet, &mut baseline)?;
            }
            thread::sleep(Duration::from_millis(20));
            continue;
        }
        let _ = std::fs::write(PROBE_CMD, "");
        if command == "quit" {
            note("PROBE quit");
            return Ok(());
        }
        let Some(rest) = command.strip_prefix("send ") else {
            note(&format!("PROBE bad command {command}"));
            continue;
        };
        let mut parts = rest.split_whitespace();
        let (Some(start), Some(end)) = (parts.next(), parts.next()) else {
            note(&format!("PROBE bad range {rest}"));
            continue;
        };
        let (Ok(start), Ok(end)) = (start.parse::<u16>(), end.parse::<u16>()) else {
            note(&format!("PROBE bad range {rest}"));
            continue;
        };
        if start > end {
            note(&format!("PROBE bad range {start} {end}"));
            continue;
        }
        let mut packed = Vec::new();
        let mut sent = 0u32;
        let mut op = start as u32;
        let last = end as u32;
        while op <= last {
            let code = op as u16;
            if !opcodes.has(code) {
                let packet = frame(code, &[1]);
                let mut owned = packet;
                cipher.encrypt(&mut owned);
                packed.extend_from_slice(&owned);
                sent += 1;
            }
            op += 1;
        }
        stream.write_all(&packed).map_err(|err| err.to_string())?;
        let frames = wait_frames(stream, cipher, plain, Duration::from_millis(200))?;
        for packet in frames {
            handle_probe_packet(stream, cipher, opcodes, characters, account, &packet, &mut baseline)?;
        }
        note(&format!("PROBE sent {start} {end} count {sent}"));
    }
}

fn handle_probe_packet(
    stream: &mut TcpStream,
    cipher: &mut Cipher,
    opcodes: &Opcodes,
    characters: &Roster,
    account: &str,
    packet: &[u8],
    baseline: &mut HashSet<u16>,
) -> Result<(), String> {
    let opcode = u16::from_le_bytes([packet[2], packet[3]]);
    let name = opcodes.name(opcode);
    let fresh = baseline.insert(opcode);
    if name == "C_GET_USER_LIST" {
        send_characters(stream, cipher, opcodes, characters, account)?;
        return Ok(());
    }
    if name == "C_CAN_CREATE_USER" {
        note("PROBE click");
        return Ok(());
    }
    if fresh && opcode != 43849 && opcode != 48668 {
        let end = packet.len().min(28);
        note(&format!(
            "PROBE rx {name} opcode={opcode} bytes={} {}",
            packet.len(),
            hex(&packet[4..end])
        ));
    }
    Ok(())
}

fn note_packet(opcodes: &Opcodes, packet: &[u8], baseline: &mut HashSet<u16>) {
    let opcode = u16::from_le_bytes([packet[2], packet[3]]);
    baseline.insert(opcode);
    note(&format!(
        "PROBE baseline {} opcode={opcode}",
        opcodes.name(opcode)
    ));
}

fn note(line: &str) {
    println!("{line}");
    let _ = std::io::stdout().flush();
    let _ = std::fs::write(PROBE_STATE, line);
}

fn wait_frames(
    stream: &mut TcpStream,
    cipher: &mut Cipher,
    plain: &mut Vec<u8>,
    timeout: Duration,
) -> Result<Vec<Vec<u8>>, String> {
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| err.to_string())?;
    let mut raw = [0u8; 8192];
    let mut frames = Vec::new();
    loop {
        match stream.read(&mut raw) {
            Ok(0) => return Err("client closed the socket".into()),
            Ok(n) => {
                let mut chunk = raw[..n].to_vec();
                cipher.decrypt(&mut chunk);
                plain.extend_from_slice(&chunk);
                loop {
                    match next_frame(plain) {
                        Take::NeedMore => break,
                        Take::BadLength(len) => {
                            return Err(format!("bad frame length {len}"));
                        }
                        Take::Frame(packet) => {
                            if packet.len() > MAX_PACKET {
                                return Err("frame exceeds limit".into());
                            }
                            frames.push(packet);
                        }
                    }
                }
            }
            Err(err) if is_timeout(&err) => break,
            Err(err) => return Err(err.to_string()),
        }
    }
    Ok(frames)
}

fn is_timeout(err: &std::io::Error) -> bool {
    err.kind() == ErrorKind::TimedOut || err.kind() == ErrorKind::WouldBlock
}

