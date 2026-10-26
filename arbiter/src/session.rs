use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use crate::crypt::Cipher;
use crate::opcode::Opcodes;
use crate::packets::{
    self, contains_version, next_frame, parse_login, s_account_package_list, s_check_version,
    s_get_user_list, s_load_client_account_setting, s_loading_screen, s_login_account_info,
    s_login_arbiter, ticket_matches, Take,
};
use crate::tickets::Tickets;

const KEY_LEN: usize = 128;
const MAX_PACKET: usize = 0xffff;

pub fn handle(mut stream: TcpStream, opcodes: Opcodes, tickets: Arc<Tickets>) {
    let peer = stream
        .peer_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "unknown".into());
    println!("connected {peer}");
    if let Err(err) = session(&mut stream, &opcodes, &tickets) {
        println!("closed {peer}: {err}");
    }
}

fn session(stream: &mut TcpStream, opcodes: &Opcodes, tickets: &Tickets) -> Result<(), String> {
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
    let mut logged_in = false;

    loop {
        let n = stream.read(&mut raw).map_err(|err| err.to_string())?;
        if n == 0 {
            return Err("client closed the socket".into());
        }
        let mut chunk = raw[..n].to_vec();
        cipher.decrypt(&mut chunk);
        plain.extend_from_slice(&chunk);

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
                    dispatch(stream, &mut cipher, opcodes, tickets, &packet, &mut logged_in)?;
                }
            }
        }
    }
}

fn dispatch(
    stream: &mut TcpStream,
    cipher: &mut Cipher,
    opcodes: &Opcodes,
    tickets: &Tickets,
    packet: &[u8],
    logged_in: &mut bool,
) -> Result<(), String> {
    let opcode = u16::from_le_bytes([packet[2], packet[3]]);
    let name = opcodes.name(opcode);
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
            Some(account) => {
                println!("ticket accepted for {account}");
                *logged_in = true;
                send_login(stream, cipher, opcodes, language)?;
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

    if name == "C_GET_USER_LIST" && *logged_in {
        send(stream, cipher, &s_get_user_list(require(opcodes, "S_GET_USER_LIST")?))?;
        println!("sent empty character list");
        return Ok(());
    }

    Ok(())
}

fn send_login(
    stream: &mut TcpStream,
    cipher: &mut Cipher,
    opcodes: &Opcodes,
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
    send(stream, cipher, &s_get_user_list(require(opcodes, "S_GET_USER_LIST")?))?;
    println!("sent login replies and empty character list");
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

