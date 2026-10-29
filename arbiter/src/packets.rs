pub const PROTOCOL_VERSION: i32 = 387463;

pub fn frame(opcode: u16, payload: &[u8]) -> Vec<u8> {
    let len = (4 + payload.len()) as u16;
    let mut out = Vec::with_capacity(len as usize);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&opcode.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

pub fn contains_version(packet: &[u8]) -> bool {
    let needle = PROTOCOL_VERSION.to_le_bytes();
    packet.windows(4).any(|window| window == needle)
}

pub fn s_check_version(opcode: u16) -> Vec<u8> {
    frame(opcode, &[1])
}

pub fn s_login_arbiter(opcode: u16, success: bool, language: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(u8::from(success));
    payload.push(0);
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&language.to_le_bytes());
    payload.push(0);
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    frame(opcode, &payload)
}

pub fn s_login_account_info(opcode: u16) -> Vec<u8> {
    let name = utf16_z("Local");
    let empty = utf16_z("");
    let mut payload = vec![0u8; 18];
    payload[6..14].copy_from_slice(&1u64.to_le_bytes());
    let name_at = (4 + payload.len()) as u16;
    let api_at = name_at + name.len() as u16;
    let token_at = api_at + empty.len() as u16;
    payload[0..2].copy_from_slice(&name_at.to_le_bytes());
    payload[2..4].copy_from_slice(&api_at.to_le_bytes());
    payload[4..6].copy_from_slice(&token_at.to_le_bytes());
    payload.extend_from_slice(&name);
    payload.extend_from_slice(&empty);
    payload.extend_from_slice(&empty);
    frame(opcode, &payload)
}

pub fn s_loading_screen(opcode: u16) -> Vec<u8> {
    frame(opcode, &[0])
}

pub fn s_account_package_list(opcode: u16) -> Vec<u8> {
    frame(opcode, &0u32.to_le_bytes())
}

pub fn s_load_client_account_setting(opcode: u16) -> Vec<u8> {
    frame(opcode, &0u32.to_le_bytes())
}

pub struct UserListEntry {
    pub id: u32,
    pub name: String,
    pub lobby_gender: i32,
    pub race: i32,
    pub class_id: i32,
    pub appearance: [u8; 8],
    pub second: bool,
    pub appearance2: u32,
    pub details: Vec<u8>,
    pub shape: Vec<u8>,
    pub position: i32,
}

pub struct CreateUser {
    pub name: String,
    pub gender: i32,
    pub race: i32,
    pub class_id: i32,
    pub appearance: [u8; 8],
    pub second: bool,
    pub appearance2: u32,
    pub random_name: bool,
    pub details: Vec<u8>,
    pub shape: Vec<u8>,
}

pub fn s_can_create_user(opcode: u16, ok: bool) -> Vec<u8> {
    frame(opcode, &[u8::from(ok)])
}

pub fn s_check_username(opcode: u16, result: u8) -> Vec<u8> {
    frame(opcode, &[result])
}

pub fn s_create_user(opcode: u16, success: bool) -> Vec<u8> {
    frame(opcode, &[u8::from(success)])
}

pub fn s_get_user_list(opcode: u16, entries: &[UserListEntry]) -> Vec<u8> {
    let mut payload = user_list_header();
    if entries.is_empty() {
        return frame(opcode, &payload);
    }
    let mut starts = Vec::with_capacity(entries.len());
    for entry in entries {
        let start = 4 + payload.len();
        starts.push(start);
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes());
        let refs = payload.len();
        payload.extend_from_slice(&[0u8; 16]);
        let fixed = payload.len();
        payload.extend_from_slice(&[0u8; FIXED_LEN]);
        write_fixed(&mut payload, fixed, entry);
        let name_at = (4 + payload.len()) as u16;
        payload.extend_from_slice(&utf16_z(&entry.name));
        let details_at = (4 + payload.len()) as u16;
        payload.extend_from_slice(&entry.details);
        let shape_at = (4 + payload.len()) as u16;
        payload.extend_from_slice(&entry.shape);
        let guild_at = (4 + payload.len()) as u16;
        payload.extend_from_slice(&utf16_z(""));
        write_u16(&mut payload, refs, 0);
        write_u16(&mut payload, refs + 2, 0);
        write_u16(&mut payload, refs + 4, name_at);
        write_u16(&mut payload, refs + 6, details_at);
        write_u16(&mut payload, refs + 8, entry.details.len() as u16);
        write_u16(&mut payload, refs + 10, shape_at);
        write_u16(&mut payload, refs + 12, entry.shape.len() as u16);
        write_u16(&mut payload, refs + 14, guild_at);
    }
    for (index, start) in starts.iter().enumerate() {
        let next = starts.get(index + 1).copied().unwrap_or(0) as u16;
        let at = start - 4;
        write_u16(&mut payload, at, *start as u16);
        write_u16(&mut payload, at + 2, next);
    }
    write_u16(&mut payload, 0, entries.len() as u16);
    write_u16(&mut payload, 2, starts[0] as u16);
    if payload.len() + 4 > u16::MAX as usize {
        return frame(opcode, &user_list_header());
    }
    frame(opcode, &payload)
}

const FIXED_LEN: usize = 456;
const OFF_APPEARANCE: usize = 117;
const OFF_SECOND: usize = 125;
const OFF_SHOW_FACE: usize = 287;
const OFF_NEW: usize = 409;
const OFF_APPEARANCE2: usize = 415;
const OFF_POSITION: usize = 427;

fn user_list_header() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.push(0);
    payload.extend_from_slice(&0i32.to_le_bytes());
    payload.extend_from_slice(&8i32.to_le_bytes());
    payload.push(1);
    payload.push(0);
    for _ in 0..4 {
        payload.extend_from_slice(&0i32.to_le_bytes());
    }
    payload
}

fn write_fixed(payload: &mut [u8], at: usize, entry: &UserListEntry) {
    write_u32(payload, at, entry.id);
    write_i32(payload, at + 4, entry.lobby_gender);
    write_i32(payload, at + 8, entry.race);
    write_i32(payload, at + 12, entry.class_id);
    write_i32(payload, at + 16, 1);
    write_i64(payload, at + 20, 200);
    write_i32(payload, at + 28, 200);
    payload[at + OFF_APPEARANCE..at + OFF_APPEARANCE + 8].copy_from_slice(&entry.appearance);
    payload[at + OFF_SECOND] = u8::from(entry.second);
    payload[at + OFF_SHOW_FACE] = 1;
    payload[at + OFF_NEW] = 1;
    write_u32(payload, at + OFF_APPEARANCE2, entry.appearance2);
    write_i32(payload, at + OFF_POSITION, entry.position);
}

fn write_u16(buf: &mut [u8], at: usize, value: u16) {
    buf[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(buf: &mut [u8], at: usize, value: u32) {
    buf[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_i32(buf: &mut [u8], at: usize, value: i32) {
    buf[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_i64(buf: &mut [u8], at: usize, value: i64) {
    buf[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

pub fn parse_username(packet: &[u8]) -> Option<String> {
    if packet.len() < 6 {
        return None;
    }
    let offset = u16::from_le_bytes([packet[4], packet[5]]) as usize;
    if offset < 6 {
        return None;
    }
    read_utf16(packet, offset)
}

pub fn parse_create_user(packet: &[u8]) -> Option<CreateUser> {
    if packet.len() < 40 {
        return None;
    }
    let name_at = u16::from_le_bytes([packet[4], packet[5]]) as usize;
    let details_at = u16::from_le_bytes([packet[6], packet[7]]) as usize;
    let details_len = u16::from_le_bytes([packet[8], packet[9]]) as usize;
    let shape_at = u16::from_le_bytes([packet[10], packet[11]]) as usize;
    let shape_len = u16::from_le_bytes([packet[12], packet[13]]) as usize;
    let gender = i32::from_le_bytes([packet[14], packet[15], packet[16], packet[17]]);
    let race = i32::from_le_bytes([packet[18], packet[19], packet[20], packet[21]]);
    let class_id = i32::from_le_bytes([packet[22], packet[23], packet[24], packet[25]]);
    let mut appearance = [0u8; 8];
    appearance.copy_from_slice(&packet[26..34]);
    let second = packet[34] != 0;
    let appearance2 = u32::from_le_bytes([packet[35], packet[36], packet[37], packet[38]]);
    let random_name = packet[39] != 0;
    if name_at < 40 {
        return None;
    }
    let name = read_utf16(packet, name_at)?;
    let details = read_bytes(packet, details_at, details_len)?;
    let shape = read_bytes(packet, shape_at, shape_len)?;
    Some(CreateUser {
        name,
        gender,
        race,
        class_id,
        appearance,
        second,
        appearance2,
        random_name,
        details,
        shape,
    })
}

fn read_bytes(packet: &[u8], offset: usize, len: usize) -> Option<Vec<u8>> {
    if len == 0 {
        return Some(Vec::new());
    }
    let end = offset.checked_add(len)?;
    if end > packet.len() {
        return None;
    }
    Some(packet[offset..end].to_vec())
}

fn read_utf16(packet: &[u8], offset: usize) -> Option<String> {
    if offset >= packet.len() {
        return None;
    }
    let mut units = Vec::new();
    let mut index = offset;
    while index + 1 < packet.len() {
        let unit = u16::from_le_bytes([packet[index], packet[index + 1]]);
        index += 2;
        if unit == 0 {
            return String::from_utf16(&units).ok();
        }
        if units.len() == 64 {
            return None;
        }
        units.push(unit);
    }
    None
}

pub struct LoginRequest {
    pub language: u32,
    pub ticket: Vec<u8>,
}

pub fn parse_login(packet: &[u8]) -> Option<LoginRequest> {
    // C_LOGIN_ARBITER.2, offsets from the start of the packet:
    // string name, bytes ticket, int32, byte, uint32 language, int32 patch.
    if packet.len() < 23 {
        return None;
    }
    let ticket_at = u16::from_le_bytes([packet[6], packet[7]]) as usize;
    let ticket_len = u16::from_le_bytes([packet[8], packet[9]]) as usize;
    let language = u32::from_le_bytes([packet[15], packet[16], packet[17], packet[18]]);
    let ticket_end = ticket_at.checked_add(ticket_len)?;
    if ticket_end > packet.len() {
        return None;
    }
    Some(LoginRequest {
        language,
        ticket: packet[ticket_at..ticket_end].to_vec(),
    })
}

pub fn ticket_matches(presented: &[u8], expected: &str) -> bool {
    let ascii = expected.as_bytes();
    if presented == ascii || presented.strip_suffix(&[0]) == Some(ascii) {
        return true;
    }
    let wide = utf16_z(expected);
    let wide_body = &wide[..wide.len().saturating_sub(2)];
    presented == wide_body || presented == wide.as_slice()
}

fn utf16_z(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

#[derive(Debug)]
pub enum Take {
    NeedMore,
    Frame(Vec<u8>),
    BadLength(u16),
}

pub fn next_frame(buffer: &mut Vec<u8>) -> Take {
    if buffer.len() < 4 {
        return Take::NeedMore;
    }
    let len = u16::from_le_bytes([buffer[0], buffer[1]]);
    if len < 4 {
        return Take::BadLength(len);
    }
    if buffer.len() < len as usize {
        return Take::NeedMore;
    }
    Take::Frame(buffer.drain(..len as usize).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_constant_is_visible_in_a_check_packet() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.extend_from_slice(&8u16.to_le_bytes());
        payload.extend_from_slice(&8u16.to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(&0i32.to_le_bytes());
        payload.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        let packet = frame(19900, &payload);
        assert!(contains_version(&packet));
    }

    #[test]
    fn frames_split_across_reads() {
        let first = frame(1, &[9, 9]);
        let second = frame(2, &[7]);
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&first[..3]);
        assert!(matches!(next_frame(&mut buffer), Take::NeedMore));
        buffer.extend_from_slice(&first[3..]);
        buffer.extend_from_slice(&second[..1]);
        match next_frame(&mut buffer) {
            Take::Frame(got) => assert_eq!(got, first),
            other => panic!("first frame: {other:?}"),
        }
        assert!(matches!(next_frame(&mut buffer), Take::NeedMore));
        buffer.extend_from_slice(&second[1..]);
        match next_frame(&mut buffer) {
            Take::Frame(got) => assert_eq!(got, second),
            other => panic!("second frame: {other:?}"),
        }
    }

    #[test]
    fn ticket_accepts_the_exact_ascii_or_utf16_form() {
        assert!(ticket_matches(b"abc", "abc"));
        assert!(ticket_matches(b"abc\0", "abc"));
        assert!(ticket_matches(&[b'a', 0, b'b', 0, b'c', 0], "abc"));
        let mut wide = vec![b'a', 0, b'b', 0, b'c', 0];
        wide.extend_from_slice(&0u16.to_le_bytes());
        assert!(ticket_matches(&wide, "abc"));
        assert!(!ticket_matches(b"ab", "abc"));
        assert!(!ticket_matches(b"xxabcxx", "abc"));
        assert!(!ticket_matches(b"abc!", "abc"));
    }

    #[test]
    fn login_reads_the_version_two_layout() {
        let name = utf16_z("dev");
        let ticket = b"18e22b7afcb379f8";
        let mut payload = vec![0u8; 19];
        let name_at = (4 + payload.len()) as u16;
        let ticket_at = name_at + name.len() as u16;
        payload[0..2].copy_from_slice(&name_at.to_le_bytes());
        payload[2..4].copy_from_slice(&ticket_at.to_le_bytes());
        payload[4..6].copy_from_slice(&(ticket.len() as u16).to_le_bytes());
        payload[11..15].copy_from_slice(&6u32.to_le_bytes());
        payload[15..19].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        payload.extend_from_slice(&name);
        payload.extend_from_slice(ticket);
        let packet = frame(40075, &payload);
        assert_eq!(packet.len(), 47);
        let parsed = parse_login(&packet).unwrap();
        assert_eq!(parsed.language, 6);
        assert_eq!(parsed.ticket, ticket);
    }

    #[test]
    fn login_rejects_a_ticket_range_past_the_packet() {
        let mut payload = vec![0u8; 19];
        payload[4..6].copy_from_slice(&50u16.to_le_bytes());
        assert!(parse_login(&frame(40075, &payload)).is_none());
    }

    fn sample_entry(name: &str, gender: i32, position: i32) -> UserListEntry {
        UserListEntry {
            id: position as u32,
            name: name.into(),
            lobby_gender: gender,
            race: 4,
            class_id: 5,
            appearance: [1, 2, 3, 4, 5, 6, 7, 8],
            second: false,
            appearance2: 11,
            details: vec![9, 9],
            shape: vec![8],
            position,
        }
    }

    #[test]
    fn empty_user_list_keeps_the_header_only() {
        let packet = s_get_user_list(39197, &[]);
        assert_eq!(packet.len(), 4 + 31);
        assert_eq!(&packet[4..8], &[0, 0, 0, 0]);
        assert_eq!(&packet[13..17], &8i32.to_le_bytes());
        assert_eq!(packet[17], 1);
        assert_eq!(packet[18], 0);
    }

    #[test]
    fn user_list_links_characters_and_echoes_appearance() {
        let packet = s_get_user_list(39197, &[sample_entry("Мира", 1, 1), sample_entry("Арн", 2, 2)]);
        let count = u16::from_le_bytes([packet[4], packet[5]]);
        let offset = u16::from_le_bytes([packet[6], packet[7]]) as usize;
        assert_eq!(count, 2);
        let here = u16::from_le_bytes([packet[offset], packet[offset + 1]]) as usize;
        let next = u16::from_le_bytes([packet[offset + 2], packet[offset + 3]]) as usize;
        assert_eq!(here, offset);
        assert_ne!(next, 0);
        let name_at = u16::from_le_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        assert_eq!(&packet[name_at..name_at + 2], &('М' as u16).to_le_bytes());
        let fixed = offset + 20;
        assert_eq!(&packet[fixed + 4..fixed + 8], &1i32.to_le_bytes());
        assert_eq!(&packet[fixed + 117..fixed + 125], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(packet[fixed + 409], 1);
        assert_eq!(&packet[fixed + 427..fixed + 431], &1i32.to_le_bytes());
        let second_here = u16::from_le_bytes([packet[next], packet[next + 1]]) as usize;
        let second_next = u16::from_le_bytes([packet[next + 2], packet[next + 3]]);
        assert_eq!(second_here, next);
        assert_eq!(second_next, 0);
        assert_eq!(&packet[next + 20 + 427..next + 20 + 431], &2i32.to_le_bytes());
    }

    #[test]
    fn create_user_reads_the_fixed_header_then_blobs() {
        let name = utf16_z("Мира");
        let details = [4u8, 5, 6];
        let shape = [7u8, 8];
        let mut payload = vec![0u8; 36];
        let name_at = (4 + payload.len()) as u16;
        payload.extend_from_slice(&name);
        let details_at = (4 + payload.len()) as u16;
        payload.extend_from_slice(&details);
        let shape_at = (4 + payload.len()) as u16;
        payload.extend_from_slice(&shape);
        payload[0..2].copy_from_slice(&name_at.to_le_bytes());
        payload[2..4].copy_from_slice(&details_at.to_le_bytes());
        payload[4..6].copy_from_slice(&(details.len() as u16).to_le_bytes());
        payload[6..8].copy_from_slice(&shape_at.to_le_bytes());
        payload[8..10].copy_from_slice(&(shape.len() as u16).to_le_bytes());
        payload[10..14].copy_from_slice(&1i32.to_le_bytes());
        payload[14..18].copy_from_slice(&4i32.to_le_bytes());
        payload[18..22].copy_from_slice(&5i32.to_le_bytes());
        payload[22..30].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        payload[31..35].copy_from_slice(&11u32.to_le_bytes());
        payload[35] = 1;
        let parsed = parse_create_user(&frame(1, &payload)).unwrap();
        assert_eq!(parsed.name, "Мира");
        assert_eq!(parsed.gender, 1);
        assert_eq!(parsed.race, 4);
        assert_eq!(parsed.class_id, 5);
        assert_eq!(parsed.appearance, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(parsed.appearance2, 11);
        assert!(parsed.random_name);
        assert_eq!(parsed.details, details);
        assert_eq!(parsed.shape, shape);
    }

    #[test]
    fn create_user_rejects_a_blob_past_the_packet() {
        let mut payload = vec![0u8; 36];
        payload[4..6].copy_from_slice(&80u16.to_le_bytes());
        assert!(parse_create_user(&frame(1, &payload)).is_none());
    }

    #[test]
    fn username_reads_one_string() {
        let name = utf16_z("Мира");
        let mut payload = vec![0u8; 2];
        let at = (4 + payload.len()) as u16;
        payload[0..2].copy_from_slice(&at.to_le_bytes());
        payload.extend_from_slice(&name);
        assert_eq!(parse_username(&frame(1, &payload)).as_deref(), Some("Мира"));
        assert!(parse_username(&frame(1, &[0, 0])).is_none());
    }

    #[test]
    fn login_result_follows_the_def() {
        let denied = s_login_arbiter(43140, false, 6);
        let accepted = s_login_arbiter(43140, true, 6);
        assert_eq!(denied[4], 0);
        assert_eq!(accepted[4], 1);
        assert_eq!(&denied[14..18], &6u32.to_le_bytes());
        assert_eq!(&accepted[14..18], &6u32.to_le_bytes());
    }
}
