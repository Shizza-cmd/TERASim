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

pub fn s_get_user_list(opcode: u16) -> Vec<u8> {
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
    frame(opcode, &payload)
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
