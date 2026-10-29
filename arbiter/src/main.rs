mod characters;
mod crypt;
mod opcode;
mod packets;
mod session;
mod tickets;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use characters::Roster;
use opcode::Opcodes;
use tickets::Tickets;

const GAME_PORT: u16 = 7801;
const TICKET_PORT: u16 = 17802;

fn main() {
    let opcodes = Opcodes::load();
    let tickets = Arc::new(Tickets::load());
    let characters = Arc::new(Roster::load());
    let http_tickets = Arc::clone(&tickets);

    thread::spawn(move || {
        if let Err(err) = serve_tickets(http_tickets) {
            eprintln!("tickets: {err}");
        }
    });

    let listener = TcpListener::bind(("127.0.0.1", GAME_PORT)).expect("bind 7801");
    println!("arbiter on 127.0.0.1:{GAME_PORT}");
    println!("tickets on http://127.0.0.1:{TICKET_PORT}/tickets");

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!("accept: {err}");
                continue;
            }
        };
        let opcodes = opcodes.clone();
        let tickets = Arc::clone(&tickets);
        let characters = Arc::clone(&characters);
        thread::spawn(move || session::handle(stream, opcodes, tickets, characters));
    }
}

fn serve_tickets(tickets: Arc<Tickets>) -> std::io::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", TICKET_PORT))?;
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!("tickets accept: {err}");
                continue;
            }
        };
        if let Err(err) = reply_ticket(&tickets, &mut stream) {
            eprintln!("tickets: {err}");
        }
    }
    Ok(())
}

fn reply_ticket(tickets: &Tickets, stream: &mut (impl Read + Write)) -> std::io::Result<()> {
    let mut buf = [0u8; 2048];
    let n = stream.read(&mut buf)?;
    if n == 0 {
        return Ok(());
    }
    let request = String::from_utf8_lossy(&buf[..n]);
    let account = match query_account(&request) {
        AccountQuery::Bad => {
            return stream.write_all(
                b"HTTP/1.0 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }
        AccountQuery::Missing => "dev".to_string(),
        AccountQuery::Value(account) => account,
    };
    let ticket = tickets.issue(&account);
    let body = ticket_body(&ticket, &account);
    let header = format!(
        "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    println!("issued ticket for {account}");
    Ok(())
}

fn ticket_body(ticket: &str, account: &str) -> String {
    serde_json::json!({ "ticket": ticket, "account": account }).to_string()
}

#[derive(Debug)]
enum AccountQuery {
    Missing,
    Value(String),
    Bad,
}

fn query_account(request: &str) -> AccountQuery {
    let Some(line) = request.lines().next() else {
        return AccountQuery::Missing;
    };
    let Some(path) = line.split_whitespace().nth(1) else {
        return AccountQuery::Missing;
    };
    let Some((_, query)) = path.split_once('?') else {
        return AccountQuery::Missing;
    };
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        if key != "account" {
            continue;
        }
        let Some(account) = percent_decode(value) else {
            return AccountQuery::Bad;
        };
        if !account.is_empty() {
            return AccountQuery::Value(account);
        }
    }
    AccountQuery::Missing
}

fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => out.push(b' '),
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                index += 2;
            }
            b'%' => return None,
            byte => out.push(byte),
        }
        index += 1;
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::{percent_decode, query_account, ticket_body, AccountQuery};

    #[test]
    fn ticket_json_escapes_the_account() {
        let body = ticket_body("t", "a\"b\n");
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["ticket"], "t");
        assert_eq!(value["account"], "a\"b\n");
    }

    #[test]
    fn query_decodes_the_account() {
        let request = "GET /tickets?account=a%22b%26c HTTP/1.0\r\n\r\n";
        match query_account(request) {
            AccountQuery::Value(account) => assert_eq!(account, "a\"b&c"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn missing_account_stays_missing() {
        assert!(matches!(
            query_account("GET /tickets HTTP/1.0\r\n\r\n"),
            AccountQuery::Missing
        ));
    }

    #[test]
    fn broken_percent_is_rejected() {
        assert!(matches!(
            query_account("GET /tickets?account=%ZZ HTTP/1.0\r\n\r\n"),
            AccountQuery::Bad
        ));
        assert_eq!(percent_decode("%4"), None);
    }
}
