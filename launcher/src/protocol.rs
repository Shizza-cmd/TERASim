use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

const HELLO_ID: usize = 0x0DBADB0A;

pub struct Session {
    account: String,
    server_list_url: String,
    ticket: String,
    last_server_id: i64,
}

pub struct Reply {
    pub payload: Option<String>,
    pub nul_terminated: bool,
    pub quit: bool,
}

impl Session {
    pub fn new(account: String, server_list_url: String) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        Self {
            account,
            server_list_url,
            ticket: format!("{nanos:x}"),
            last_server_id: 1,
        }
    }

    pub fn reply(&self, dw_data: usize, text: &str) -> Reply {
        if dw_data == HELLO_ID || text == "Hello!!" {
            return text_reply("Hello!!");
        }
        match text {
            "slsurl" => text_reply(&self.server_list_url),
            "gamestr" => text_reply(&self.gamestr().to_string()),
            "ticket" => text_reply(&json!({ "ticket": self.ticket }).to_string()),
            "last_svr" => text_reply(
                &json!({ "last_connected_server_id": self.last_server_id }).to_string(),
            ),
            "char_cnt" => text_reply(&json!({ "chars_per_server": {} }).to_string()),
            _ if text.starts_with("getWebLinkUrl(") => Reply {
                payload: Some(String::new()),
                nul_terminated: false,
                quit: false,
            },
            _ if text.starts_with("endPopup(") => Reply {
                payload: None,
                nul_terminated: false,
                quit: true,
            },
            _ => Reply {
                payload: None,
                nul_terminated: false,
                quit: false,
            },
        }
    }

    fn gamestr(&self) -> Value {
        json!({
            "result-code": 200,
            "master_account_name": self.account,
            "game_account_name": self.account,
            "ticket": self.ticket,
            "last_connected_server_id": self.last_server_id,
            "chars_per_server": {}
        })
    }
}

fn text_reply(body: &str) -> Reply {
    Reply {
        payload: Some(body.to_string()),
        nul_terminated: true,
        quit: false,
    }
}

