use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Tickets {
    path: PathBuf,
    inner: Mutex<HashMap<String, String>>,
}

impl Tickets {
    pub fn load() -> Self {
        let path = store_path();
        let map = fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str::<HashMap<String, String>>(&text).ok())
            .unwrap_or_default();
        println!("loaded {} tickets from {}", map.len(), path.display());
        Self {
            path,
            inner: Mutex::new(map),
        }
    }

    pub fn issue(&self, account: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let ticket = format!("{nanos:x}");
        self.remember(ticket.clone(), account);
        ticket
    }

    pub fn remember(&self, ticket: String, account: &str) {
        let mut map = self.inner.lock().expect("tickets");
        map.insert(ticket, account.to_string());
        if let Ok(text) = serde_json::to_string(&*map) {
            let _ = fs::write(&self.path, text);
        }
    }

    pub fn find(&self, mut matches: impl FnMut(&str) -> bool) -> Option<String> {
        self.inner
            .lock()
            .expect("tickets")
            .iter()
            .find(|(ticket, _)| matches(ticket))
            .map(|(_, account)| account.clone())
    }
}

fn store_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("tickets.json")))
        .unwrap_or_else(|| PathBuf::from("tickets.json"))
}
