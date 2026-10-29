use std::collections::HashMap;

const MAP_TEXT: &str = include_str!("../../protocol/387463.map");

#[derive(Clone)]
pub struct Opcodes {
    by_name: HashMap<String, u16>,
    by_code: HashMap<u16, String>,
}

impl Opcodes {
    pub fn load() -> Self {
        let mut by_name = HashMap::new();
        let mut by_code = HashMap::new();
        for line in MAP_TEXT.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let Some(name) = parts.next() else { continue };
            let Some(code) = parts.next() else { continue };
            let Ok(code) = code.parse::<u16>() else { continue };
            by_name.insert(name.to_string(), code);
            by_code.insert(code, name.to_string());
        }
        Self { by_name, by_code }
    }

    pub fn code(&self, name: &str) -> Option<u16> {
        self.by_name.get(name).copied()
    }

    pub fn has(&self, code: u16) -> bool {
        self.by_code.contains_key(&code)
    }

    pub fn name(&self, code: u16) -> String {
        self.by_code
            .get(&code)
            .cloned()
            .unwrap_or_else(|| format!("UNKNOWN_{code}"))
    }
}
