use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::packets::UserListEntry;

pub const MAX_CHARACTERS: usize = 8;
const MAX_BLOB: usize = 2048;

pub struct Roster {
    path: PathBuf,
    inner: Mutex<HashMap<String, Vec<Character>>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Character {
    pub id: u32,
    pub name: String,
    pub gender: i32,
    pub race: i32,
    pub class_id: i32,
    pub appearance: [u8; 8],
    pub second: bool,
    pub appearance2: u32,
    pub details: Vec<u8>,
    pub shape: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct NewCharacter {
    pub name: String,
    pub gender: i32,
    pub race: i32,
    pub class_id: i32,
    pub appearance: [u8; 8],
    pub second: bool,
    pub appearance2: u32,
    pub details: Vec<u8>,
    pub shape: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameStatus {
    Free = 0,
    Taken = 1,
    Invalid = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateError {
    Invalid,
    Taken,
    Full,
}

impl Roster {
    pub fn load() -> Self {
        let path = store_path();
        let roster = Self::open(path);
        let count = roster
            .inner
            .lock()
            .expect("characters")
            .values()
            .map(|list| list.len())
            .sum::<usize>();
        println!("loaded {count} characters from {}", roster.path.display());
        roster
    }

    pub fn open(path: PathBuf) -> Self {
        let map = fs::read_to_string(&path)
            .ok()
            .and_then(|text| decode(&text))
            .unwrap_or_default();
        Self {
            path,
            inner: Mutex::new(map),
        }
    }

    pub fn list(&self, account: &str) -> Vec<Character> {
        self.inner
            .lock()
            .expect("characters")
            .get(account)
            .cloned()
            .unwrap_or_default()
    }

    pub fn allows(&self, account: &str) -> bool {
        self.list(account).len() < MAX_CHARACTERS
    }

    pub fn check(&self, name: &str) -> NameStatus {
        if !valid_name(name) {
            return NameStatus::Invalid;
        }
        if self.taken(name) {
            NameStatus::Taken
        } else {
            NameStatus::Free
        }
    }

    pub fn create(&self, account: &str, draft: NewCharacter) -> Result<Character, CreateError> {
        if !valid_draft(&draft) {
            return Err(CreateError::Invalid);
        }
        let mut map = self.inner.lock().expect("characters");
        if map.get(account).map(|list| list.len()).unwrap_or(0) >= MAX_CHARACTERS {
            return Err(CreateError::Full);
        }
        if taken_in(&map, &draft.name) {
            return Err(CreateError::Taken);
        }
        let id = next_id(&map);
        let character = Character {
            id,
            name: draft.name,
            gender: draft.gender,
            race: draft.race,
            class_id: draft.class_id,
            appearance: draft.appearance,
            second: draft.second,
            appearance2: draft.appearance2,
            details: draft.details,
            shape: draft.shape,
        };
        map.entry(account.to_string())
            .or_default()
            .push(character.clone());
        if let Ok(text) = encode(&map) {
            let _ = fs::write(&self.path, text);
        }
        Ok(character)
    }
}

impl Character {
    pub fn list_entry(&self, position: i32) -> UserListEntry {
        UserListEntry {
            id: self.id,
            name: self.name.clone(),
            lobby_gender: lobby_gender(self.gender),
            race: self.race,
            class_id: self.class_id,
            appearance: self.appearance,
            second: self.second,
            appearance2: self.appearance2,
            details: self.details.clone(),
            shape: self.shape.clone(),
            position,
        }
    }
}

pub fn lobby_gender(gender: i32) -> i32 {
    if gender == 0 { 2 } else { 1 }
}

fn valid_draft(draft: &NewCharacter) -> bool {
    valid_name(&draft.name)
        && (draft.gender == 0 || draft.gender == 1)
        && (0..=5).contains(&draft.race)
        && (0..=12).contains(&draft.class_id)
        && draft.details.len() <= MAX_BLOB
        && draft.shape.len() <= MAX_BLOB
}

fn valid_name(name: &str) -> bool {
    let count = name.chars().count();
    (1..=16).contains(&count) && name.chars().all(|ch| ch.is_alphabetic())
}

fn taken_in(map: &HashMap<String, Vec<Character>>, name: &str) -> bool {
    let folded = name.to_lowercase();
    map.values().flatten().any(|character| character.name.to_lowercase() == folded)
}

impl Roster {
    fn taken(&self, name: &str) -> bool {
        taken_in(&self.inner.lock().expect("characters"), name)
    }
}

fn next_id(map: &HashMap<String, Vec<Character>>) -> u32 {
    map.values()
        .flatten()
        .map(|character| character.id)
        .max()
        .unwrap_or(0)
        .saturating_add(1)
}

fn store_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("characters.json")))
        .unwrap_or_else(|| PathBuf::from("characters.json"))
}

fn encode(map: &HashMap<String, Vec<Character>>) -> Result<String, ()> {
    let mut accounts = serde_json::Map::new();
    let mut names: Vec<&String> = map.keys().collect();
    names.sort();
    for name in names {
        let list = map.get(name).map(Vec::as_slice).unwrap_or(&[]);
        let values = list.iter().map(character_json).collect();
        accounts.insert(name.clone(), serde_json::Value::Array(values));
    }
    serde_json::to_string_pretty(&serde_json::Value::Object(accounts)).map_err(|_| ())
}

fn character_json(character: &Character) -> serde_json::Value {
    serde_json::json!({
        "id": character.id,
        "name": character.name,
        "gender": character.gender,
        "race": character.race,
        "class": character.class_id,
        "appearance": character.appearance.to_vec(),
        "second": character.second,
        "appearance2": character.appearance2,
        "details": character.details,
        "shape": character.shape,
    })
}

fn decode(text: &str) -> Option<HashMap<String, Vec<Character>>> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let object = value.as_object()?;
    let mut map = HashMap::new();
    for (account, list) in object {
        let mut characters = Vec::new();
        for item in list.as_array()? {
            characters.push(character_from(item)?);
        }
        map.insert(account.clone(), characters);
    }
    Some(map)
}

fn character_from(value: &serde_json::Value) -> Option<Character> {
    let appearance = bytes_at(value, "appearance")?;
    if appearance.len() != 8 {
        return None;
    }
    let mut appearance_bytes = [0u8; 8];
    appearance_bytes.copy_from_slice(&appearance);
    Some(Character {
        id: value.get("id")?.as_u64()? as u32,
        name: value.get("name")?.as_str()?.to_string(),
        gender: value.get("gender")?.as_i64()? as i32,
        race: value.get("race")?.as_i64()? as i32,
        class_id: value.get("class")?.as_i64()? as i32,
        appearance: appearance_bytes,
        second: value.get("second")?.as_bool()?,
        appearance2: value.get("appearance2")?.as_u64()? as u32,
        details: bytes_at(value, "details").unwrap_or_default(),
        shape: bytes_at(value, "shape").unwrap_or_default(),
    })
}

fn bytes_at(value: &serde_json::Value, key: &str) -> Option<Vec<u8>> {
    value.get(key)?.as_array()?.iter().map(|item| {
        let byte = item.as_u64()?;
        if byte > 255 {
            None
        } else {
            Some(byte as u8)
        }
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft(name: &str) -> NewCharacter {
        NewCharacter {
            name: name.into(),
            gender: 0,
            race: 0,
            class_id: 0,
            appearance: [9; 8],
            second: false,
            appearance2: 3,
            details: vec![1, 2],
            shape: vec![4],
        }
    }

    fn roster() -> Roster {
        let path = std::env::temp_dir().join(format!(
            "terasim-characters-{}-{}.json",
            std::process::id(),
            next_temp()
        ));
        let _ = fs::remove_file(&path);
        Roster::open(path)
    }

    fn next_temp() -> u32 {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(1);
        N.fetch_add(1, Ordering::Relaxed)
    }

    #[test]
    fn name_rules() {
        let roster = roster();
        assert_eq!(roster.check(""), NameStatus::Invalid);
        assert_eq!(roster.check("a b"), NameStatus::Invalid);
        assert_eq!(roster.check("Имя17символовлишнее"), NameStatus::Invalid);
        assert_eq!(roster.check("Мира"), NameStatus::Free);
        roster.create("dev", draft("Мира")).unwrap();
        assert_eq!(roster.check("мира"), NameStatus::Taken);
    }

    #[test]
    fn create_stores_and_reloads() {
        let path = std::env::temp_dir().join(format!("terasim-characters-reload-{}.json", std::process::id()));
        let _ = fs::remove_file(&path);
        let roster = Roster::open(path.clone());
        let created = roster.create("dev", draft("Aria")).unwrap();
        assert_eq!(created.id, 1);
        assert!(roster.create("dev", draft("Aria")).is_err());
        let female = draft("Lena");
        let mut female = female;
        female.gender = 1;
        let created = roster.create("other", female).unwrap();
        assert_eq!(created.id, 2);
        let loaded = Roster::open(path);
        let list = loaded.list("dev");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "Aria");
        assert_eq!(list[0].list_entry(1).lobby_gender, 2);
        assert_eq!(loaded.list("other")[0].list_entry(1).lobby_gender, 1);
    }

    #[test]
    fn eighth_is_the_last() {
        let roster = roster();
        for name in ["Aa", "Bb", "Cc", "Dd", "Ee", "Ff", "Gg", "Hh"] {
            roster.create("dev", draft(name)).unwrap();
        }
        assert!(!roster.allows("dev"));
        assert_eq!(roster.create("dev", draft("Overflow")), Err(CreateError::Full));
    }
}
