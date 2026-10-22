use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

const KEY: &[u8] = b"LogFileEncrypt";

/// Decrypt a TERA `Launch-*.log`.
///
/// The file is UTF-16 LE. Only the low byte of each code unit is XORed with
/// `LogFileEncrypt`, and the key index restarts at the beginning of every
/// log record (the record includes its trailing CR LF).
pub fn decrypt_launch_log(data: &[u8]) -> String {
    let data = data.strip_prefix(&[0xff, 0xfe]).unwrap_or(data);
    let low: Vec<u8> = data.chunks(2).map(|unit| unit[0]).collect();
    let mut out = String::new();
    let mut pos = 0;
    while pos < low.len() {
        let end = line_end(&low, pos).unwrap_or(low.len());
        for (index, byte) in low[pos..end].iter().enumerate() {
            out.push(char::from(byte ^ KEY[index % KEY.len()]));
        }
        pos = end;
    }
    out
}

fn line_end(low: &[u8], start: usize) -> Option<usize> {
    let rest = &low[start..];
    for len in 2..=rest.len() {
        let cr = rest[len - 2] ^ KEY[(len - 2) % KEY.len()];
        let lf = rest[len - 1] ^ KEY[(len - 1) % KEY.len()];
        if cr == b'\r' && lf == b'\n' {
            return Some(start + len);
        }
    }
    None
}

pub fn watch(dir: PathBuf) {
    println!("decrypting client logs in {}", dir.display());
    let mut written: HashMap<PathBuf, u64> = HashMap::new();
    loop {
        poll(&dir, &mut written);
        thread::sleep(Duration::from_millis(400));
    }
}

fn poll(dir: &Path, written: &mut HashMap<PathBuf, u64>) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !is_launch_log(&path) {
            continue;
        }
        let len = entry.metadata().map(|meta| meta.len()).unwrap_or(0);
        if written.get(&path) == Some(&len) {
            continue;
        }
        let data = match fs::read(&path) {
            Ok(data) => data,
            Err(err) => {
                eprintln!("log read {}: {err}", path.display());
                continue;
            }
        };
        let text = decrypt_launch_log(&data);
        let out = path.with_extension("txt");
        match fs::write(&out, text.as_bytes()) {
            Ok(()) => {
                if !written.contains_key(&path) {
                    println!("decrypted {}", out.display());
                }
                written.insert(path, len);
            }
            Err(err) => eprintln!("log write {}: {err}", out.display()),
        }
    }
}

fn is_launch_log(path: &Path) -> bool {
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
    name.starts_with("Launch-") && name.ends_with(".log")
}

#[cfg(test)]
mod tests {
    use super::decrypt_launch_log;

    #[test]
    fn decrypts_a_crash_log() {
        let data = hex(
            "fffe00000000000066000f000500090020004e000c0002001c001e0058006c005e00570069005b005e004a00770058004300430041004a0040007b005500540073006400660017005f00570070005f00420051007c003300430037000b0002001b003e0055004700000008001800040029004e00060000000b001f0006006d0062006d004b00630061006f00",
        );
        let text = decrypt_launch_log(&data);
        assert!(text.starts_with("Log file open, 10/22/26 18:47:35\r\n[0066.49] Error: Fatal error!\r\n"));
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect()
    }
}
