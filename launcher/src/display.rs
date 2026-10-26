use std::fs;
use std::path::Path;

pub fn apply(client_root: &Path, width: u32, height: u32, mode: &str) -> Result<(), String> {
    if width == 0 || height == 0 {
        return Err("screen width and height must be greater than zero".into());
    }
    let mode = ScreenMode::parse(mode)?;
    let config = client_root.join("Client").join("S1Game").join("Config");
    let width = width.to_string();
    let height = height.to_string();
    let fullscreen = if mode.fullscreen { "True" } else { "False" };
    let screenmode = mode.screenmode.to_string();

    patch_file(
        &config.join("S1Option.ini"),
        "VIDEO",
        &[
            ("RESOLUTION_X", width.as_str()),
            ("RESOLUTION_Y", height.as_str()),
            ("SCREENMODE", screenmode.as_str()),
            ("IS_FULLSCREEN", fullscreen),
        ],
    )?;
    patch_file(
        &config.join("S1Engine.ini"),
        "WinDrv.WindowsClient",
        &[
            ("StartupFullscreen", fullscreen),
            ("WindowedViewportX", width.as_str()),
            ("WindowedViewportY", height.as_str()),
        ],
    )?;
    patch_file(
        &config.join("S1SystemSettings.ini"),
        "SystemSettings",
        &[
            ("Fullscreen", fullscreen),
            ("ResX", width.as_str()),
            ("ResY", height.as_str()),
        ],
    )?;

    println!("display {width}x{height} {}", mode.name);
    Ok(())
}

struct ScreenMode {
    name: &'static str,
    screenmode: u8,
    fullscreen: bool,
}

impl ScreenMode {
    fn parse(name: &str) -> Result<Self, String> {
        let mode = match name {
            "fullscreen" => Self {
                name: "fullscreen",
                screenmode: 0,
                fullscreen: true,
            },
            "borderless" => Self {
                name: "borderless",
                screenmode: 1,
                fullscreen: false,
            },
            "window" => Self {
                name: "window",
                screenmode: 2,
                fullscreen: false,
            },
            _ => {
                return Err(format!(
                    "screen_mode must be fullscreen, borderless, or window (got {name})"
                ));
            }
        };
        Ok(mode)
    }
}

fn patch_file(path: &Path, section: &str, updates: &[(&str, &str)]) -> Result<(), String> {
    let text = fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    let patched = patch_ini(&text, section, updates).map_err(|err| format!("{}: {err}", path.display()))?;
    if patched != text {
        fs::write(path, patched).map_err(|err| format!("{}: {err}", path.display()))?;
    }
    Ok(())
}

fn patch_ini(text: &str, section: &str, updates: &[(&str, &str)]) -> Result<String, String> {
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let header = format!("[{section}]");
    let mut in_section = false;
    let mut seen = false;
    let mut found = vec![false; updates.len()];
    let mut out = Vec::new();

    let mut lines: Vec<&str> = text.split('\n').collect();
    if text.ends_with('\n') {
        lines.pop();
    }

    for raw in lines {
        let line = raw.trim_end_matches('\r');
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            if in_section {
                push_missing(&mut out, updates, &mut found);
                in_section = false;
            }
            if trimmed == header {
                in_section = true;
                seen = true;
            }
            out.push(line.to_string());
            continue;
        }
        if in_section {
            if let Some((key, _)) = line.split_once('=') {
                if let Some(index) = updates
                    .iter()
                    .position(|(name, _)| key.trim().eq_ignore_ascii_case(name))
                {
                    out.push(format!("{}={}", updates[index].0, updates[index].1));
                    found[index] = true;
                    continue;
                }
            }
        }
        out.push(line.to_string());
    }
    if in_section {
        push_missing(&mut out, updates, &mut found);
    }
    if !seen {
        return Err(format!("{header} not found"));
    }

    let mut result = out.join(newline);
    if text.ends_with('\n') {
        result.push_str(newline);
    }
    Ok(result)
}

fn push_missing(out: &mut Vec<String>, updates: &[(&str, &str)], found: &mut [bool]) {
    for (index, update) in updates.iter().enumerate() {
        if !found[index] {
            out.push(format!("{}={}", update.0, update.1));
            found[index] = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::patch_ini;

    #[test]
    fn replaces_keys_only_in_the_named_section() {
        let text = "\
[SystemSettings]\r\n\
Fullscreen=True\r\n\
ResX=800\r\n\
ResY=600\r\n\
\r\n\
[SystemSettingsMobile]\r\n\
Fullscreen=True\r\n";
        let patched = patch_ini(
            text,
            "SystemSettings",
            &[("Fullscreen", "False"), ("ResX", "1280"), ("ResY", "720")],
        )
        .unwrap();
        assert_eq!(
            patched,
            "\
[SystemSettings]\r\n\
Fullscreen=False\r\n\
ResX=1280\r\n\
ResY=720\r\n\
\r\n\
[SystemSettingsMobile]\r\n\
Fullscreen=True\r\n"
        );
    }

    #[test]
    fn inserts_a_missing_key_before_the_next_section() {
        let text = "[VIDEO]\nIS_FULLSCREEN=True\n\n[AUDIO]\nVOLUME=1\n";
        let patched = patch_ini(text, "VIDEO", &[("SCREENMODE", "2"), ("IS_FULLSCREEN", "False")]).unwrap();
        assert_eq!(
            patched,
            "[VIDEO]\nIS_FULLSCREEN=False\n\nSCREENMODE=2\n[AUDIO]\nVOLUME=1\n"
        );
    }

    #[test]
    fn reports_a_missing_section() {
        let err = patch_ini("[AUDIO]\nVOLUME=1\n", "VIDEO", &[("SCREENMODE", "2")]).unwrap_err();
        assert_eq!(err, "[VIDEO] not found");
    }
}
