mod log_decrypt;
mod protocol;

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::exit;
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use serde::Deserialize;
use windows::Win32::Foundation::{CloseHandle, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::DataExchange::COPYDATASTRUCT;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Threading::{CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, PostMessageW, PostQuitMessage,
    RegisterClassExW, SendMessageW, TranslateMessage, CW_USEDEFAULT, MSG, WINDOW_EX_STYLE,
    WINDOW_STYLE, WM_COPYDATA, WM_DESTROY, WM_USER, WNDCLASSEXW,
};
use windows::core::PCWSTR;

use protocol::Session;

const CLASS_NAME: &str = "EME.LauncherWnd";

static SESSION: OnceLock<Session> = OnceLock::new();

struct PendingReply {
    target: isize,
    dw_data: usize,
    data: Vec<u8>,
}

static REPLIES: Mutex<Vec<PendingReply>> = Mutex::new(Vec::new());

#[derive(Debug, Deserialize)]
struct Config {
    client_root: PathBuf,
    #[serde(default = "default_account")]
    account: String,
    #[serde(default = "default_http_port")]
    http_port: u16,
    #[serde(default = "default_host")]
    game_host: String,
    #[serde(default = "default_game_port")]
    game_port: u16,
    #[serde(default = "default_server_name")]
    server_name: String,
}

fn default_account() -> String {
    "dev".into()
}
fn default_http_port() -> u16 {
    17801
}
fn default_host() -> String {
    "127.0.0.1".into()
}
fn default_game_port() -> u16 {
    7801
}
fn default_server_name() -> String {
    "Local".into()
}

fn main() {
    let config = match load_config() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("config: {err}");
            exit(1);
        }
    };

    let server_list_url = format!("http://127.0.0.1:{}/servers", config.http_port);
    let xml = server_list_xml(&config);
    let session = Session::new(config.account.clone(), server_list_url);
    SESSION.set(session).ok();

    let xml_for_http = xml.clone();
    let http_port = config.http_port;
    thread::spawn(move || {
        if let Err(err) = serve_http(http_port, &xml_for_http) {
            eprintln!("http: {err}");
        }
    });

    let log_dir = config
        .client_root
        .join("Client")
        .join("S1Game")
        .join("Logs");
    thread::spawn(move || log_decrypt::watch(log_dir));

    if let Err(err) = run_window(&config) {
        eprintln!("launcher: {err}");
        exit(1);
    }
}

fn load_config() -> Result<Config, String> {
    let path = config_path();
    let text = fs::read_to_string(&path).map_err(|err| format!("{}: {err}", path.display()))?;
    serde_json::from_str(&text).map_err(|err| format!("{}: {err}", path.display()))
}

fn config_path() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let beside = dir.join("launcher.json");
            if beside.is_file() {
                return beside;
            }
        }
    }
    PathBuf::from("launcher.json")
}

fn server_list_xml(config: &Config) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<serverlist>
  <server>
    <id>1</id>
    <ip>{host}</ip>
    <port>{port}</port>
    <category sort="1">TERA</category>
    <name raw_name="{name}">{name}</name>
    <crowdness sort="1">smooth</crowdness>
    <open sort="1">recommended</open>
    <permission_mask>0x00000000</permission_mask>
    <server_stat>0x00000000</server_stat>
    <popup></popup>
    <language>en</language>
  </server>
</serverlist>
"#,
        host = xml_escape(&config.game_host),
        port = config.game_port,
        name = xml_escape(&config.server_name),
    )
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn serve_http(port: u16, xml: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    println!("server list on http://127.0.0.1:{port}/servers");
    for stream in listener.incoming() {
        let mut stream = stream?;
        let mut buf = [0_u8; 2048];
        let _ = stream.read(&mut buf);
        println!("http request");
        let header = format!(
            "HTTP/1.0 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            xml.len()
        );
        stream.write_all(header.as_bytes())?;
        stream.write_all(xml.as_bytes())?;
    }
    Ok(())
}

fn run_window(config: &Config) -> Result<(), String> {
    let class_name = wide(CLASS_NAME);
    let instance = unsafe { GetModuleHandleW(None) }.map_err(|err| err.to_string())?;

    let class = WNDCLASSEXW {
        cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
        lpfnWndProc: Some(wnd_proc),
        hInstance: instance.into(),
        lpszClassName: PCWSTR(class_name.as_ptr()),
        ..Default::default()
    };

    let atom = unsafe { RegisterClassExW(&class) };
    if atom == 0 {
        return Err(format!(
            "RegisterClassExW: {}",
            windows::core::Error::from_win32()
        ));
    }

    let hwnd = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            PCWSTR(class_name.as_ptr()),
            PCWSTR(class_name.as_ptr()),
            WINDOW_STYLE::default(),
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            None,
            None,
            Some(instance.into()),
            None,
        )
    }
    .map_err(|err| err.to_string())?;

    println!("window {CLASS_NAME} hwnd={hwnd:?}");
    spawn_tl(config)?;

    let mut msg = MSG::default();
    loop {
        let got = unsafe { GetMessageW(&mut msg, None, 0, 0) };
        if got.0 == 0 || got.0 == -1 {
            break;
        }
        unsafe {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    Ok(())
}

fn spawn_tl(config: &Config) -> Result<(), String> {
    let tl = config.client_root.join("Client").join("Tl.exe");
    let cwd = config.client_root.join("Client");
    if !tl.is_file() {
        return Err(format!("missing {}", tl.display()));
    }

    let mut application = wide(tl.to_str().ok_or("client path is not unicode")?);
    let mut directory = wide(cwd.to_str().ok_or("client path is not unicode")?);
    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut process = PROCESS_INFORMATION::default();

    unsafe {
        CreateProcessW(
            PCWSTR(application.as_mut_ptr()),
            None,
            None,
            None,
            false,
            Default::default(),
            None,
            PCWSTR(directory.as_mut_ptr()),
            &startup,
            &mut process,
        )
    }
    .map_err(|err| format!("CreateProcess {}: {err}", tl.display()))?;

    println!("started {}", tl.display());
    unsafe {
        let _ = CloseHandle(process.hProcess);
        let _ = CloseHandle(process.hThread);
    }
    Ok(())
}

unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_COPYDATA => handle_copydata(hwnd, wparam, lparam),
        msg if msg == WM_USER => {
            flush_replies(hwnd);
            LRESULT(0)
        }
        WM_DESTROY => {
            unsafe { PostQuitMessage(0) };
            LRESULT(0)
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

fn handle_copydata(hwnd: HWND, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let Some(session) = SESSION.get() else {
        return LRESULT(0);
    };
    let copy = unsafe { &*(lparam.0 as *const COPYDATASTRUCT) };
    let bytes = if copy.lpData.is_null() || copy.cbData == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(copy.lpData as *const u8, copy.cbData as usize) }
    };
    let text = String::from_utf8_lossy(bytes).trim_end_matches('\0').to_string();
    println!("recv dwData={:#x} {text}", copy.dwData);

    let reply = session.reply(copy.dwData, &text);
    if reply.quit {
        thread::spawn(|| {
            thread::sleep(Duration::from_millis(200));
            unsafe { PostQuitMessage(0) };
        });
    }

    if let Some(payload) = reply.payload {
        println!("queue dwData={:#x} {payload}", copy.dwData);
        let mut data = payload.into_bytes();
        if reply.nul_terminated {
            data.push(0);
        }
        REPLIES.lock().expect("reply queue").push(PendingReply {
            target: wparam.0 as isize,
            dw_data: copy.dwData,
            data,
        });
        unsafe {
            let _ = PostMessageW(Some(hwnd), WM_USER, WPARAM(0), LPARAM(0));
        }
    }

    LRESULT(1)
}

fn flush_replies(hwnd: HWND) {
    let pending = std::mem::take(&mut *REPLIES.lock().expect("reply queue"));
    for mut item in pending {
        println!(
            "send dwData={:#x} {}",
            item.dw_data,
            String::from_utf8_lossy(item.data.split(|byte| *byte == 0).next().unwrap_or(&[]))
        );
        let response = COPYDATASTRUCT {
            dwData: item.dw_data,
            cbData: item.data.len() as u32,
            lpData: item.data.as_mut_ptr() as *mut _,
        };
        let target = HWND(item.target as *mut _);
        unsafe {
            SendMessageW(
                target,
                WM_COPYDATA,
                Some(WPARAM(hwnd.0 as usize)),
                Some(LPARAM(&response as *const _ as isize)),
            );
        }
    }
}

fn wide(value: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
