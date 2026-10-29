mod display;
mod log_decrypt;
mod patch;
mod protocol;

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use serde::Deserialize;
use windows::Win32::Foundation::{CloseHandle, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::DataExchange::COPYDATASTRUCT;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Threading::{CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW};
use windows::Win32::UI::Controls::Dialogs::{GetOpenFileNameW, OPENFILENAMEW, OFN_FILEMUSTEXIST, OFN_PATHMUSTEXIST};
use windows::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, GetWindowTextW, MessageBoxW,
    PostMessageW, PostQuitMessage, RegisterClassExW, SendMessageW, SetWindowTextW, ShowWindow,
    TranslateMessage, CW_USEDEFAULT, ES_AUTOHSCROLL, HMENU, MB_ICONERROR, MB_OK, MSG, SW_SHOW,
    WINDOW_EX_STYLE, WINDOW_STYLE, WM_COMMAND, WM_COPYDATA, WM_DESTROY, WM_USER, WNDCLASSEXW,
    WS_BORDER, WS_CAPTION, WS_CHILD, WS_MINIMIZEBOX, WS_OVERLAPPED, WS_SYSMENU, WS_TABSTOP,
    WS_VISIBLE,
};
use windows::core::{PCWSTR, PWSTR};

use protocol::Session;

const CLASS_NAME: &str = "EME.LauncherWnd";
const WM_APP_QUIT: u32 = WM_USER + 1;
const WM_APP_ENABLE: u32 = WM_USER + 2;
const ID_BROWSE: u16 = 101;
const ID_LAUNCH: u16 = 102;

static SESSION: OnceLock<Session> = OnceLock::new();
static CONFIG: OnceLock<Config> = OnceLock::new();
static HTTP_STARTED: AtomicBool = AtomicBool::new(false);
static LOGS_STARTED: AtomicBool = AtomicBool::new(false);
static MAIN_HWND: AtomicIsize = AtomicIsize::new(0);
static PATH_HWND: AtomicIsize = AtomicIsize::new(0);
static LAUNCH_HWND: AtomicIsize = AtomicIsize::new(0);
static STATUS_HWND: AtomicIsize = AtomicIsize::new(0);

struct PendingReply {
    target: isize,
    dw_data: usize,
    data: Vec<u8>,
}

static REPLIES: Mutex<Vec<PendingReply>> = Mutex::new(Vec::new());

#[derive(Debug, Deserialize, Clone)]
struct Config {
    client_root: PathBuf,
    #[serde(default)]
    client_exe: PathBuf,
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
    #[serde(default = "default_arbiter_http")]
    arbiter_http: String,
    #[serde(default = "default_screen_width")]
    screen_width: u32,
    #[serde(default = "default_screen_height")]
    screen_height: u32,
    #[serde(default = "default_screen_mode")]
    screen_mode: String,
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
fn default_arbiter_http() -> String {
    "http://127.0.0.1:17802".into()
}
fn default_screen_width() -> u32 {
    1280
}
fn default_screen_height() -> u32 {
    720
}
fn default_screen_mode() -> String {
    "window".into()
}

fn main() {
    let config = match load_config() {
        Ok(config) => config,
        Err(err) => fail(&format!("config: {err}")),
    };

    if let Err(err) = run_window(&config) {
        fail(&format!("launcher: {err}"));
    }
}

fn fail(message: &str) -> ! {
    eprintln!("{message}");
    let text = wide(message);
    let title = wide("TERASim");
    unsafe {
        let _ = MessageBoxW(
            None,
            PCWSTR(text.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_OK | MB_ICONERROR,
        );
    }
    exit(1);
}

fn load_config() -> Result<Config, String> {
    let path = config_path();
    let text = fs::read_to_string(&path).map_err(|err| format!("{}: {err}", path.display()))?;
    serde_json::from_str(&text).map_err(|err| format!("{}: {err}", path.display()))
}

fn config_path() -> PathBuf {
    let mut starts = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        starts.push(cwd);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            starts.push(dir.to_path_buf());
        }
    }
    for start in starts {
        if let Some(path) = config_candidates(&start).into_iter().find(|path| path.is_file()) {
            return path;
        }
    }
    PathBuf::from("launcher.json")
}

fn config_candidates(start: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut current = Some(start);
    while let Some(dir) = current {
        found.push(dir.join("launcher.json"));
        found.push(dir.join("launcher").join("launcher.json"));
        current = dir.parent();
    }
    found
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

fn fetch_ticket(base: &str, account: &str) -> Result<String, String> {
    let host = base
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string();
    let mut stream = std::net::TcpStream::connect(host.as_str())
        .map_err(|err| format!("{host}: {err}"))?;
    let account = url_encode(account);
    let request = format!(
        "GET /tickets?account={account} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|err| err.to_string())?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|err| err.to_string())?;
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(response.as_str());
    let value: serde_json::Value =
        serde_json::from_str(body.trim()).map_err(|err| format!("ticket response: {err}"))?;
    value["ticket"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| "ticket response has no ticket".into())
}

fn url_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn serve_http(port: u16, xml: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    println!("server list on http://127.0.0.1:{port}/servers");
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!("http accept: {err}");
                continue;
            }
        };
        let mut buf = [0_u8; 2048];
        let _ = stream.read(&mut buf);
        println!("http request");
        let header = format!(
            "HTTP/1.0 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            xml.len()
        );
        if let Err(err) = stream
            .write_all(header.as_bytes())
            .and_then(|_| stream.write_all(xml.as_bytes()))
        {
            eprintln!("http: {err}");
        }
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

    let title = wide("TERASim");
    let hwnd = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            PCWSTR(class_name.as_ptr()),
            PCWSTR(title.as_ptr()),
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            640,
            210,
            None,
            None,
            Some(instance.into()),
            None,
        )
    }
    .map_err(|err| err.to_string())?;

    let path_box = child(
        hwnd,
        instance.into(),
        "EDIT",
        "",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | WINDOW_STYLE(ES_AUTOHSCROLL as u32),
        16,
        40,
        470,
        24,
        100,
    )?;
    let _browse = child(hwnd, instance.into(), "BUTTON", "Обзор", button_style(), 496, 38, 112, 28, ID_BROWSE as isize)?;
    let launch = child(hwnd, instance.into(), "BUTTON", "Запустить", button_style(), 16, 80, 140, 32, ID_LAUNCH as isize)?;
    let status = child(
        hwnd,
        instance.into(),
        "STATIC",
        "Выберите файл клиента и нажмите «Запустить»",
        WS_CHILD | WS_VISIBLE,
        170,
        86,
        440,
        40,
        104,
    )?;
    let _label = child(hwnd, instance.into(), "STATIC", "Файл клиента", WS_CHILD | WS_VISIBLE, 16, 16, 200, 18, 105)?;
    let initial = initial_exe(config);
    set_text(path_box, &initial.display().to_string());

    MAIN_HWND.store(hwnd.0 as isize, Ordering::Relaxed);
    PATH_HWND.store(path_box.0 as isize, Ordering::Relaxed);
    LAUNCH_HWND.store(launch.0 as isize, Ordering::Relaxed);
    STATUS_HWND.store(status.0 as isize, Ordering::Relaxed);
    let _ = CONFIG.set(config.clone());
    println!("window {CLASS_NAME} hwnd={hwnd:?}");
    unsafe { let _ = ShowWindow(hwnd, SW_SHOW); };

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

fn button_style() -> WINDOW_STYLE {
    WS_CHILD | WS_VISIBLE | WS_TABSTOP
}

fn child(
    parent: HWND,
    instance: windows::Win32::Foundation::HINSTANCE,
    class: &str,
    text: &str,
    style: WINDOW_STYLE,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    id: isize,
) -> Result<HWND, String> {
    let class_name = wide(class);
    let caption = wide(text);
    unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            PCWSTR(class_name.as_ptr()),
            PCWSTR(caption.as_ptr()),
            style,
            x,
            y,
            width,
            height,
            Some(parent),
            Some(HMENU(id as *mut _)),
            Some(instance),
            None,
        )
    }
    .map_err(|err| err.to_string())
}

fn initial_exe(config: &Config) -> PathBuf {
    if !config.client_exe.as_os_str().is_empty() {
        config.client_exe.clone()
    } else {
        config.client_root.join("Client").join("Tl.exe")
    }
}

fn client_root_from_exe(exe: &Path) -> PathBuf {
    let mut current = exe.parent();
    while let Some(dir) = current {
        if dir.join("Client").join("S1Game").is_dir() {
            return dir.to_path_buf();
        }
        if dir.file_name().is_some_and(|name| name == "Client") && dir.join("S1Game").is_dir() {
            if let Some(root) = dir.parent() {
                return root.to_path_buf();
            }
        }
        current = dir.parent();
    }
    exe.parent().unwrap_or(exe).to_path_buf()
}

fn on_launch() {
    let Some(config) = CONFIG.get() else {
        return;
    };
    let exe = PathBuf::from(window_text(hwnd_of(&PATH_HWND)));
    if !exe.is_file() {
        set_status(&format!("нет файла {}", exe.display()));
        return;
    }
    unsafe {
        let _ = EnableWindow(hwnd_of(&LAUNCH_HWND), false);
    }
    let config = config.clone();
    let config_path = config_path();
    thread::spawn(move || {
        if let Err(err) = launch(&config, &config_path, &exe) {
            eprintln!("launch: {err}");
            set_status(&err);
            let main = MAIN_HWND.load(Ordering::Relaxed);
            if main != 0 {
                unsafe {
                    let _ = PostMessageW(Some(HWND(main as *mut _)), WM_APP_ENABLE, WPARAM(0), LPARAM(0));
                }
            }
        }
    });
}

fn launch(config: &Config, config_path: &Path, exe: &Path) -> Result<(), String> {
    let root = client_root_from_exe(exe);
    set_status("Настраиваю окно клиента");
    display::apply(&root, config.screen_width, config.screen_height, &config.screen_mode)?;

    set_status("Беру билет");
    ensure_session(config, &root)?;
    let _ = remember_exe(config_path, exe);

    set_status("Запускаю клиент");
    let before = patch::pids("TERA.exe");
    let _pid = start_process(exe)?;
    set_status("Жду распаковку TERA.exe");
    let game = patch::wait_for_new("TERA.exe", &before, Duration::from_secs(120))?;
    set_status("Ставлю патч");
    patch::arm(game)?;
    set_status("Патч установлен. «Новый персонаж» откроет выбор расы.");
    println!("patched TERA.exe pid {game}");
    Ok(())
}

fn ensure_session(config: &Config, root: &Path) -> Result<(), String> {
    if SESSION.get().is_some() {
        return Ok(());
    }
    let server_list_url = format!("http://127.0.0.1:{}/servers", config.http_port);
    let ticket = fetch_ticket(&config.arbiter_http, &config.account)?;
    let session = Session::new(config.account.clone(), server_list_url, ticket);
    SESSION.set(session).ok();

    let xml = server_list_xml(config);
    let http_port = config.http_port;
    if !HTTP_STARTED.swap(true, Ordering::SeqCst) {
        thread::spawn(move || {
            if let Err(err) = serve_http(http_port, &xml) {
                eprintln!("http: {err}");
            }
        });
    }
    let log_dir = root.join("Client").join("S1Game").join("Logs");
    if !LOGS_STARTED.swap(true, Ordering::SeqCst) {
        thread::spawn(move || log_decrypt::watch(log_dir));
    }
    Ok(())
}

fn remember_exe(path: &Path, exe: &Path) -> Result<(), String> {
    let text = fs::read_to_string(path).map_err(|err| err.to_string())?;
    let mut value: serde_json::Value = serde_json::from_str(&text).map_err(|err| err.to_string())?;
    value["client_exe"] = serde_json::Value::String(exe.display().to_string());
    let pretty = serde_json::to_string_pretty(&value).map_err(|err| err.to_string())?;
    fs::write(path, pretty + "\n").map_err(|err| err.to_string())
}

fn start_process(exe: &Path) -> Result<u32, String> {
    let cwd = exe.parent().ok_or("у файла клиента нет папки")?;
    let mut application = wide(exe.to_str().ok_or("путь клиента не unicode")?);
    let mut directory = wide(cwd.to_str().ok_or("путь клиента не unicode")?);
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
    .map_err(|err| format!("запуск {}: {err}", exe.display()))?;
    let pid = process.dwProcessId;
    println!("started {} pid {pid}", exe.display());
    unsafe {
        let _ = CloseHandle(process.hProcess);
        let _ = CloseHandle(process.hThread);
    }
    Ok(pid)
}

fn browse(owner: HWND) {
    let current = window_text(hwnd_of(&PATH_HWND));
    let mut file = [0u16; 520];
    for (index, unit) in current.encode_utf16().take(file.len() - 1).enumerate() {
        file[index] = unit;
    }
    let filter = wide_units("Executable\0*.exe\0\0");
    let title = wide("Файл клиента");
    let mut dialog = OPENFILENAMEW {
        lStructSize: std::mem::size_of::<OPENFILENAMEW>() as u32,
        hwndOwner: owner,
        lpstrFilter: PCWSTR(filter.as_ptr()),
        lpstrFile: PWSTR(file.as_mut_ptr()),
        nMaxFile: file.len() as u32,
        lpstrTitle: PCWSTR(title.as_ptr()),
        Flags: OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST,
        ..OPENFILENAMEW::default()
    };
    let picked = unsafe { GetOpenFileNameW(&mut dialog) };
    if picked.as_bool() {
        let end = file.iter().position(|unit| *unit == 0).unwrap_or(file.len());
        set_text(hwnd_of(&PATH_HWND), &String::from_utf16_lossy(&file[..end]));
    }
}

fn window_text(hwnd: HWND) -> String {
    let mut buf = [0u16; 1024];
    let count = unsafe { GetWindowTextW(hwnd, &mut buf) };
    if count <= 0 {
        return String::new();
    }
    String::from_utf16_lossy(&buf[..count as usize])
}

fn set_text(hwnd: HWND, text: &str) {
    let wide = wide(text);
    unsafe {
        let _ = SetWindowTextW(hwnd, PCWSTR(wide.as_ptr()));
    }
}

fn set_status(text: &str) {
    println!("{text}");
    let hwnd = hwnd_of(&STATUS_HWND);
    if !hwnd.0.is_null() {
        set_text(hwnd, text);
    }
}

fn hwnd_of(slot: &AtomicIsize) -> HWND {
    HWND(slot.load(Ordering::Relaxed) as *mut _)
}

fn wide_units(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_COPYDATA => handle_copydata(hwnd, wparam, lparam),
        WM_COMMAND => {
            let id = (wparam.0 & 0xffff) as u16;
            let note = ((wparam.0 >> 16) & 0xffff) as u16;
            if note == 0 {
                match id {
                    ID_BROWSE => browse(hwnd),
                    ID_LAUNCH => on_launch(),
                    _ => {}
                }
            }
            LRESULT(0)
        }
        msg if msg == WM_USER => {
            flush_replies(hwnd);
            LRESULT(0)
        }
        msg if msg == WM_APP_ENABLE => {
            unsafe {
                let _ = EnableWindow(hwnd_of(&LAUNCH_HWND), true);
            }
            LRESULT(0)
        }
        msg if msg == WM_APP_QUIT => {
            unsafe { PostQuitMessage(0) };
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
        let window = hwnd.0 as isize;
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(200));
            unsafe {
                let _ = PostMessageW(
                    Some(HWND(window as *mut _)),
                    WM_APP_QUIT,
                    WPARAM(0),
                    LPARAM(0),
                );
            }
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

#[cfg(test)]
mod tests {
    use super::{client_root_from_exe, config_candidates, url_encode};
    use std::fs;

    #[test]
    fn encodes_reserved_characters() {
        assert_eq!(url_encode("dev"), "dev");
        assert_eq!(url_encode("a b"), "a%20b");
        assert_eq!(url_encode("a\"b&c"), "a%22b%26c");
    }

    #[test]
    fn client_root_is_the_directory_above_client() {
        let root = std::env::temp_dir().join(format!("terasim-root-{}", std::process::id()));
        let client = root.join("Client");
        fs::create_dir_all(client.join("S1Game")).unwrap();
        fs::create_dir_all(client.join("Binaries")).unwrap();
        let tera = client.join("Binaries").join("TERA.exe");
        let tl = client.join("Tl.exe");
        assert_eq!(client_root_from_exe(&tera), root);
        assert_eq!(client_root_from_exe(&tl), root);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn config_search_climbs_to_the_launcher_folder() {
        let root = std::env::temp_dir().join(format!("terasim-cfg-{}", std::process::id()));
        let debug = root.join("target").join("debug");
        fs::create_dir_all(&debug).unwrap();
        fs::create_dir_all(root.join("launcher")).unwrap();
        let expected = root.join("launcher").join("launcher.json");
        fs::write(&expected, "{}").unwrap();
        let hit = config_candidates(&debug).into_iter().find(|path| path.is_file());
        assert_eq!(hit.as_deref(), Some(expected.as_path()));
        let _ = fs::remove_dir_all(&root);
    }
}

fn wide(value: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
