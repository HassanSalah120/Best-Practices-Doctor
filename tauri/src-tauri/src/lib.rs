use tauri::{AppHandle, Manager};
use tauri_plugin_shell::ShellExt;
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_dialog::DialogExt;
use std::sync::{Arc, Mutex};
use std::path::PathBuf;
use std::time::Duration;
use serde::{Serialize, Deserialize};
use tokio::time::sleep;

fn home_discovery_dir() -> Option<PathBuf> {
    let home = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")).ok()?;
    Some(PathBuf::from(home).join(".best-practices-doctor"))
}

fn candidate_discovery_files(run_id: &str, preferred_dir: &PathBuf) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = vec![preferred_dir.clone()];
    if let Some(home_dir) = home_discovery_dir() {
        if home_dir != *preferred_dir {
            dirs.push(home_dir);
        }
    }
    dirs.into_iter()
        .map(|d| d.join(format!("bpd-discovery-{}.json", run_id)))
        .collect()
}

#[derive(Clone, Serialize, Deserialize)]
struct BackendInfo {
    port: u16,
    token: String,
}

struct AppState {
    backend_info: Arc<Mutex<Option<BackendInfo>>>,
    sidecar_child: Arc<Mutex<Option<CommandChild>>>,
    _run_id: String,
    discovery_dir: Arc<Mutex<PathBuf>>,
}

#[tauri::command]
async fn get_backend_info(state: tauri::State<'_, AppState>) -> Result<BackendInfo, String> {
    // Fast path: already discovered.
    {
        let info = state.backend_info.lock().map_err(|_| "Failed to lock state")?;
        if let Some(v) = info.clone() {
            return Ok(v);
        }
    }

    // Fallback: attempt to read the discovery file on-demand.
    let run_id = state._run_id.clone();
    let discovery_dir = state.discovery_dir.lock().map_err(|_| "Failed to lock state")?.clone();
    let candidates = candidate_discovery_files(&run_id, &discovery_dir);

    for discovery_file in &candidates {
        if discovery_file.exists() {
            if let Ok(content) = std::fs::read_to_string(discovery_file) {
                if let Ok(info) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let (Some(port), Some(token)) = (info["port"].as_u64(), info["token"].as_str()) {
                        let found = BackendInfo { port: port as u16, token: token.to_string() };
                        if let Ok(mut lock) = state.backend_info.lock() {
                            *lock = Some(found.clone());
                        }
                        return Ok(found);
                    }
                }
            }
        }
    }

    let attempted = candidates
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(" OR ");

    Err(format!("Backend not ready (waiting for discovery file: {attempted})"))
}

#[tauri::command]
async fn pick_directory(app: AppHandle) -> Result<Option<String>, String> {
    // Commands do not run on the main thread, so the blocking API is fine here.
    let path = app.dialog().file().blocking_pick_folder();
    Ok(path.map(|p| p.to_string()))
}

fn kill_backend(child: Option<CommandChild>) {
    if let Some(child) = child {
        println!("Gracefully shutting down backend...");
        // In a real scenario, we might send a signal or a shutdown request to the API.
        // For sidecars, Tauri's Child.kill() is often immediate, but we can try to be nice
        // if the platform supports it (on Windows, kill() is basically terminate).
        let _ = child.kill();
        
        // escalation logic: if it were asynchronous, we'd wait here.
        // For now, tauri-plugin-shell kill() is the primary tool.
    }
}

pub fn run() {
    let run_id = uuid::Uuid::new_v4().to_string();
    let backend_info = Arc::new(Mutex::new(None));
    let sidecar_child = Arc::new(Mutex::new(None));

    // Default discovery dir (overridden in setup once we have an AppHandle).
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string());
    let discovery_dir = Arc::new(Mutex::new(PathBuf::from(home).join(".best-practices-doctor")));
     
    let backend_info_clone = backend_info.clone();
    let sidecar_child_clone = sidecar_child.clone();
    let run_id_clone = run_id.clone();
    let discovery_dir_clone = discovery_dir.clone();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            let _ = app.get_webview_window("main")
                .expect("no main window")
                .set_focus();
        }))
        .manage(AppState {
            backend_info,
            sidecar_child,
            _run_id: run_id.clone(),
            discovery_dir,
        })
        .invoke_handler(tauri::generate_handler![get_backend_info, pick_directory])
        .setup(move |app| {
            let app_handle = app.handle().clone();
            let run_id = run_id_clone.clone();
            let backend_info = backend_info_clone.clone();
            let sidecar_child = sidecar_child_clone.clone();
            let discovery_dir = discovery_dir_clone.clone();

            // Prefer OS-specific app data dir. This is more reliable than HOME/USERPROFILE
            // for sidecar processes spawned by the shell plugin.
            if let Ok(app_data) = app_handle.path().app_data_dir() {
                if let Ok(mut lock) = discovery_dir.lock() {
                    *lock = app_data.clone();
                }
            }
            let discovery_dir_value = discovery_dir.lock().unwrap().clone();

            tauri::async_runtime::spawn(async move {
                // Dev reliability: allow forcing the Python backend (from source) to avoid stale/broken
                // bundled sidecar EXEs during active development.
                let force_py_backend =
                    cfg!(debug_assertions)
                        && std::env::var("BPD_DEV_FORCE_PYTHON_BACKEND")
                            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                            .unwrap_or(false);

                if force_py_backend {
                    println!("BPD_DEV_FORCE_PYTHON_BACKEND=1: skipping sidecar, starting python backend ...");

                    let backend_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join("..")
                        .join("..")
                        .join("backend");
                    let py_cmd = app_handle
                        .shell()
                        .command("python")
                        .current_dir(backend_dir)
                        .env("BPD_APP_DATA_DIR", discovery_dir_value.to_string_lossy().to_string())
                        .args(&["main.py", "--run-id", &run_id])
                        .spawn();

                    match py_cmd {
                        Ok((mut py_rx, py_child)) => {
                            println!("Python backend spawned. Child PID: {:?}", py_child.pid());
                            if let Ok(mut lock) = sidecar_child.lock() {
                                *lock = Some(py_child);
                            }

                            let candidates = candidate_discovery_files(&run_id, &discovery_dir_value);
                            println!("Looking for discovery file at: {:?}", candidates);

                            // Wait briefly for discovery file from fallback.
                            for _ in 0..120 {
                                let mut found = false;
                                for discovery_file in &candidates {
                                    if discovery_file.exists() {
                                        if let Ok(content) = std::fs::read_to_string(discovery_file) {
                                            if let Ok(info) = serde_json::from_str::<serde_json::Value>(&content) {
                                                if let (Some(port), Some(token)) = (info["port"].as_u64(), info["token"].as_str()) {
                                                    println!("Backend info loaded (python forced): Port {}, Token found", port);
                                                    if let Ok(mut state) = backend_info.lock() {
                                                        *state = Some(BackendInfo {
                                                            port: port as u16,
                                                            token: token.to_string(),
                                                        });
                                                    }
                                                    found = true;
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                                if found {
                                    break;
                                }
                                sleep(Duration::from_millis(500)).await;
                            }

                            while let Some(event) = py_rx.recv().await {
                                match event {
                                    CommandEvent::Stdout(line) => println!("Backend OUT: {}", String::from_utf8_lossy(&line)),
                                    CommandEvent::Stderr(line) => println!("Backend ERR: {}", String::from_utf8_lossy(&line)),
                                    CommandEvent::Error(err) => println!("Backend ERROR Event: {}", err),
                                    CommandEvent::Terminated(payload) => println!("Backend Terminated: {:?}", payload),
                                    _ => {}
                                }
                            }
                            return;
                        }
                        Err(e) => {
                            println!("Python backend failed to spawn: {}", e);
                            return;
                        }
                    }
                }

                println!("Attempting to spawn sidecar...");
                let sidecar_cmd = app_handle.shell().sidecar("python-backend");
                if let Err(e) = &sidecar_cmd {
                    println!("Failed to create sidecar command: {}", e);
                }
                
                let sidecar = sidecar_cmd.unwrap();
                let spawn_result = sidecar
                    .env("BPD_APP_DATA_DIR", discovery_dir_value.to_string_lossy().to_string())
                    .args(&["--run-id", &run_id])
                    .spawn();

                if let Err(e) = &spawn_result {
                    println!("Failed to spawn sidecar process: {}", e);
                    return;
                }

                let (mut rx, child) = spawn_result.unwrap();
                println!("Sidecar spawned successfully. Child PID: {:?}", child.pid());

                {
                    let mut lock = sidecar_child.lock().unwrap();
                    *lock = Some(child);
                }

                let candidates = candidate_discovery_files(&run_id, &discovery_dir_value);
                println!("Looking for discovery file at: {:?}", candidates);

                // PyInstaller sidecar can take a while to self-extract and start the server.
                // In dev builds, fail fast to allow python fallback when the sidecar is broken.
                let max_attempts = if cfg!(debug_assertions) { 40 } else { 240 };
                let mut attempts = 0;
                let mut loaded = false;
                while attempts < max_attempts {
                    for discovery_file in &candidates {
                        if discovery_file.exists() {
                            println!("Discovery file found!");
                            if let Ok(content) = std::fs::read_to_string(discovery_file) {
                                if let Ok(info) = serde_json::from_str::<serde_json::Value>(&content) {
                                    if let (Some(port), Some(token)) = (info["port"].as_u64(), info["token"].as_str()) {
                                        println!("Backend info loaded: Port {}, Token found", port);
                                        let mut state = backend_info.lock().unwrap();
                                        *state = Some(BackendInfo {
                                            port: port as u16,
                                            token: token.to_string(),
                                        });
                                        loaded = true;
                                        break;
                                    } else {
                                        println!("Invalid JSON structure in discovery file");
                                    }
                                } else {
                                    println!("Failed to parse discovery file JSON");
                                }
                            } else {
                                println!("Failed to read discovery file");
                            }
                        }
                    }
                    if loaded {
                        break;
                    }

                    if attempts % 10 == 0 {
                        println!(
                            "Discovery file not found yet (attempt {}/{})",
                            attempts + 1,
                            max_attempts
                        );
                    }

                    attempts += 1;
                    sleep(Duration::from_millis(500)).await;
                }

                if attempts >= max_attempts {
                    println!("Gave up waiting for backend discovery file.");
                }

                // If the PyInstaller sidecar fails to run (common in dev environments with unsupported
                // Python/PyInstaller combos), fall back to running the backend via the local python
                // interpreter. This is DEV convenience only; production still uses the bundled sidecar.
                if !loaded {
                    println!("Attempting python fallback for backend (dev mode) ...");
                    // Resolve backend path relative to the Tauri crate at build time:
                    // tauri/src-tauri -> ../../backend
                    let backend_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join("..")
                        .join("..")
                        .join("backend");
                    let py_cmd = app_handle
                        .shell()
                        .command("python")
                        .current_dir(backend_dir)
                        .env("BPD_APP_DATA_DIR", discovery_dir_value.to_string_lossy().to_string())
                        .args(&["main.py", "--run-id", &run_id])
                        .spawn();

                    match py_cmd {
                        Ok((mut py_rx, py_child)) => {
                            println!("Python backend spawned. Child PID: {:?}", py_child.pid());
                            if let Ok(mut lock) = sidecar_child.lock() {
                                *lock = Some(py_child);
                            }

                            // Wait briefly for discovery file from fallback.
                            for _ in 0..60 {
                                let mut found = false;
                                for discovery_file in &candidates {
                                    if discovery_file.exists() {
                                        if let Ok(content) = std::fs::read_to_string(discovery_file) {
                                            if let Ok(info) = serde_json::from_str::<serde_json::Value>(&content) {
                                                if let (Some(port), Some(token)) = (info["port"].as_u64(), info["token"].as_str()) {
                                                    println!("Backend info loaded (python fallback): Port {}, Token found", port);
                                                    if let Ok(mut state) = backend_info.lock() {
                                                        *state = Some(BackendInfo {
                                                            port: port as u16,
                                                            token: token.to_string(),
                                                        });
                                                    }
                                                    found = true;
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                                if found {
                                    break;
                                }
                                sleep(Duration::from_millis(500)).await;
                            }

                            // Drain events from fallback backend as well.
                            while let Some(event) = py_rx.recv().await {
                                match event {
                                    CommandEvent::Stdout(line) => println!("Backend OUT: {}", String::from_utf8_lossy(&line)),
                                    CommandEvent::Stderr(line) => println!("Backend ERR: {}", String::from_utf8_lossy(&line)),
                                    CommandEvent::Error(err) => println!("Backend ERROR Event: {}", err),
                                    CommandEvent::Terminated(payload) => println!("Backend Terminated: {:?}", payload),
                                    _ => {}
                                }
                            }

                            return;
                        }
                        Err(e) => {
                            println!("Python fallback failed to spawn: {}", e);
                        }
                    }
                }

                while let Some(event) = rx.recv().await {
                    match event {
                        CommandEvent::Stdout(line) => println!("Backend OUT: {}", String::from_utf8_lossy(&line)),
                        CommandEvent::Stderr(line) => println!("Backend ERR: {}", String::from_utf8_lossy(&line)),
                        CommandEvent::Error(err) => println!("Backend ERROR Event: {}", err),
                        CommandEvent::Terminated(payload) => println!("Backend Terminated: {:?}", payload),
                        _ => {}
                    }
                }
            });

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                // When the window is closing, we should trigger cleanup.
                let sidecar_child = {
                    let state = window.app_handle().state::<AppState>();
                    state.sidecar_child.clone()
                };

                if let Ok(mut child_lock) = sidecar_child.lock() {
                     kill_backend(child_lock.take());
                };
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
