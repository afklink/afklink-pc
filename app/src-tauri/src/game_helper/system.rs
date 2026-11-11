//! Windows for the game helper: the owner's SID, the install directory, Task Scheduler, the
//! elevation prompt, the file dialog, the launch exe's manifest and compatibility layers, the
//! owner's `user\` directory, the signal, and the process list the game's launcher is learned
//! from.

use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::time::Duration;

use windows::core::{Interface, BSTR, HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, FreeLibrary, LocalFree, ERROR_ALREADY_EXISTS, ERROR_CANCELLED,
    ERROR_NO_MORE_FILES, FILETIME, HANDLE, HLOCAL, HMODULE, HWND, RPC_E_CHANGED_MODE,
    SCHED_E_TASK_NOT_RUNNING, VARIANT_FALSE, VARIANT_TRUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::CreateDirectoryW;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, CLSCTX_INPROC_SERVER,
    COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, COINIT_MULTITHREADED,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::LibraryLoader::{
    FindResourceW, LoadLibraryExW, LoadResource, LockResource, SetDefaultDllDirectories,
    SizeofResource, LOAD_LIBRARY_AS_DATAFILE, LOAD_LIBRARY_AS_IMAGE_RESOURCE,
    LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::TaskScheduler::{
    IExecAction, ILogonTrigger, ITaskDefinition, ITaskFolder, ITaskService, TaskScheduler,
    TASK_ACTION_EXEC, TASK_CREATE_OR_UPDATE, TASK_INSTANCES_IGNORE_NEW,
    TASK_LOGON_INTERACTIVE_TOKEN, TASK_RUNLEVEL_HIGHEST, TASK_RUNLEVEL_LUA, TASK_STATE_RUNNING,
    TASK_TRIGGER_LOGON,
};
use windows::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, GetCurrentProcessId, GetExitCodeProcess, GetProcessTimes,
    OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, ResetEvent, SetEvent,
    WaitForSingleObject, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::System::Variant::VARIANT;
use windows::Win32::UI::Shell::Common::COMDLG_FILTERSPEC;
use windows::Win32::UI::Shell::{
    FOLDERID_ProgramFiles, FileOpenDialog, IFileOpenDialog, IShellItem,
    SHCreateItemFromParsingName, SHGetKnownFolderPath, ShellExecuteExW, FOS_DONTADDTORECENT,
    FOS_FILEMUSTEXIST, FOS_FORCEFILESYSTEM, FOS_NOCHANGEDIR, KF_FLAG_DEFAULT, SEE_MASK_FLAG_NO_UI,
    SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, SIGDN_FILESYSPATH,
};
use windows::Win32::UI::WindowsAndMessaging::{RT_MANIFEST, SW_HIDE};

use afklink_game_helper::{manifest_text, RunLevel, EXE_NAME, SIGNAL_NAME, TASK_PRIORITY};

use super::{quote_arg, Listed, ProcessSeen};

/// `GetExitCodeProcess`'s answer for a process that has not ended.
const STILL_ACTIVE: u32 = 259;

pub(crate) struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns one open handle; a failed close leaves nothing to do.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct Com;
impl Drop for Com {
    fn drop(&mut self) {
        // SAFETY: paired on this thread with a CoInitializeEx that succeeded.
        unsafe { CoUninitialize() };
    }
}

/// COM on this thread for as long as the result lives: `None` when the thread already has it in
/// another apartment (the app's main thread is single-threaded) — usable as it is.
fn com(apartment: windows::Win32::System::Com::COINIT) -> Result<Option<Com>, String> {
    // SAFETY: paired with Com's drop when it succeeds.
    let hr = unsafe { CoInitializeEx(None, apartment) };
    if hr.is_ok() {
        Ok(Some(Com))
    } else if hr == RPC_E_CHANGED_MODE {
        Ok(None)
    } else {
        Err(format!(
            "COM not initialized: {}",
            windows::core::Error::from(hr)
        ))
    }
}

/// The SID of the account this process runs as.
pub(crate) fn current_sid() -> Result<String, String> {
    let mut token = HANDLE::default();
    // SAFETY: this process's own token, query access, a live output.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .map_err(|e| format!("open the process token: {e}"))?;
    let token = Handle(token);
    let mut len = 0;
    // SAFETY: the first call only asks for the size (it fails with ERROR_INSUFFICIENT_BUFFER).
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut len) };
    if len == 0 {
        return Err("Windows did not report the account's SID".into());
    }
    // u64s align the buffer for TOKEN_USER, which holds a pointer.
    let mut buffer = vec![0u64; (len as usize).div_ceil(size_of::<u64>())];
    // SAFETY: an aligned writable buffer of at least `len` bytes.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            len,
            &mut len,
        )
    }
    .map_err(|e| format!("read the account's SID: {e}"))?;
    // SAFETY: Windows wrote a TOKEN_USER at the start of the buffer.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut sid = PWSTR::null();
    // SAFETY: the SID lives in the buffer; Windows allocates the string.
    unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid) }
        .map_err(|e| format!("the SID as text: {e}"))?;
    // SAFETY: a NUL-terminated string Windows just wrote.
    let text = unsafe { sid.to_string() }.map_err(|e| e.to_string());
    // SAFETY: ConvertSidToStringSidW allocates with LocalAlloc.
    unsafe { LocalFree(Some(HLOCAL(sid.0.cast()))) };
    text
}

/// `Program Files\AFKLink\GameHelper\<SID>`: Program Files from the known folder, never from an
/// environment variable a user sets.
pub(crate) fn install_dir(sid: &str) -> Result<PathBuf, String> {
    if !afklink_game_helper::valid_sid(sid) {
        return Err("invalid owner SID".into());
    }
    // SAFETY: a fixed known folder; the string is freed below with the allocator it came from.
    let wide = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, None) }
        .map_err(|e| format!("Program Files not found: {e}"))?;
    // SAFETY: NUL-terminated, from SHGetKnownFolderPath.
    let folder = unsafe { wide.to_string() }.map_err(|e| e.to_string());
    // SAFETY: allocated by SHGetKnownFolderPath with CoTaskMemAlloc.
    unsafe { CoTaskMemFree(Some(wide.0.cast())) };
    Ok(PathBuf::from(folder?)
        .join("AFKLink")
        .join("GameHelper")
        .join(sid))
}

/* ── Task Scheduler ───────────────────────────────────────────────────────────────────────── */

pub(crate) struct Scheduler {
    service: ITaskService,
    root: ITaskFolder,
    // Last: the interfaces above are released before COM is.
    _com: Option<Com>,
}

impl Scheduler {
    pub(crate) fn connect() -> Result<Self, String> {
        let com = com(COINIT_MULTITHREADED)?;
        // SAFETY: the local Task Scheduler; empty variants: this computer, the current account.
        let service: ITaskService =
            unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) }
                .map_err(|e| format!("Task Scheduler: {e}"))?;
        let empty = VARIANT::default();
        // SAFETY: as above.
        unsafe { service.Connect(&empty, &empty, &empty, &empty) }
            .map_err(|e| format!("Task Scheduler connect: {e}"))?;
        // SAFETY: the root folder of the connected service.
        let root = unsafe { service.GetFolder(&BSTR::from("\\")) }
            .map_err(|e| format!("Task Scheduler root folder: {e}"))?;
        Ok(Self {
            service,
            root,
            _com: com,
        })
    }
}

pub(crate) fn task_name(sid: &str) -> BSTR {
    BSTR::from(format!("AFKLink Game Helper {sid}"))
}

fn absent(error: &windows::core::Error) -> bool {
    // HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND).
    matches!(error.code().0 as u32, 0x8007_0002 | 0x8007_0003)
}

/// The task as the owner can see it (the task's security gives them read and run).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TaskPresence {
    Absent,
    Present { running: bool },
}

pub(crate) fn task_presence(scheduler: &Scheduler, sid: &str) -> Result<TaskPresence, String> {
    // SAFETY: a read of this owner's precisely named task.
    match unsafe { scheduler.root.GetTask(&task_name(sid)) } {
        Ok(task) => {
            // SAFETY: as above.
            let state = unsafe { task.State() }.map_err(|e| format!("task state: {e}"))?;
            Ok(TaskPresence::Present {
                running: state == TASK_STATE_RUNNING,
            })
        }
        Err(e) if absent(&e) => Ok(TaskPresence::Absent),
        Err(e) => Err(format!("task not read: {e}")),
    }
}

/// Start the task: from the elevated setup, or from the app (the owner may run it). One instance
/// at most: a second start of a running task is ignored (`IgnoreNew`).
pub(crate) fn run_task(scheduler: &Scheduler, sid: &str) -> Result<(), String> {
    // SAFETY: this owner's task, no parameters.
    unsafe {
        scheduler
            .root
            .GetTask(&task_name(sid))
            .and_then(|task| task.Run(&VARIANT::default()))
    }
    .map(|_| ())
    .map_err(|e| e.to_string())
}

/// Stop and delete this owner's task: `true` when there was one.
pub(crate) fn remove_task(scheduler: &Scheduler, sid: &str) -> Result<bool, String> {
    // SAFETY: only this owner's precisely named helper task is touched.
    let task = match unsafe { scheduler.root.GetTask(&task_name(sid)) } {
        Ok(task) => task,
        Err(e) if absent(&e) => return Ok(false),
        Err(e) => return Err(format!("task not read: {e}")),
    };
    // SAFETY: as above.
    unsafe {
        task.SetEnabled(VARIANT_FALSE)
            .map_err(|e| format!("task not disabled: {e}"))?;
        match task.Stop(0) {
            Ok(()) => {}
            Err(e) if e.code() == SCHED_E_TASK_NOT_RUNNING => {}
            Err(e) => return Err(format!("task not stopped: {e}")),
        }
        scheduler
            .root
            .DeleteTask(&task_name(sid), 0)
            .map_err(|e| format!("task not deleted: {e}"))?;
    }
    Ok(true)
}

/// The task: the helper's exe with no arguments, at the owner's logon and on demand, in their
/// interactive session only (no stored password), at `level`, at priority
/// [`afklink_game_helper::TASK_PRIORITY`] — a normal-priority process; Task Scheduler's default, 7,
/// is below normal (there the helper's ticks took 16–25 s on a loaded PC). `description`: what
/// Task Scheduler shows for it (`task.gameHelper.native`, in the window's language — the setup's
/// argument). The name stays [`task_name`], with the SID, in every language.
pub(crate) fn task_definition(
    scheduler: &Scheduler,
    sid: &str,
    dir: &Path,
    level: RunLevel,
    description: &str,
) -> Result<ITaskDefinition, String> {
    let fail = |what: &str| {
        let what = what.to_string();
        move |e: windows::core::Error| format!("task {what}: {e}")
    };
    // SAFETY: a new, unregistered definition, filled in below.
    unsafe {
        let definition = scheduler.service.NewTask(0).map_err(fail("definition"))?;
        definition
            .RegistrationInfo()
            .and_then(|r| r.SetDescription(&BSTR::from(description)))
            .map_err(fail("description"))?;
        let principal = definition.Principal().map_err(fail("principal"))?;
        principal
            .SetUserId(&BSTR::from(sid))
            .map_err(fail("user"))?;
        principal
            .SetLogonType(TASK_LOGON_INTERACTIVE_TOKEN)
            .map_err(fail("logon type"))?;
        principal
            .SetRunLevel(match level {
                RunLevel::Highest => TASK_RUNLEVEL_HIGHEST,
                RunLevel::Lua => TASK_RUNLEVEL_LUA,
            })
            .map_err(fail("run level"))?;
        let settings = definition.Settings().map_err(fail("settings"))?;
        settings
            .SetExecutionTimeLimit(&BSTR::from("PT0S"))
            .map_err(fail("time limit"))?;
        settings
            .SetMultipleInstances(TASK_INSTANCES_IGNORE_NEW)
            .map_err(fail("instances"))?;
        settings
            .SetDisallowStartIfOnBatteries(VARIANT_FALSE)
            .map_err(fail("battery"))?;
        settings
            .SetStopIfGoingOnBatteries(VARIANT_FALSE)
            .map_err(fail("battery"))?;
        settings
            .SetStartWhenAvailable(VARIANT_TRUE)
            .map_err(fail("start when available"))?;
        settings
            .SetPriority(i32::from(TASK_PRIORITY))
            .map_err(fail("priority"))?;
        // A helper that could not start (its exit code says why) is tried again a few times.
        settings
            .SetRestartInterval(&BSTR::from("PT1M"))
            .map_err(fail("restart interval"))?;
        settings.SetRestartCount(3).map_err(fail("restart count"))?;
        let trigger: ILogonTrigger = definition
            .Triggers()
            .and_then(|t| t.Create(TASK_TRIGGER_LOGON))
            .and_then(|t| t.cast())
            .map_err(fail("logon trigger"))?;
        trigger
            .SetUserId(&BSTR::from(sid))
            .map_err(fail("trigger user"))?;
        let action: IExecAction = definition
            .Actions()
            .and_then(|a| a.Create(TASK_ACTION_EXEC))
            .and_then(|a| a.cast())
            .map_err(fail("action"))?;
        action
            .SetPath(&BSTR::from(dir.join(EXE_NAME).to_string_lossy().as_ref()))
            .map_err(fail("path"))?;
        action
            .SetWorkingDirectory(&BSTR::from(dir.to_string_lossy().as_ref()))
            .map_err(fail("working directory"))?;
        Ok(definition)
    }
}

pub(crate) fn register_task(
    scheduler: &Scheduler,
    sid: &str,
    dir: &Path,
    level: RunLevel,
    description: &str,
) -> Result<(), String> {
    let definition = task_definition(scheduler, sid, dir, level, description)?;
    // The owner reads and runs it; only SYSTEM and administrators change it.
    let security = format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;{sid})");
    // SAFETY: the owner's SID, their interactive token, no stored credentials.
    unsafe {
        scheduler.root.RegisterTaskDefinition(
            &task_name(sid),
            &definition,
            TASK_CREATE_OR_UPDATE.0,
            &VARIANT::from(sid),
            &VARIANT::default(),
            TASK_LOGON_INTERACTIVE_TOKEN,
            &VARIANT::from(security.as_str()),
        )
    }
    .map(|_| ())
    .map_err(|e| e.to_string())
}

/* ── The launch exe ───────────────────────────────────────────────────────────────────────── */

struct Module(HMODULE);
impl Drop for Module {
    fn drop(&mut self) {
        // SAFETY: loaded below as a data file; a failed free leaves nothing to do.
        let _ = unsafe { FreeLibrary(self.0) };
    }
}

/// The exe's manifest (`RT_MANIFEST` #1, the one Windows reads when it starts the process), read
/// as data — nothing in the file runs. `Ok(None)`: it has none.
pub(crate) fn read_manifest(exe: &Path) -> Result<Option<String>, String> {
    // SAFETY: loaded as an image resource and data file only: no code, no imports, no DllMain.
    let module = Module(
        unsafe {
            LoadLibraryExW(
                &HSTRING::from(exe.as_os_str()),
                None,
                LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE,
            )
        }
        .map_err(|e| e.to_string())?,
    );
    // SAFETY: MAKEINTRESOURCE(1) in the module just loaded.
    let found = unsafe { FindResourceW(Some(module.0), PCWSTR(1 as _), RT_MANIFEST) };
    if found.is_invalid() {
        return Ok(None);
    }
    // SAFETY: the resource found above, in the same module, which stays loaded until the end.
    let bytes = unsafe {
        let size = SizeofResource(Some(module.0), found) as usize;
        let data = LoadResource(Some(module.0), found).map_err(|e| e.to_string())?;
        let ptr = LockResource(data) as *const u8;
        if ptr.is_null() || size == 0 {
            return Ok(None);
        }
        std::slice::from_raw_parts(ptr, size).to_vec()
    };
    Ok(Some(manifest_text(&bytes)))
}

/// The compatibility layers set for the exe («Запускать от имени администратора» in its
/// properties): the owner's (their hive, by SID — the setup may run as another administrator) and
/// the machine's. With what could not be read, for the log.
pub(crate) fn compat_layers(sid: &str, exe: &str) -> (Vec<(String, String)>, Vec<String>) {
    use winreg::enums::{HKEY_LOCAL_MACHINE, HKEY_USERS};
    use winreg::RegKey;

    const LAYERS: &str = r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers";
    let mut found = Vec::new();
    let mut notes = Vec::new();
    for (place, root, key) in [
        (
            "the owner's settings",
            HKEY_USERS,
            format!(r"{sid}\{LAYERS}"),
        ),
        (
            "the machine's settings",
            HKEY_LOCAL_MACHINE,
            LAYERS.to_string(),
        ),
    ] {
        match RegKey::predef(root)
            .open_subkey(&key)
            .and_then(|k| k.get_value::<String, _>(exe))
        {
            Ok(value) => {
                notes.push(format!("{place}: {value:?}"));
                found.push((place.to_string(), value));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                notes.push(format!("{place}: none"));
            }
            Err(e) => notes.push(format!("{place}: not read ({e})")),
        }
    }
    (found, notes)
}

/// `user\`: where a helper without rights writes its log and state — SYSTEM and administrators
/// full, the owner modify, nobody else; not inherited from Program Files.
pub(crate) fn create_user_dir(path: &Path, sid: &str) -> Result<(), String> {
    let sddl = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;{sid})");
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: a fixed SDDL with the checked SID; Windows allocates the descriptor.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &HSTRING::from(sddl),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(|e| format!("security descriptor: {e}"))?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: false.into(),
    };
    // SAFETY: the descriptor lives until it is freed below.
    let made = unsafe { CreateDirectoryW(&HSTRING::from(path.as_os_str()), Some(&attributes)) };
    // SAFETY: allocated with LocalAlloc by the conversion above.
    unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
    made.map_err(|e| e.to_string())
}

/* ── The elevation prompt ─────────────────────────────────────────────────────────────────── */

/// For the elevated setup, before anything else it does: DLLs this process loads by name from now
/// on come from System32 only (and Windows' own known DLLs and API sets), never from the folder the
/// portable exe lies in — a folder its owner, and so any of their programs, can write to.
/// <https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-setdefaultdlldirectories>
/// The exe's static imports are resolved before any of its code runs; `build.rs` limits them the
/// same way with the linker's `/DEPENDENTLOADFLAG`.
pub(crate) fn limit_dll_search() -> Result<(), String> {
    // SAFETY: a process-wide setting with a documented flag; no pointers.
    unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) }
        .map_err(|e| format!("SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32): {e}"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Elevated {
    /// The owner declined (or closed the prompt): `ERROR_CANCELLED`, 1223.
    Cancelled,
    Exited(u32),
    /// Still running after the wait: given up on, left to finish.
    TimedOut,
}

/// Run this exe again elevated with `args`, through Windows' standard elevation prompt, and wait
/// for it. `owner`: the window the prompt belongs to.
///
/// The exe is the portable one, wherever the owner keeps it. Elevated, its static imports are
/// looked for in System32 only (`/DEPENDENTLOADFLAG`, `build.rs`) and, from its first line, its
/// loads by name too ([`limit_dll_search`]): a DLL put beside it is not loaded. The exe itself is
/// what the owner confirms in Windows' prompt — a replaced exe is a replaced program (README,
/// «Остаточный риск»).
pub(crate) fn elevate(
    args: &[String],
    owner: Option<usize>,
    wait: Duration,
) -> Result<Elevated, String> {
    let exe = std::env::current_exe().map_err(|e| format!("this exe's path: {e}"))?;
    let params = args
        .iter()
        .map(|a| quote_arg(a))
        .collect::<Vec<_>>()
        .join(" ");
    let verb = HSTRING::from("runas");
    let file = HSTRING::from(exe.as_os_str());
    let params = HSTRING::from(params);
    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
        hwnd: HWND(owner.unwrap_or(0) as *mut _),
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(params.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    // SAFETY: every string outlives the call; Windows shows its own elevation prompt.
    match unsafe { ShellExecuteExW(&mut info) } {
        Ok(()) => {}
        Err(e) if e.code() == ERROR_CANCELLED.to_hresult() => return Ok(Elevated::Cancelled),
        Err(e) => return Err(format!("the elevated setup did not start: {e}")),
    }
    if info.hProcess.is_invalid() {
        return Err("Windows started the setup but returned no process".into());
    }
    let process = Handle(info.hProcess);
    let millis = u32::try_from(wait.as_millis()).unwrap_or(u32::MAX);
    // SAFETY: our own handle to the setup's process; a blocking worker thread, not the UI's.
    match unsafe { WaitForSingleObject(process.0, millis) } {
        WAIT_OBJECT_0 => {}
        WAIT_TIMEOUT => return Ok(Elevated::TimedOut),
        other => return Err(format!("waiting for the setup failed ({:#x})", other.0)),
    }
    let mut code = 0;
    // SAFETY: a live output and the process handle.
    unsafe { GetExitCodeProcess(process.0, &mut code) }
        .map_err(|e| format!("the setup's exit code: {e}"))?;
    Ok(Elevated::Exited(code))
}

/* ── The file dialog ──────────────────────────────────────────────────────────────────────── */

/// Windows' own Open dialog for an `.exe`, starting in `start`, over `owner`. `Ok(None)`: closed
/// without a choice. Runs on a thread of its own, in the apartment the dialog needs.
pub(crate) fn pick_exe(
    owner: Option<usize>,
    start: Option<PathBuf>,
    title: String,
    filter: String,
) -> Result<Option<String>, String> {
    std::thread::Builder::new()
        .name("afklink-file-dialog".into())
        .spawn(move || pick_on_this_thread(owner, start.as_deref(), &title, &filter))
        .map_err(|e| format!("the dialog's thread did not start: {e}"))?
        .join()
        .map_err(|_| "the dialog's thread panicked".to_string())?
}

fn pick_on_this_thread(
    owner: Option<usize>,
    start: Option<&Path>,
    title: &str,
    filter: &str,
) -> Result<Option<String>, String> {
    let _com = com(COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE)?;
    let name = HSTRING::from(filter);
    let spec = HSTRING::from("*.exe");
    let title = HSTRING::from(title);
    // SAFETY: Windows' file dialog on this single-threaded apartment; the strings outlive it.
    unsafe {
        let dialog: IFileOpenDialog = CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| format!("the file dialog: {e}"))?;
        dialog
            .SetFileTypes(&[COMDLG_FILTERSPEC {
                pszName: PCWSTR(name.as_ptr()),
                pszSpec: PCWSTR(spec.as_ptr()),
            }])
            .map_err(|e| format!("file types: {e}"))?;
        let options = dialog.GetOptions().map_err(|e| format!("options: {e}"))?;
        dialog
            .SetOptions(
                options
                    | FOS_FILEMUSTEXIST
                    | FOS_FORCEFILESYSTEM
                    | FOS_NOCHANGEDIR
                    | FOS_DONTADDTORECENT,
            )
            .map_err(|e| format!("options: {e}"))?;
        dialog.SetTitle(&title).map_err(|e| format!("title: {e}"))?;
        if let Some(start) = start {
            // A folder that is gone leaves the dialog where Windows puts it.
            if let Ok(folder) = SHCreateItemFromParsingName::<_, _, IShellItem>(
                &HSTRING::from(start.as_os_str()),
                None,
            ) {
                dialog
                    .SetFolder(&folder)
                    .map_err(|e| format!("start folder: {e}"))?;
            }
        }
        match dialog.Show(owner.map(|h| HWND(h as *mut _))) {
            Ok(()) => {}
            Err(e) if e.code() == ERROR_CANCELLED.to_hresult() => return Ok(None),
            Err(e) => return Err(format!("the file dialog: {e}")),
        }
        let item = dialog.GetResult().map_err(|e| format!("the choice: {e}"))?;
        let name = item
            .GetDisplayName(SIGDN_FILESYSPATH)
            .map_err(|e| format!("the chosen path: {e}"))?;
        let path = name.to_string().map_err(|e| e.to_string());
        CoTaskMemFree(Some(name.0.cast()));
        path.map(Some)
    }
}

/* ── The game's launcher, learned from its parent ─────────────────────────────────────────── */

/// Every process in Windows' list: its id, its parent's id, its exe's file name. Reads names only:
/// no process is opened.
pub(crate) fn processes() -> Result<Vec<Listed>, String> {
    // SAFETY: a process snapshot; no process memory is read.
    let snapshot = Handle(
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
            .map_err(|e| format!("process snapshot: {e}"))?,
    );
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut listed = Vec::new();
    // SAFETY: a correctly sized entry and a live snapshot.
    let mut next = unsafe { Process32FirstW(snapshot.0, &mut entry) };
    loop {
        match next {
            Ok(()) => {}
            Err(e) if e.code() == ERROR_NO_MORE_FILES.to_hresult() => break,
            Err(e) => return Err(format!("process list: {e}")),
        }
        let len = entry
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(entry.szExeFile.len());
        listed.push(Listed {
            pid: entry.th32ProcessID,
            parent: entry.th32ParentProcessID,
            name: String::from_utf16_lossy(&entry.szExeFile[..len]),
        });
        // SAFETY: as above.
        next = unsafe { Process32NextW(snapshot.0, &mut entry) };
    }
    Ok(listed)
}

/// A process as the limited query right reads it — its full path, start, session, and whether it
/// still runs. Windows grants that right for processes running with rights too (measured).
pub(crate) fn process(pid: u32) -> Result<ProcessSeen, String> {
    let mut session = 0;
    // SAFETY: a query with a live output.
    unsafe { ProcessIdToSessionId(pid, &mut session) }
        .map_err(|e| format!("pid {pid}: its session not read: {e}"))?;
    // SAFETY: only the limited query right.
    let process = Handle(
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
            .map_err(|e| format!("pid {pid} not opened: {e}"))?,
    );
    let mut buffer = vec![0u16; 32768];
    let mut len = buffer.len() as u32;
    // SAFETY: the buffer is writable for `len` characters; the process stays open.
    unsafe {
        QueryFullProcessImageNameW(
            process.0,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut len,
        )
    }
    .map_err(|e| format!("pid {pid}: its path not read: {e}"))?;
    let path = String::from_utf16_lossy(&buffer[..len as usize]);
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: four live outputs; the process stays open.
    unsafe { GetProcessTimes(process.0, &mut created, &mut exited, &mut kernel, &mut user) }
        .map_err(|e| format!("pid {pid}: its start not read: {e}"))?;
    let mut code = 0;
    // SAFETY: a live output; the process stays open.
    unsafe { GetExitCodeProcess(process.0, &mut code) }
        .map_err(|e| format!("pid {pid}: whether it runs not read: {e}"))?;
    Ok(ProcessSeen {
        path,
        started: (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime),
        session,
        alive: code == STILL_ACTIVE,
    })
}

/// This app's Windows session.
pub(crate) fn this_session() -> Result<u32, String> {
    let mut session = 0;
    // SAFETY: this process's own id, a live output.
    unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) }
        .map_err(|e| e.to_string())?;
    Ok(session)
}

/* ── The signal ───────────────────────────────────────────────────────────────────────────── */

/// The helper's permission: a manual-reset event in this session's `Local\` namespace, made at
/// start — by the one instance only, in `setup`, past the single-instance lock — not set. It lives
/// as long as this handle — the app gone, the helper finds nothing and does nothing.
pub(crate) struct Signal(HANDLE);

// SAFETY: a kernel handle, usable from any thread; set and reset are atomic in the kernel.
unsafe impl Send for Signal {}
// SAFETY: as above.
unsafe impl Sync for Signal {}

impl Signal {
    /// The event, and whether its name already existed — another process made it first. Reset
    /// either way: a name that exists when the one instance starts was made by someone else (the
    /// helper only opens it for a moment each tick), and the reset undoes a set made before this
    /// start. It does not stop a process that still holds the name from setting it again later.
    pub(crate) fn create() -> Result<(Self, bool), String> {
        Self::create_named(SIGNAL_NAME)
    }

    /// [`Signal::create`] under another name: the tests' own, so they never touch the real one.
    fn create_named(name: &str) -> Result<(Self, bool), String> {
        // SAFETY: a named event with the default security (this account and SYSTEM).
        let handle = unsafe { CreateEventW(None, true, false, &HSTRING::from(name)) }
            .map_err(|e| e.to_string())?;
        let existed =
            std::io::Error::last_os_error().raw_os_error() == Some(ERROR_ALREADY_EXISTS.0 as i32);
        let signal = Self(handle);
        signal.set(false)?;
        Ok((signal, existed))
    }

    pub(crate) fn set(&self, on: bool) -> Result<(), String> {
        // SAFETY: our own event handle.
        unsafe {
            if on {
                SetEvent(self.0)
            } else {
                ResetEvent(self.0)
            }
        }
        .map_err(|e| e.to_string())
    }
}

impl Drop for Signal {
    fn drop(&mut self) {
        // SAFETY: the handle made in `create`.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use afklink_i18n::{Locale, NativeText};

    use super::*;

    /// A transient definition, read back as XML: nothing is registered or run.
    fn xml(level: RunLevel, locale: Locale) -> String {
        let scheduler = Scheduler::connect().unwrap();
        let sid = "S-1-5-21-123-456-789-1001";
        let dir = Path::new(r"C:\Program Files\AFKLink\GameHelper\S-1-5-21-123-456-789-1001");
        let description = NativeText::TaskGameHelper.t(locale);
        let definition = task_definition(&scheduler, sid, dir, level, description).unwrap();
        let mut xml = BSTR::new();
        // SAFETY: reading the unregistered definition.
        unsafe { definition.XmlText(&mut xml) }.unwrap();
        xml.to_string()
    }

    /// What Task Scheduler shows for the task: the dictionary's sentence in the window's language
    /// (the setup's argument), not a fixed English one.
    #[test]
    fn the_task_is_described_in_the_windows_language() {
        let ru = xml(RunLevel::Lua, Locale::Ru);
        assert!(
            ru.contains(
                "<Description>AFKLink: во время сеанса запускает выбранную игру и возвращает её на \
                 экран</Description>"
            ),
            "{ru}"
        );
        let en = xml(RunLevel::Lua, Locale::En);
        assert!(
            en.contains(&format!(
                "<Description>{}</Description>",
                NativeText::TaskGameHelper.t(Locale::En)
            )),
            "{en}"
        );
        assert!(!en.contains("the owner approved"), "{en}");
    }

    #[test]
    fn the_task_runs_only_the_helper_in_the_owners_session_at_the_needed_level() {
        let highest = xml(RunLevel::Highest, Locale::En);
        let lua = xml(RunLevel::Lua, Locale::En);
        assert!(
            highest.contains("<RunLevel>HighestAvailable</RunLevel>"),
            "{highest}"
        );
        assert!(lua.contains("<RunLevel>LeastPrivilege</RunLevel>"), "{lua}");
        for xml in [&highest, &lua] {
            assert_eq!(xml.matches("<Exec>").count(), 1, "{xml}");
            assert!(!xml.contains("<Arguments>"), "no arguments: {xml}");
            assert_eq!(xml.matches("<LogonTrigger>").count(), 1, "{xml}");
            assert_eq!(
                xml.matches("<UserId>S-1-5-21-123-456-789-1001</UserId>")
                    .count(),
                2,
                "{xml}"
            );
            for part in [
                "<LogonType>InteractiveToken</LogonType>",
                "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>",
                "<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>",
                "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>",
                "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>",
                // Normal, not Task Scheduler's default 7 (below normal).
                "<Priority>5</Priority>",
                r"<Command>C:\Program Files\AFKLink\GameHelper\S-1-5-21-123-456-789-1001\afklink-game-helper.exe</Command>",
            ] {
                assert!(xml.contains(part), "{part} missing: {xml}");
            }
        }
    }

    /// Read as data, never run: an inbox program's manifest asks for no administrator.
    #[test]
    fn a_manifest_is_read_without_running_the_program() {
        let windows = std::env::var_os("SystemRoot").unwrap();
        let cmd = Path::new(&windows).join("System32").join("cmd.exe");
        let manifest = read_manifest(&cmd)
            .unwrap()
            .expect("cmd.exe has a manifest");
        assert_eq!(
            afklink_game_helper::manifest_execution_level(&manifest),
            Ok(Some(afklink_game_helper::ExecutionLevel::AsInvoker)),
            "{manifest}"
        );
        assert!(read_manifest(&Path::new(&windows).join("no-such-program.exe")).is_err());
        let (_, notes) = compat_layers("S-1-5-21-123-456-789-1001", &cmd.to_string_lossy());
        assert_eq!(notes.len(), 2, "{notes:?}");
    }

    #[test]
    fn the_install_directory_is_under_program_files_by_sid_only() {
        let dir = install_dir("S-1-5-21-1-2-3-1001").unwrap();
        assert!(
            dir.ends_with(r"AFKLink\GameHelper\S-1-5-21-1-2-3-1001"),
            "{dir:?}"
        );
        assert!(install_dir(r"S-1-5\..\..").is_err());
        assert!(current_sid().is_ok_and(|s| afklink_game_helper::valid_sid(&s)));
    }

    /// What the launcher is learned from, read for this test's own process: listed with its parent,
    /// its path, start and session read with the limited right, alive. Nothing is opened for more.
    #[test]
    fn the_process_list_and_a_process_read_with_the_limited_right() {
        let me = std::process::id();
        let listed = processes().unwrap();
        let entry = listed
            .iter()
            .find(|p| p.pid == me)
            .expect("this process listed");
        let exe = std::env::current_exe().unwrap();
        assert!(
            entry
                .name
                .eq_ignore_ascii_case(&exe.file_name().unwrap().to_string_lossy()),
            "{entry:?}"
        );
        assert_ne!(entry.parent, 0, "{entry:?}");
        let seen = process(me).unwrap();
        assert!(
            afklink_game_helper::same_path(&seen.path, &exe.to_string_lossy()),
            "{seen:?}"
        );
        assert!(seen.alive && seen.started > 0, "{seen:?}");
        assert_eq!(seen.session, this_session().unwrap());
        assert!(process(u32::MAX - 3).is_err(), "no such process");
    }

    /// A name of this test's own in this session's `Local\` namespace: never the real signal's.
    fn test_signal_name() -> String {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT: AtomicU32 = AtomicU32::new(0);
        format!(
            r"Local\AFKLink.Test.Signal.{}.{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )
    }

    /// The event under `name` as the helper reads it (`afklink_game_helper`'s `read_signal`): opened
    /// for waiting only, tested with a zero timeout, closed again. `None`: no such event (only
    /// `ERROR_FILE_NOT_FOUND`, as the helper reads it); any other failure fails the test.
    fn read_as_the_helper(name: &str) -> Option<bool> {
        use windows::Win32::Foundation::ERROR_FILE_NOT_FOUND;
        use windows::Win32::System::Threading::{OpenEventW, SYNCHRONIZATION_SYNCHRONIZE};
        // SAFETY: a named object in this session's namespace, opened for waiting only.
        let opened =
            unsafe { OpenEventW(SYNCHRONIZATION_SYNCHRONIZE, false, &HSTRING::from(name)) };
        if matches!(&opened, Err(e) if e.code() == ERROR_FILE_NOT_FOUND.to_hresult()) {
            return None;
        }
        // Any other failure fails the test, with the error.
        let handle = Handle(opened.unwrap());
        // SAFETY: a zero timeout on the handle just opened: a test, not a wait.
        let answer = unsafe { WaitForSingleObject(handle.0, 0) };
        assert!(
            answer == WAIT_OBJECT_0 || answer == WAIT_TIMEOUT,
            "wait answered {:#x}",
            answer.0
        );
        Some(answer == WAIT_OBJECT_0)
    }

    /// A set signal stays set while the helper reads it: its reads do not consume it (a
    /// manual-reset event); only its maker turns it off. That a second launch makes no signal over
    /// the running instance's is guarded elsewhere: `GameHelper::start` takes `&tauri::App` and
    /// `game_helper::tests::the_signal_is_made_only_past_the_single_instance_lock`.
    #[test]
    fn a_set_signal_stays_set_while_the_helper_reads_it() {
        let name = test_signal_name();
        let (running, existed) = Signal::create_named(&name).unwrap();
        assert!(!existed, "a fresh name");
        assert_eq!(read_as_the_helper(&name), Some(false), "made not set");
        running.set(true).unwrap();
        for _ in 0..3 {
            assert_eq!(read_as_the_helper(&name), Some(true), "still set");
        }
        running.set(false).unwrap();
        assert_eq!(
            read_as_the_helper(&name),
            Some(false),
            "the running one turns it off"
        );
    }

    /// What a second launch would do if it made the signal — and what the one instance does when
    /// the name already exists as it starts: the event is reset, and the name's existing is
    /// reported (the warning in `GameHelper::start`). The reset undoes a set made before the one
    /// instance starts; it does not stop a holder of the name from setting it again later.
    #[test]
    fn a_signal_made_where_the_name_exists_and_is_set_is_reset_and_says_so() {
        let name = test_signal_name();
        let (first, existed) = Signal::create_named(&name).unwrap();
        assert!(!existed, "a fresh name");
        first.set(true).unwrap();
        assert_eq!(read_as_the_helper(&name), Some(true));
        let (second, existed) = Signal::create_named(&name).unwrap();
        assert!(existed, "the name existed");
        assert_eq!(read_as_the_helper(&name), Some(false), "reset on making");
        drop(second);
        assert_eq!(
            read_as_the_helper(&name),
            Some(false),
            "the first handle keeps the event, reset"
        );
    }

    /// The app gone, the signal is gone with its last handle: the helper finds nothing.
    #[test]
    fn the_signal_ends_with_its_handle() {
        let name = test_signal_name();
        let (signal, _) = Signal::create_named(&name).unwrap();
        signal.set(true).unwrap();
        drop(signal);
        assert_eq!(read_as_the_helper(&name), None);
    }
}
