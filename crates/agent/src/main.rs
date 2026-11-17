//! Headless AFKLink agent — runs the full capture -> encode -> WebRTC pipeline
//! and prints the pairing code, so the agent is testable without the GUI.
//!
//! Usage:
//!   afklink-agent               run the agent (connect, pair, serve sessions)
//!   afklink-agent --selftest    capture+encode a few frames locally and exit
//!   afklink-agent --help        show this help
//!
//! It is also the bench device: `--bench`, `--data-dir`, `--capture-corpus`, `--no-input`,
//! `--auto-approve-pairing`, `--link-profile` and `--link-control` replace the screen, the input
//! and the identity, shape the link, and print machine-readable `BENCH` lines (`cli::help_text`).

mod bench;
mod cli;
mod terminal;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::sync::broadcast;

use afklink_capture::WgcCapturer;
use afklink_core::build_info::BuildInfo;
use afklink_core::logging::StartupFilter;
use afklink_core::traits::{Capturer, Encoder as _, InputInjector};
use afklink_core::{Agent, AgentControl, AgentEvent, Backends, Config, Identity, OnReplaced};
use afklink_encode::OpenH264Encoder;
use afklink_input::create_input_injector;
use afklink_transport::{LinkProfile, LinkShaper};

use bench::corpus_capture::CorpusCapturer;
use bench::noop_input::NoopInjector;
use bench::stdout;
use cli::Options;
use terminal::TerminalCommand;

/// This build's identity: the workspace version and the stamp its build passed in (empty for a
/// plain `cargo build`, which then says «dev»), through `build.rs` (`afklink_core::build_info`).
fn build_info() -> BuildInfo {
    BuildInfo::from_stamp(
        env!("CARGO_PKG_VERSION"),
        env!("AFKLINK_BUILD_COMMIT"),
        env!("AFKLINK_BUILD_DIRTY"),
        env!("AFKLINK_BUILD_TIME"),
        env!("AFKLINK_BUILD_CHANNEL"),
    )
}

/// The CLI's log filter: `RUST_LOG` if set, else config.json's chosen `log_level`, else the build
/// channel's default (`debug` for a development build; for a release `debug` during the beta test
/// and `info` after it, `afklink_core::logging::RELEASE_PHASE`) — the same resolution as the
/// desktop app, from `afklink_core::logging`.
fn startup_filter(config: Option<&Config>, build: &BuildInfo) -> StartupFilter {
    StartupFilter::resolve(config, build.channel)
}

/// Stdout at the level [`startup_filter`] resolves. No runtime switching here: the CLI has no
/// Settings, and restarting it is the switch.
///
/// The first line is the build's: version, channel, commit, tree state, build time and the exe —
/// as in the desktop app.
fn init_tracing(config: Option<&Config>) {
    let build = build_info();
    let startup = startup_filter(config, &build);
    tracing_subscriber::fmt()
        .with_env_filter(startup.filter())
        .with_target(false)
        .init();
    build.log_startup("afklink-agent");
    startup.log_summary();
}

/// A capturer factory: the corpus when `--capture-corpus` was given, the screen otherwise.
fn capturer_factory(opts: &Options) -> Box<dyn Fn() -> Result<Box<dyn Capturer>> + Send + Sync> {
    match &opts.capture_corpus {
        Some(path) => {
            let path = path.clone();
            Box::new(move || Ok(Box::new(CorpusCapturer::new(path.clone())) as Box<dyn Capturer>))
        }
        None => Box::new(|| Ok(Box::new(WgcCapturer::new()) as Box<dyn Capturer>)),
    }
}

fn build_backends(opts: &Options) -> Backends {
    let injector: Arc<dyn InputInjector> = if opts.no_input {
        tracing::debug!(reason = "--no-input", "input injection disabled");
        Arc::new(NoopInjector::new())
    } else {
        create_input_injector()
    };
    tracing::debug!(
        capture = if opts.capture_corpus.is_some() {
            "corpus"
        } else {
            "wgc"
        },
        input = if opts.no_input { "none" } else { "auto" },
        "backends"
    );
    Backends {
        make_capturer: capturer_factory(opts),
        // «Only the game window» when config.json turns it on — the game's window from the screen
        // even under `--capture-corpus`, which stands in for the monitor only.
        make_game_capturer: Box::new(|request| Ok(afklink_capture::game_capturer(request))),
        make_encoder: Box::new(|| {
            Ok(Box::new(OpenH264Encoder::with_defaults()?)
                as Box<dyn afklink_core::traits::Encoder>)
        }),
        injector,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = match Options::parse(std::env::args().skip(1)).and_then(Options::resolve) {
        Ok(opts) => opts,
        Err(e) => {
            // Before any log exists: the refusal and the usage go to stderr, and nothing ran.
            eprintln!("afklink-agent: {e}\n\n{}", cli::help_text());
            std::process::exit(2);
        }
    };
    if opts.help {
        println!("{}", cli::help_text());
        return Ok(());
    }

    // The data directory before anything reads config or identity: both come from there.
    let prepared = match &opts.data_dir {
        Some(dir) => match bench::data_dir::prepare(dir, opts.bench) {
            Ok(prepared) => Some(prepared),
            Err(e) => {
                eprintln!("afklink-agent: {e:#}");
                std::process::exit(2);
            }
        },
        None => None,
    };

    // A pre-rename install (`%APPDATA%\Remoter`) moves to `%APPDATA%\AFKLink` before config or
    // identity are read from there — skipped under `--data-dir`. Logged once the log exists.
    let migration = afklink_core::paths::migrate_legacy_dir();
    // Config before tracing: its chosen `log_level` (else the build channel's default) decides the
    // filter. One that fails to load still gets a subscriber, at the channel's default level; the
    // agent then stops on the error, the selftest (which needs no config) carries on.
    let config = Config::load_or_create();
    init_tracing(config.as_ref().ok());
    install_panic_hook();
    migration.log();
    log_startup(&opts, prepared.as_ref());
    // The timer resolution a live peer raises (`AFKLINK_TIMER_RESOLUTION` overrides it): the
    // policy and the system's current resolution, in the log before any session.
    afklink_transport::timer::init_process();

    // Readable now rather than at the first session: a capture that cannot start would otherwise
    // surface as a session that ends at once, which looks like anything but a missing file.
    if let Some(path) = &opts.capture_corpus {
        match CorpusCapturer::probe(path) {
            Ok(what) => tracing::info!(
                path = %path.display(),
                "capture: corpus playback instead of the screen: {what}"
            ),
            Err(e) => {
                tracing::error!("--capture-corpus: {e:#}");
                return Err(e);
            }
        }
    }

    if opts.selftest {
        let capturer = capturer_factory(&opts)()?;
        return tokio::task::spawn_blocking(move || selftest(capturer)).await?;
    }

    // Into the log as well as out of `main`: the error `main` returns goes to stderr, which a
    // redirected run does not keep beside the log.
    let config = match config {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("config.json could not be loaded: {e:#}");
            return Err(e);
        }
    };
    run_agent(config, opts).await
}

/// A panic into the log, with where it happened, and — on the main thread, whose panic ends the
/// process — into the run state as this process's exit (`afklink_core::run_state::record_panic`),
/// so the next start says `panic`. Then the default hook, which prints it to stderr as before.
fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let location = info.location().map_or_else(
            || "unknown location".to_string(),
            |l| format!("{}:{}:{}", l.file(), l.line(), l.column()),
        );
        let message = info.payload_as_str().unwrap_or("non-string panic payload");
        let current = std::thread::current();
        tracing::error!(
            %location,
            thread = current.name().unwrap_or("unnamed"),
            "panic: {message}"
        );
        // The place goes to the record hashed; the message never leaves the log.
        afklink_core::run_state::record_panic(current.name(), info.location());
        previous(info);
    }));
}

/// What this run was told, in the log once it exists.
fn log_startup(opts: &Options, prepared: Option<&bench::data_dir::Prepared>) {
    if let Some(p) = prepared {
        for note in &p.notes {
            tracing::info!(
                dir = %p.dir.display(),
                created = p.created,
                "--data-dir: {note}"
            );
        }
    }
    if opts.bench_mode() {
        tracing::info!(
            bench = opts.bench,
            data_dir = ?opts.data_dir,
            capture_corpus = ?opts.capture_corpus,
            no_input = opts.no_input,
            auto_approve_pairing = opts.auto_approve_pairing,
            link_profile = ?opts.link_profile,
            link_control = ?opts.link_control,
            "bench flags in effect"
        );
    } else {
        tracing::debug!("no bench flags: the ordinary agent");
    }
}

/// The link shaper, when a link flag was given: `--link-profile` read once, then `--link-control`
/// applied at once if it exists and watched from then on.
fn build_link_shaper(opts: &Options) -> Option<Arc<LinkShaper>> {
    if !opts.shaping() {
        tracing::debug!("no link flags: peer sockets are used directly");
        return None;
    }
    let initial = match &opts.link_profile {
        Some(path) => match LinkProfile::load(path) {
            Ok(p) => {
                tracing::info!(path = %path.display(), profile = %p, "--link-profile read");
                p
            }
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    "--link-profile not applied ({e:#}); the link starts unshaped"
                );
                LinkProfile::default()
            }
        },
        None => LinkProfile::default(),
    };
    let shaper = LinkShaper::new(initial);
    if let Some(path) = &opts.link_control {
        // Applied here, before any session can start, so the first peer already has it; the
        // watcher's first look then finds it unchanged.
        if path.exists() {
            let changed = shaper.apply_file(path, "link-control (startup)");
            tracing::debug!(changed, path = %path.display(), "--link-control applied at startup");
        } else {
            tracing::debug!(
                path = %path.display(),
                "--link-control does not exist yet; watching for it"
            );
        }
        let _watcher = shaper.watch_control_file(path.clone());
    }
    Some(shaper)
}

async fn run_agent(config: Config, opts: Options) -> Result<()> {
    let identity = match Identity::load_or_create() {
        Ok(id) => Arc::new(id),
        Err(e) => {
            tracing::error!("identity.json could not be loaded: {e:#}");
            return Err(e);
        }
    };

    // The same facts as the banner below, in the log: config.json is read before the subscriber
    // exists, so nothing else records which config and which device this run is.
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        pid = std::process::id(),
        device_id = %config.device_id,
        server = %config.server_url,
        // config.json held an address this build does not connect to, replaced at load
        // (`afklink_core::config`'s `server_moves_to`).
        server_moved_from = config.server_moved_from().unwrap_or("-"),
        config = %config.path().map_or_else(|| "-".to_string(), |p| p.display().to_string()),
        public_key = %identity.public_key_b64(),
        bench = opts.bench_mode(),
        "afklink-agent starting"
    );

    println!("AFKLink agent");
    println!("  device_id : {}", config.device_id);
    println!("  server    : {}", config.server_url);
    println!("  name      : {}", config.name);
    println!("  pubkey    : {}", identity.public_key_b64());
    if let Some(path) = config.path() {
        println!("  config    : {}", path.display());
    }
    println!();

    let device_id = config.device_id.clone();
    let shaper = build_link_shaper(&opts);
    // How the previous process with this data directory ended, and this one's record of its own
    // run (`afklink_core::run_state`; `--data-dir` moves it with the rest): claimed at once — the
    // CLI has no single-instance lock to wait for. Logged there.
    let first_run = identity.created_now();
    // What happened on this PC outside sessions, for the server (`afklink_core::agent_events`): a
    // queue beside the run state, claimed at once, sent on every connection after its handshake.
    let events = afklink_core::agent_events::EventQueue::open_default().map(Arc::new);
    if let Some(queue) = &events {
        afklink_core::agent_events::install(Arc::clone(queue));
    }
    let hello = match afklink_core::run_state::RunState::open_default() {
        Some(state) => {
            let state = Arc::new(state);
            state.claim();
            // This start (and the last one's panic, if it ended in one); the CLI is never started
            // by Windows' autostart.
            afklink_core::agent_events::record_start(&state, &build_info(), first_run, false);
            state.hello(&build_info())
        }
        None => afklink_transport::HelloInfo {
            build: build_info().wire(),
            ..Default::default()
        },
    };
    // Which way to the server — the configured address or the RU entry — remembered in the data
    // directory beside config.json, as the desktop app does (`afklink_core::entry`).
    let entry = Arc::new(afklink_core::entry::Entry::open_default(&config.server_url));
    let (agent, control) = Agent::new(config, identity, build_backends(&opts));
    let agent = match events {
        Some(queue) => agent.with_event_queue(queue),
        None => agent,
    };
    let agent = agent.with_entry(entry);
    // `replaced` stops the CLI: another process with this identity holds the backend connection,
    // and the CLI has no Retry button to wait on. Its exit is the clear stop (see the end of this
    // function); the desktop app waits for its owner instead.
    // The PC's hardware fingerprint in every hello (the invite-only beta), read once as the agent
    // starts (`afklink_hw`), as the desktop app does.
    let agent = agent
        .with_link_shaper(shaper)
        .with_on_replaced(OnReplaced::Stop)
        .with_user_agent(build_info().user_agent())
        .with_hello(hello)
        .with_hw_reader(Arc::new(afklink_hw::system));
    // The PC's trusted devices beside config.json, as the desktop app keeps them (device keys:
    // every offer goes through the admission). Opening reads the file, and a damaged list's
    // backup is checked when it is attached: blocking file I/O, so off the runtime's worker
    // (`block_in_place`, the default multi-thread runtime), before the agent runs.
    let agent = tokio::task::block_in_place(|| {
        let store = afklink_core::viewer_keys::TrustStore::open_default();
        tracing::debug!("trusted devices: the list opened for the CLI");
        agent.with_trust_store(store)
    });
    // Clipboard sync as in the desktop app, for viewers that turn it on — not on a bench run that
    // touches nothing of this PC (`--no-input`): its viewer is told the clipboard is unavailable.
    let agent = if opts.no_input {
        tracing::debug!(
            reason = "--no-input",
            "clipboard sync off: the bench touches nothing on this PC"
        );
        agent
    } else {
        agent.with_clipboard(Arc::new(afklink_clipboard::SystemClipboard::new()))
    };

    // Subscribed before the agent runs, so no event can come before its listener.
    tokio::spawn(announce(control.subscribe(), device_id));
    if opts.auto_approve_pairing {
        tokio::spawn(auto_pairing(control.clone(), control.subscribe()));
    }
    tokio::spawn(watch_pairing_code(control.clone()));

    // One terminal loop standing in for the GUI.
    //
    // It does both jobs the pairing panel does: opening it (which is what mints a
    // code — nothing mints one automatically any more) and answering the
    // confirmation prompt. A person at this machine typing `y` is the same guarantee
    // the GUI dialog provides, which is the entire point of the confirmation step.
    {
        let control = control.clone();
        tokio::spawn(async move {
            println!("Commands:  pair  = show a pairing code    cancel = hide it");
            println!("           y / n = answer a pairing request");
            println!("           retry = connect now (after the backend refused this agent)");
            println!("           stop  = end all sessions and refuse new ones");
            println!("           resume = accept connections again");
            println!("           quit  = end all sessions and exit, as Ctrl-C does\n");
            loop {
                let raw = match tokio::task::spawn_blocking(|| {
                    let mut buf = String::new();
                    // End of input is `Ok(0)`, not an error.
                    //
                    // Without that check this loop spun a core for the life of the process, and it
                    // only did so when stdin was not a terminal — a service, a redirected launch,
                    // anything a real deployment looks like. Measured on an agent that had never
                    // had a session: 142% of one core, no log line, no traffic, just a warm
                    // laptop. The `_ => return` arm below was written for exactly this case and
                    // could never be reached, because reading nothing from a closed handle
                    // succeeds.
                    std::io::stdin()
                        .read_line(&mut buf)
                        .ok()
                        .and_then(|read| (read > 0).then_some(buf))
                })
                .await
                {
                    // As read, line ending included: `TerminalCommand::read` trims it (and a BOM).
                    Ok(Some(l)) => l,
                    // stdin closed (service / redirected): stop reading. Not an exit: a launch
                    // with stdin ignored reads end of input at once (an older bench harness did)
                    // and must keep running; the harness now ends its agent with `quit`.
                    _ => {
                        tracing::debug!("stdin closed: terminal commands are off for this run");
                        return;
                    }
                };

                let pending = afklink_core::lock(&control.state).pending_pair.clone();

                match TerminalCommand::read(&raw, pending) {
                    // Whatever is waiting, a pairing request included: Ctrl-C's clean exit, for
                    // whoever cannot send Ctrl-C (the bench harness, which has no shared console
                    // with its agent). Does not return.
                    TerminalCommand::Quit => {
                        tracing::info!(
                            "terminal: quit — the clean exit (sessions ended, goodbye, last_exit \
                             app_exit)"
                        );
                        println!("  quitting: sessions end, the server is told goodbye\n");
                        clean_exit(&control, "the terminal's quit").await;
                    }
                    TerminalCommand::AnswerWhileLinkDown(p) => {
                        tracing::debug!(
                            request_id = %p.request_id,
                            link = p.link.as_str(),
                            "terminal: pairing answer typed while its link is down; not sent"
                        );
                        println!(
                            "  no connection to the server: {} is still waiting — answer once it is back.",
                            p.display_name()
                        );
                    }
                    TerminalCommand::Answer {
                        pending: p,
                        accept: false,
                    } => {
                        send_command(
                            &control,
                            afklink_core::AgentCommand::RespondToPair {
                                request_id: p.request_id,
                                accept: false,
                                role: None,
                                second_step: false,
                                shown: None,
                            },
                        );
                        println!("  -> declined\n");
                    }
                    TerminalCommand::Answer {
                        pending: p,
                        accept: true,
                    } => {
                        // Not asked «Кто это?»: an approval makes the person a guest. The
                        // line says what the core made of it.
                        let name = p.display_name();
                        let outcome = approve_and_wait(&control, p.request_id, None).await;
                        println!("  -> {}\n", approval_line(outcome, &name, false));
                    }
                    TerminalCommand::AnswerAsOwner(p) => {
                        let name = p.display_name();
                        let outcome = approve_and_wait(
                            &control,
                            p.request_id,
                            Some(afklink_core::BindingRole::Owner),
                        )
                        .await;
                        println!("  -> {}\n", approval_line(outcome, &name, true));
                    }
                    TerminalCommand::StillWaiting(p) if p.asks_role() => {
                        println!(
                            "  {} is waiting — answer o (the owner), y (a guest) or n.",
                            p.display_name()
                        );
                    }
                    TerminalCommand::StillWaiting(p) => {
                        println!("  {} is waiting — answer y or n.", p.display_name());
                    }
                    TerminalCommand::Pair => {
                        send_command(&control, afklink_core::AgentCommand::RequestPairing);
                    }
                    TerminalCommand::Cancel => {
                        send_command(&control, afklink_core::AgentCommand::CancelPairing);
                        println!("  pairing code revoked\n");
                    }
                    TerminalCommand::Retry => {
                        send_command(&control, afklink_core::AgentCommand::Retry);
                    }
                    // The kill switch: sessions end and new ones are refused until `resume` — kept
                    // in config.json, so a restart (the desktop app's too) is paused as well. The
                    // orchestrator logs both.
                    TerminalCommand::Stop => {
                        send_command(&control, afklink_core::AgentCommand::KillSwitch);
                        println!("  all sessions ended; new connections refused until `resume`\n");
                    }
                    TerminalCommand::Resume => {
                        send_command(&control, afklink_core::AgentCommand::Resume);
                        println!("  connections accepted again\n");
                    }
                    TerminalCommand::Empty => {}
                    TerminalCommand::Unknown(other) => println!("  unknown command: {other}"),
                }
            }
        });
    }

    // Surface a pairing request as soon as it arrives, so the prompt is not waiting
    // silently for someone who never looked at the terminal. With `--auto-approve-pairing` there
    // is nobody to ask: `auto_pairing` answers it.
    if !opts.auto_approve_pairing {
        let control = control.clone();
        tokio::spawn(async move {
            let mut announced: Option<String> = None;
            loop {
                let pending = afklink_core::lock(&control.state).pending_pair.clone();
                match pending {
                    Some(p) if announced.as_deref() != Some(p.request_id.as_str()) => {
                        announced = Some(p.request_id.clone());
                        println!("\n------------------------------");
                        println!("  {} wants to pair with this PC.", p.display_name());
                        if p.asks_role() {
                            // An unowned PC asks «Кто это?».
                            println!("  Approve as the owner [o], as a guest [y], or decline [n]?");
                        } else {
                            println!("  Approve?  [y/n]");
                        }
                        println!("------------------------------");
                    }
                    None => announced = None,
                    _ => {}
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        });
    }

    // Ctrl-C -> the clean exit (`clean_exit`, shared with the terminal's `quit`): the sessions end,
    // the goodbye to the backend (`quit`), then exit.
    {
        let control = control.clone();
        tokio::spawn(async move {
            match tokio::signal::ctrl_c().await {
                Ok(()) => {
                    tracing::info!(
                        "Ctrl-C: the clean exit (sessions ended, goodbye, last_exit app_exit)"
                    );
                    clean_exit(&control, "Ctrl-C").await;
                }
                // Then Ctrl-C ends the process the default way: no sessions ended, so a held
                // button is not released on the way out.
                Err(e) => tracing::warn!("Ctrl-C handler not installed: {e}"),
            }
        });
    }

    // An error here is the agent refusing to go on — `replaced`, or a relay that died — and the
    // process ends with it, non-zero. By `process::exit` rather than by returning it from `main`:
    // returning drops the runtime, which waits for every blocking task, and the terminal loop above
    // is one, parked in a `read_line` on a console nobody may ever type into again. The log is
    // written synchronously to stdout, so nothing is lost by not unwinding.
    if let Err(e) = agent.run().await {
        tracing::error!("agent stopped: {e:#}");
        eprintln!("afklink-agent: {e:#}");
        // Stopping by its own decision (`replaced`, a relay that died), not dying: the CLI stopped.
        afklink_core::run_state::record_exit(
            afklink_core::run_state::ExitKind::App,
            "the agent stopped with an error",
        );
        std::process::exit(1);
    }
    tracing::info!("agent stopped: nothing can command it any more");
    afklink_core::run_state::record_exit(
        afklink_core::run_state::ExitKind::App,
        "the agent stopped",
    );
    Ok(())
}

/// Print the pairing code whenever the backend issues one: the block a person reads, and the
/// `BENCH PAIRING_CODE=` line the harness reads.
async fn watch_pairing_code(control: AgentControl) {
    let mut last: Option<String> = None;
    loop {
        let code = afklink_core::lock(&control.state).pairing_code.clone();
        if code != last {
            match &code {
                Some(c) => {
                    // Grouped as three-and-three: six digits read back to a phone far more reliably
                    // in two chunks than as one run.
                    println!("\n==============================");
                    println!(
                        "  PAIRING CODE:  {}",
                        afklink_protocol::format_pairing_code(c)
                    );
                    if let Some(link) = control.deep_link() {
                        println!("  Deep link:     {link}");
                    }
                    println!("==============================\n");
                    stdout::emit(&stdout::pairing_code(c), "pairing_code");
                }
                None => tracing::debug!("pairing code withdrawn from the terminal"),
            }
            last = code;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// The `BENCH` lines that follow the orchestrator's lifecycle: `DEVICE_ID` (once) and `READY` when
/// signaling is up, `SESSION_START` and `SESSION_END`.
async fn announce(mut events: broadcast::Receiver<AgentEvent>, device_id: String) {
    let mut device_said = false;
    loop {
        match events.recv().await {
            Ok(AgentEvent::SignalingConnected { bindings }) => {
                if !device_said {
                    stdout::emit(&stdout::device_id(&device_id), "device_id");
                    device_said = true;
                }
                tracing::debug!(bindings, "signaling up: READY");
                stdout::emit(&stdout::ready(), "ready");
            }
            Ok(AgentEvent::SignalingDisconnected) => {
                tracing::debug!("signaling down: the next READY follows the reconnect");
            }
            // No BENCH line: the orchestrator logs the refusal at error, and under `replaced` the
            // process then exits (see `run_agent`), which is what a harness sees.
            Ok(AgentEvent::SignalingRefused(refusal)) => {
                // not-a-key-name: the server's error code
                tracing::debug!(
                    code = refusal.code(),
                    kind = refusal.kind(),
                    "signaling refused by the backend: no READY until it accepts this agent"
                );
            }
            Ok(AgentEvent::SessionStarted {
                session_id,
                telegram_user_id,
            }) => {
                tracing::debug!(session = %session_id, telegram_user_id, "SESSION_START");
                stdout::emit(&stdout::session_start(&session_id), "session_start");
            }
            Ok(AgentEvent::SessionEnded { session_id, reason }) => {
                tracing::debug!(session = %session_id, %reason, "SESSION_END");
                stdout::emit(&stdout::session_end(&session_id, &reason), "session_end");
            }
            // The desktop app's toast «Новый гость: {user}»; the CLI has no toasts and no BENCH
            // line for it — the orchestrator's `binding added` line has the guest and `via`.
            Ok(AgentEvent::GuestInvited {
                telegram_user_id,
                name,
            }) => tracing::debug!(
                telegram_user_id,
                name_source = name.source.as_str(),
                "new guest by the owner's invite: no toast in the CLI"
            ),
            // The desktop app's toast «{user}: новое устройство»; the CLI has no toasts — the
            // orchestrator's journal line has the device.
            Ok(AgentEvent::NewTrustedDevice {
                telegram_user_id,
                device,
                ..
            }) => tracing::debug!(
                telegram_user_id,
                ground = %device.source,
                "a person's new trusted device: no toast in the CLI"
            ),
            Err(broadcast::error::RecvError::Lagged(missed)) => tracing::warn!(
                missed,
                "agent events missed by the stdout announcer: their BENCH lines are lost"
            ),
            Err(broadcast::error::RecvError::Closed) => {
                tracing::debug!("agent event channel closed: no more BENCH lifecycle lines");
                return;
            }
        }
    }
}

/// Ask again for a pairing code this long before the one on screen expires.
const CODE_RENEW_BEFORE_MS: i64 = 10_000;
/// A requested code that has not arrived after this long is asked for again.
const CODE_ASK_AGAIN: Duration = Duration::from_secs(10);

/// `--auto-approve-pairing`: approve every pairing request, and keep a pairing code available while
/// this device has nobody bound.
///
/// The regular CLI mints a code only when someone types `pair` (a live code on screen is readable
/// by anyone watching the stream). A bench device has nobody at its terminal and a harness that
/// needs a code to bind its viewer, so it asks for one whenever signaling comes up with no binding,
/// again when the code nears its expiry, and stops once a binding exists. `pair` on stdin still
/// works.
async fn auto_pairing(control: AgentControl, mut events: broadcast::Receiver<AgentEvent>) {
    tracing::info!(
        "--auto-approve-pairing: pairing requests are approved without asking, and a pairing code \
         is requested while this device has nobody bound"
    );
    let mut answered: Option<String> = None;
    let mut asked_at: Option<Instant> = None;
    let mut tick = tokio::time::interval(Duration::from_millis(200));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            ev = events.recv() => match ev {
                Ok(AgentEvent::SignalingConnected { bindings }) => {
                    // A code dies with the connection that minted it, so a reconnect needs a new
                    // one whatever the terminal still shows.
                    if bindings == 0 {
                        request_pairing_code(&control, "signaling is up and nobody is bound");
                        asked_at = Some(Instant::now());
                    } else {
                        tracing::debug!(bindings, "bench device already bound: no pairing code needed");
                        asked_at = None;
                    }
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    tracing::warn!(missed, "auto-pairing missed agent events");
                }
                Err(broadcast::error::RecvError::Closed) => {
                    tracing::debug!("agent event channel closed: auto-pairing stops");
                    return;
                }
            },
            _ = tick.tick() => {}
        }

        let (connected, bound, expires_at, pending) = {
            let s = afklink_core::lock(&control.state);
            (
                s.connected,
                !s.bindings.is_empty(),
                s.pairing_code.as_ref().and(s.pairing_expires_at),
                s.pending_pair.clone(),
            )
        };

        if let Some(p) = pending {
            // A request kept across a break of the link is approved once the backend re-sends it:
            // an answer now would go nowhere, and it would count as given.
            if answered.as_deref() != Some(p.request_id.as_str()) && p.answerable() {
                tracing::info!(
                    request_id = %p.request_id,
                    telegram_user_id = p.telegram_user_id,
                    username = ?p.username,
                    first_name = ?p.first_name,
                    "--auto-approve-pairing: approving the pairing request from {}",
                    p.display_name()
                );
                // Nobody to ask «Кто это?»: a guest, as any approval that was not asked. The
                // line says what the core made of it.
                let name = p.display_name();
                let outcome = approve_and_wait(&control, p.request_id.clone(), None).await;
                println!(
                    "  {name} wants to pair: auto-approve — {}",
                    approval_line(outcome, &name, false)
                );
                answered = Some(p.request_id);
            }
        }

        if connected && !bound {
            let recently = asked_at.is_some_and(|t| t.elapsed() < CODE_ASK_AGAIN);
            let why = match expires_at {
                Some(e) if e - unix_ms() < CODE_RENEW_BEFORE_MS => {
                    Some("the pairing code is about to expire")
                }
                Some(_) => None,
                None => Some("no pairing code has arrived"),
            };
            if let (Some(why), false) = (why, recently) {
                request_pairing_code(&control, why);
                asked_at = Some(Instant::now());
            }
        }
    }
}

fn request_pairing_code(control: &AgentControl, why: &str) {
    tracing::info!(
        why,
        "bench device has no binding: asking the backend for a pairing code"
    );
    send_command(control, afklink_core::AgentCommand::RequestPairing);
}

fn unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Hand a command to the orchestrator, and say so if it is no longer there to take it.
fn send_command(control: &afklink_core::AgentControl, cmd: afklink_core::AgentCommand) {
    tracing::debug!(?cmd, "terminal command");
    if let Err(e) = control.commands.send(cmd) {
        tracing::warn!(cmd = ?e.0, "command not delivered: the agent has stopped");
    }
}

/// Set by the first [`clean_exit`]; a second request finds it set and waits for the first.
static EXITING: AtomicBool = AtomicBool::new(false);

/// The CLI's clean exit, for Ctrl-C and the terminal's `quit`, as the desktop app leaves
/// (`AgentControl::leave_blocking`): every live session ends (held input released, its final
/// report and `session_end agent_ended` in the connection's queue, at most `EXIT_END_BUDGET`), then
/// the goodbye to the backend (`quit`, bounded by `GOODBYE_BUDGET`), this process's exit recorded as
/// `app_exit` with `why` (so the next start says `last_exit = app_exit`, not `crash`), and
/// `process::exit(0)`. Does not return.
///
/// Not the kill switch: its pause is kept in config.json, and an exit by it would leave the next
/// start (the desktop app's too, which reads the same file) refusing everyone until «Возобновить».
/// The terminal's `stop` is the kill switch.
///
/// Runs once. A second request while it runs (Ctrl-C during `quit`, `quit` during Ctrl-C's exit)
/// is logged and waits: the first one ends the process.
async fn clean_exit(control: &AgentControl, why: &'static str) {
    if EXITING.swap(true, Ordering::SeqCst) {
        tracing::debug!(
            why,
            "exit asked again during the clean exit: ignored, the first one ends the process"
        );
        std::future::pending::<()>().await;
        return;
    }
    // Both halves block on the orchestrator's and the connection's answers, bounded: off the async
    // workers. Each logs its outcome.
    let leaving = control.clone();
    let outcome = match tokio::task::spawn_blocking(move || {
        leaving.leave_blocking(
            afklink_core::GoodbyeReason::Quit,
            afklink_core::GOODBYE_BUDGET,
        )
    })
    .await
    {
        Ok(outcome) => outcome,
        Err(e) => {
            tracing::error!(
                why,
                "clean exit: the thread that ended the sessions and said goodbye failed ({e}); \
                 exiting all the same"
            );
            afklink_core::GoodbyeOutcome::NoConnection
        }
    };
    tracing::debug!(
        why,
        outcome = outcome.kind(),
        "clean exit: goodbye done, exiting"
    );
    // The next start's `last_exit`: the owner (or the bench harness) stopped it.
    afklink_core::run_state::record_exit(afklink_core::run_state::ExitKind::App, why);
    std::process::exit(0);
}

/// Capture + encode a few frames locally to validate the pipeline offline. The capture is the
/// corpus under `--capture-corpus`, the screen otherwise.
fn selftest(mut capturer: Box<dyn Capturer>) -> Result<()> {
    println!("selftest: starting capture + OpenH264 encode for ~3s...");

    let (tx, rx) = std::sync::mpsc::channel::<afklink_core::Frame>();
    // The selftest is checking that the pipeline works at all, so it exercises a demanding load
    // rather than whatever a degraded link would pick: the tallest height a viewer can pin, at 60
    // fps. A load of its own, not a rung of any quality profile (it runs no session).
    let rung = afklink_core::quality::Rung {
        max_h: afklink_core::quality::PINNABLE_HEIGHTS[0],
        fps: 60,
    };
    tracing::debug!(
        max_h = rung.max_h,
        fps = rung.fps,
        "selftest: capture and encode at this load"
    );
    let target = std::sync::Arc::new(afklink_core::quality::QualityTarget::new(rung));
    capturer.start(tx, target)?;

    let mut encoder = OpenH264Encoder::with_defaults()?;
    let start = Instant::now();
    let mut encoded = 0u32;
    let mut got_keyframe = false;

    while start.elapsed() < Duration::from_secs(3) && encoded < 60 {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(mut frame) => {
                frame.timestamp_ms = start.elapsed().as_millis() as u64;
                match encoder.encode(&frame)? {
                    Some(ef) => {
                        encoded += 1;
                        got_keyframe |= ef.is_keyframe;
                        println!(
                            "  frame {encoded:>3}: {}x{}  ->  {:>6} bytes  keyframe={}",
                            frame.width,
                            frame.height,
                            ef.data.len(),
                            ef.is_keyframe
                        );
                    }
                    None => println!("  (encoder produced no output for this frame)"),
                }
            }
            Err(_) => println!("  (no frame within 500ms)"),
        }
    }

    capturer.stop();
    println!("selftest: done — {encoded} encoded frames, keyframe seen: {got_keyframe}");
    if encoded == 0 {
        anyhow::bail!("no frames encoded (is a desktop session active?)");
    }
    Ok(())
}

/// What the core made of a pairing approval typed here, as its state shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApprovalOutcome {
    /// Not decided yet (the orchestrator has not taken the command).
    Pending,
    /// The request is answered (the approval went to the server).
    Approved,
    /// The request is answered, via `pc_allow`: the owner is asked (a session of someone who is
    /// not the owner is live); for a removed person the device is not added.
    OwnerAsked,
    /// A removed person, or an owner on this PC (spec §5): the core needs the window's second
    /// step, which the terminal does not give — nothing was sent, the request still waits.
    SecondStepRequired,
    /// The role given is not the one this PC derives for the person (spec §5): nothing was sent,
    /// the request still waits.
    RoleRefused,
    /// The request was not waiting (answered, cancelled, expired or forgotten at the bound):
    /// the core sent nothing.
    NotWaiting,
    /// The answer went as a decline — a change of the person's role on this PC overtook the press.
    Declined,
    /// The request's link is down: nothing was sent, the request stays.
    LinkDown,
    /// The approval went, but its device key was not added to this PC's list (the key's
    /// write was refused, or wrote another key). `why` names which.
    ApprovedKeyNotWritten(afklink_core::agent::KeyNotWritten),
}

/// [`ApprovalOutcome`] of an approval of `request_id`: the outcome the core kept for
/// that request id ([`afklink_core::AgentState::pair_answers`]) — never one guessed from the
/// request leaving the state (it may have expired, been withdrawn or declined as overtaken).
/// None kept yet, held for its key's write, or sent with that write not landed yet:
/// [`ApprovalOutcome::Pending`].
fn approval_outcome(state: &afklink_core::AgentState, request_id: &str) -> ApprovalOutcome {
    use afklink_core::agent::PairAnswer;
    match state.pair_answers.get(request_id) {
        // Sent while its key's write had not landed — not «approved» until it does.
        None | Some(PairAnswer::Held | PairAnswer::SentKeyPending) => ApprovalOutcome::Pending,
        Some(PairAnswer::Sent {
            accept: true,
            via_pc_allow: false,
        }) => ApprovalOutcome::Approved,
        Some(PairAnswer::Sent {
            accept: true,
            via_pc_allow: true,
        }) => ApprovalOutcome::OwnerAsked,
        Some(PairAnswer::Sent { accept: false, .. }) => ApprovalOutcome::Declined,
        Some(PairAnswer::SecondStepRequired) => ApprovalOutcome::SecondStepRequired,
        Some(PairAnswer::RoleRefused) => ApprovalOutcome::RoleRefused,
        Some(PairAnswer::NotWaiting) => ApprovalOutcome::NotWaiting,
        Some(PairAnswer::LinkDown) => ApprovalOutcome::LinkDown,
        Some(PairAnswer::SentKeyNotWritten { why }) => ApprovalOutcome::ApprovedKeyNotWritten(why),
    }
}

/// How long the terminal waits for the core to take its approval before it says so.
const APPROVAL_WAIT: Duration = Duration::from_secs(3);

/// Send the approval of `request_id` (`role`), then wait (polling the state, at most
/// [`APPROVAL_WAIT`]) for what the core made of it; logged at every outcome.
async fn approve_and_wait(
    control: &AgentControl,
    request_id: String,
    role: Option<afklink_core::BindingRole>,
) -> ApprovalOutcome {
    // An outcome kept from an earlier answer of this id is not this press's.
    if afklink_core::lock(&control.state)
        .pair_answers
        .forget(&request_id)
    {
        tracing::debug!(
            %request_id,
            "terminal: an earlier answer's outcome under this id forgotten before the press"
        );
    }
    send_command(
        control,
        afklink_core::AgentCommand::RespondToPair {
            request_id: request_id.clone(),
            accept: true,
            role,
            // The terminal gives no second step, so a press that would write a key for an owner on
            // this PC is not approved from here (`SecondStepRequired`); without a key to write, an
            // owner's approve goes through. Anyone else's approve is a pairing at the PC, as in
            // the window — a person removed at this PC is let back by it too.
            second_step: false,
            shown: None,
        },
    );
    let until = Instant::now() + APPROVAL_WAIT;
    loop {
        let outcome = approval_outcome(&afklink_core::lock(&control.state), &request_id);
        if outcome != ApprovalOutcome::Pending || Instant::now() >= until {
            tracing::debug!(
                %request_id,
                outcome = ?outcome,
                "terminal: the pairing approval's outcome{}",
                if outcome == ApprovalOutcome::Pending {
                    " — none within the wait (the core has not taken it yet)"
                } else {
                    ""
                }
            );
            return outcome;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The terminal's line for an approval's outcome (`as_owner`: «o»).
fn approval_line(outcome: ApprovalOutcome, name: &str, as_owner: bool) -> String {
    match outcome {
        ApprovalOutcome::Approved if as_owner => "approved as the owner".to_string(),
        ApprovalOutcome::Approved => "approved".to_string(),
        ApprovalOutcome::OwnerAsked => {
            "approved here; the owner is asked (a session of someone else is live)".to_string()
        }
        ApprovalOutcome::SecondStepRequired => format!(
            "not approved: {name} needs a second step at the window (removed from this PC, or \
             the owner's own device); the terminal gives none — answer from the window"
        ),
        ApprovalOutcome::RoleRefused => format!(
            "not approved: this PC has an owner and gives {name} another role than the one sent; \
             nothing was sent — answer from the window"
        ),
        // The terminal stops waiting here; the core may still settle it (a key's write).
        ApprovalOutcome::Pending => format!(
            "sent; no outcome from the agent within {} s — the terminal stops waiting, and the \
             outcome may still change",
            APPROVAL_WAIT.as_secs()
        ),
        ApprovalOutcome::NotWaiting => {
            format!("not approved: {name}'s request no longer waits; nothing was sent")
        }
        ApprovalOutcome::Declined => format!(
            "not approved: {name}'s role on this PC changed after the press; the request was \
             declined"
        ),
        ApprovalOutcome::LinkDown => {
            "not sent: no link to the server; the request stays — answer again once it is back"
                .to_string()
        }
        // What became of the key, as the core says it.
        ApprovalOutcome::ApprovedKeyNotWritten(afklink_core::agent::KeyNotWritten::Refused) => {
            format!(
                "approved, but {name}'s device key was not added to this PC's list (its write was \
                 refused); the device is not trusted here"
            )
        }
        ApprovalOutcome::ApprovedKeyNotWritten(afklink_core::agent::KeyNotWritten::AnotherKey) => {
            format!(
                "approved, but {name}'s device key was not added to this PC's list (another key \
                 took this pairing's place); the device is not trusted here"
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The terminal says the outcome the core kept for its own
    /// request id — never «approved» because the request left the state (expired, withdrawn,
    /// declined as overtaken by a role change), and not another request's outcome.
    #[test]
    fn the_terminal_reads_the_outcome_kept_for_its_request() {
        use afklink_core::agent::PairAnswer;
        let mut s = afklink_core::AgentState::default();
        assert_eq!(
            approval_outcome(&s, "r1"),
            ApprovalOutcome::Pending,
            "gone with no outcome: not taken yet, not «approved»"
        );
        for (answer, want) in [
            (PairAnswer::Held, ApprovalOutcome::Pending),
            // Sent, its key's write not landed: not «approved» yet.
            (PairAnswer::SentKeyPending, ApprovalOutcome::Pending),
            (
                PairAnswer::Sent {
                    accept: true,
                    via_pc_allow: false,
                },
                ApprovalOutcome::Approved,
            ),
            (
                PairAnswer::Sent {
                    accept: true,
                    via_pc_allow: true,
                },
                ApprovalOutcome::OwnerAsked,
            ),
            (
                PairAnswer::Sent {
                    accept: false,
                    via_pc_allow: false,
                },
                ApprovalOutcome::Declined,
            ),
            (
                PairAnswer::SecondStepRequired,
                ApprovalOutcome::SecondStepRequired,
            ),
            (PairAnswer::RoleRefused, ApprovalOutcome::RoleRefused),
            (PairAnswer::NotWaiting, ApprovalOutcome::NotWaiting),
            (PairAnswer::LinkDown, ApprovalOutcome::LinkDown),
            // The approval went, its key's write ended without the key: never «approved».
            (
                PairAnswer::SentKeyNotWritten {
                    why: afklink_core::agent::KeyNotWritten::AnotherKey,
                },
                ApprovalOutcome::ApprovedKeyNotWritten(
                    afklink_core::agent::KeyNotWritten::AnotherKey,
                ),
            ),
        ] {
            s.pair_answers.note("r1", answer);
            assert_eq!(approval_outcome(&s, "r1"), want, "{answer:?}");
        }
        assert_eq!(
            approval_outcome(&s, "r2"),
            ApprovalOutcome::Pending,
            "another request's outcome says nothing of this one"
        );
    }

    /// The terminal's line says what became of
    /// the device key — «refused» only for a refused write, not for another key written — and
    /// that the terminal stops waiting after
    /// [`APPROVAL_WAIT`] while the outcome may still change.
    #[test]
    fn the_terminals_line_says_why_the_key_was_not_added_and_when_it_stops_waiting() {
        use afklink_core::agent::KeyNotWritten;
        let line = |why| approval_line(ApprovalOutcome::ApprovedKeyNotWritten(why), "Vera", false);
        let another = line(KeyNotWritten::AnotherKey);
        assert!(!another.contains("refused"), "{another}");
        assert!(another.contains("another"), "{another}");
        let refused = line(KeyNotWritten::Refused);
        assert!(refused.contains("refused"), "{refused}");
        let pending = approval_line(ApprovalOutcome::Pending, "Vera", false);
        assert!(
            pending.contains(&format!("{} s", APPROVAL_WAIT.as_secs())),
            "{pending}"
        );
        assert!(pending.contains("may still change"), "{pending}");
    }
    use afklink_core::build_info::Channel;
    use afklink_core::logging::{LogLevel, RELEASE_PHASE};

    const COMMIT: &str = "3a3bc46e0f1d2c3b4a5968778695a4b3c2d1e0f9";

    fn build(channel: &str) -> BuildInfo {
        BuildInfo::from_stamp("0.1.0", COMMIT, "0", "2026-09-28T20:15:07Z", channel)
    }

    fn config(log_level: Option<&str>) -> Config {
        let mut c: Config =
            serde_json::from_str(r#"{"device_id":"d","server_url":"ws://x","name":"n"}"#)
                .expect("minimal config parses");
        c.log_level = log_level.map(str::to_string);
        c
    }

    /// The CLI resolves its level the way the desktop app does: the channel's default until a
    /// level is chosen in config.json, and the choice after that, on either channel.
    #[test]
    fn the_cli_level_follows_the_channel_until_one_is_chosen() {
        let release = build("release");
        let dev = build("");
        assert_eq!(release.channel, Channel::Release);
        assert_eq!(dev.channel, Channel::Dev);

        // A release's default is its phase's (`debug` during the beta test, `info` after it).
        let release_default = RELEASE_PHASE.default_log_level();
        let none = config(None);
        assert_eq!(startup_filter(Some(&none), &release).level, release_default);
        assert_eq!(startup_filter(Some(&none), &dev).level, LogLevel::Debug);

        let chosen = config(Some("info"));
        assert_eq!(
            startup_filter(Some(&chosen), &release).level,
            LogLevel::Info
        );
        assert_eq!(startup_filter(Some(&chosen), &dev).level, LogLevel::Info);
        // A stored level outside the three the window offers means what it means in the desktop app:
        // `warn` and `error` are «Обычные», `info`; `trace` stays `trace`.
        for (stored, want) in [
            ("warn", LogLevel::Info),
            ("error", LogLevel::Info),
            ("trace", LogLevel::Trace),
        ] {
            let old = config(Some(stored));
            assert_eq!(startup_filter(Some(&old), &release).level, want, "{stored}");
            assert_eq!(startup_filter(Some(&old), &dev).level, want, "{stored}");
        }

        // A config that could not be read still logs, at the channel's default.
        assert_eq!(startup_filter(None, &release).level, release_default);
        assert_eq!(startup_filter(None, &dev).level, LogLevel::Debug);
    }

    /// A plain `cargo test` build carries no release stamp: the development channel.
    #[test]
    fn an_unstamped_build_is_dev() {
        if env!("AFKLINK_BUILD_CHANNEL").is_empty() {
            assert_eq!(build_info().channel, Channel::Dev);
        }
    }
}
