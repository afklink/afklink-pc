#![cfg_attr(windows, windows_subsystem = "windows")]

/// The task starts the helper with no arguments: whatever it does comes from `record.json`
/// beside it. Anything on the command line means this is not the task — refused.
const EXIT_ARGUMENTS: i32 = 2;

fn main() {
    if std::env::args_os().len() > 1 {
        std::process::exit(EXIT_ARGUMENTS);
    }
    std::process::exit(afklink_game_helper::run());
}
