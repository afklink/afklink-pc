//! The terminal's commands: one line typed on stdin, read against the pairing request waiting for an
//! answer, if one is. Pure, so what each line does is tested without a terminal; the terminal loop in
//! `run_agent` acts on the result.

use afklink_core::agent::PendingPair;

/// What one line typed at the terminal asks for.
#[derive(Debug)]
pub(crate) enum TerminalCommand {
    /// `quit` or `exit`: the clean exit (`clean_exit` in `main.rs`, the same as Ctrl-C) — whatever
    /// else is going on, a pairing request waiting for an answer included. The bench harness ends
    /// its agent this way, so the next start says `last_exit = app_exit`, not `crash`.
    Quit,
    /// A pairing answer (`y`, `n`, `o` or their long forms) while the request's link is down: kept
    /// for the backend's re-send, not sent (`afklink_core::pairing`).
    AnswerWhileLinkDown(PendingPair),
    /// `y` / `yes` (`accept`; a guest — «Кто это?» is not asked) or `n` / `no`.
    Answer { pending: PendingPair, accept: bool },
    /// `o` / `owner`: approved as the owner — only where the request asks «Кто это?» (the PC has no
    /// owner).
    AnswerAsOwner(PendingPair),
    /// Any other line while a request waits: its prompt again.
    StillWaiting(PendingPair),
    /// `pair`: ask for a pairing code.
    Pair,
    /// `cancel`: revoke it.
    Cancel,
    /// `retry`: connect now (after the backend refused this agent).
    Retry,
    /// `stop`: the kill switch, without the exit.
    Stop,
    /// `resume`: accept connections again.
    Resume,
    /// An empty line, nothing waiting.
    Empty,
    /// Any other line, nothing waiting: as read (trimmed, lower case).
    Unknown(String),
}

impl TerminalCommand {
    /// Read `raw` (one line as it came from stdin, line ending included) with `pending`, the pairing
    /// request waiting for an answer, if any.
    pub(crate) fn read(raw: &str, pending: Option<PendingPair>) -> Self {
        // Strip a leading BOM as well as whitespace. Anything that pipes into this process - a
        // wrapper script, a test harness, a text editor - can prepend U+FEFF, and a command that
        // silently fails to match because of an invisible character is a miserable way to spend an
        // afternoon.
        let line = raw
            .trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}')
            .to_ascii_lowercase();
        // Before the pairing arms: while a request waits every other line only repeats its prompt,
        // and leaving must not depend on answering it first.
        if matches!(line.as_str(), "quit" | "exit") {
            return Self::Quit;
        }
        match (pending, line.as_str()) {
            // Kept across a break of the link: the answer waits for the backend's re-send (the
            // orchestrator would not send it; `afklink_core::pairing`).
            (Some(p), "y" | "yes" | "n" | "no" | "o" | "owner") if !p.answerable() => {
                Self::AnswerWhileLinkDown(p)
            }
            (Some(p), "y" | "yes" | "n" | "no") => Self::Answer {
                accept: line.starts_with('y'),
                pending: p,
            },
            // «Кто это?» answered «Владелец»: only where the PC has no owner (the server makes the
            // person a guest anywhere else).
            (Some(p), "o" | "owner") if p.asks_role() => Self::AnswerAsOwner(p),
            (Some(p), _) => Self::StillWaiting(p),
            (None, "pair") => Self::Pair,
            (None, "cancel") => Self::Cancel,
            (None, "retry") => Self::Retry,
            (None, "stop") => Self::Stop,
            (None, "resume") => Self::Resume,
            (None, "") => Self::Empty,
            (None, other) => Self::Unknown(other.to_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afklink_core::pairing::PairLink;

    fn request(link: PairLink, has_owner: Option<bool>) -> PendingPair {
        PendingPair {
            request_id: "req-1".to_owned(),
            telegram_user_id: 9_000_000_001,
            username: Some("afklink_bench".to_owned()),
            first_name: Some("Bench".to_owned()),
            expires_at: 0,
            has_owner,
            link,
        }
    }

    /// A request on a live link, on a PC with an owner: `y` makes a guest.
    fn live() -> PendingPair {
        request(PairLink::Live, Some(true))
    }

    /// A request on a live link, on an unowned PC, which asks «Кто это?».
    fn asks_role() -> PendingPair {
        request(PairLink::Live, Some(false))
    }

    /// A request kept across a break of the link: no answer can go.
    fn link_down() -> PendingPair {
        request(PairLink::Lost { since_ms: 1 }, Some(true))
    }

    fn idle(line: &str) -> TerminalCommand {
        TerminalCommand::read(line, None)
    }

    const QUIT_LINES: [&str; 9] = [
        "quit",
        "exit",
        "QUIT",
        "Exit",
        " quit \r\n",
        "quit\n",
        "\tEXIT\r\n",
        "\u{feff}quit\n",
        "\u{feff} quit \r\n",
    ];

    /// `quit` and `exit` (any case, any surrounding whitespace, a BOM) are the clean exit, with or
    /// without a pairing request waiting — in every state it can wait in.
    #[test]
    fn quit_and_exit_leave_in_every_state() {
        for line in QUIT_LINES {
            assert!(
                matches!(idle(line), TerminalCommand::Quit),
                "{line:?}, nothing waiting"
            );
            for (state, pending) in [
                ("live", live()),
                ("asks the role", asks_role()),
                ("link down", link_down()),
            ] {
                assert!(
                    matches!(
                        TerminalCommand::read(line, Some(pending)),
                        TerminalCommand::Quit
                    ),
                    "{line:?}, a request waiting ({state})"
                );
            }
        }
    }

    /// Only the whole word: anything around it is another line.
    #[test]
    fn near_misses_are_not_quit() {
        for (line, read) in [
            ("quit now", "quit now"),
            ("q", "q"),
            ("quitt", "quitt"),
            ("exit()", "exit()"),
            ("Quit!", "quit!"),
        ] {
            assert!(
                matches!(idle(line), TerminalCommand::Unknown(ref w) if w.as_str() == read),
                "{line:?}"
            );
            assert!(
                matches!(
                    TerminalCommand::read(line, Some(live())),
                    TerminalCommand::StillWaiting(_)
                ),
                "{line:?}, a request waiting"
            );
        }
    }

    /// With nothing waiting, the commands read as they always did.
    #[test]
    fn the_other_commands_are_unchanged_with_nothing_waiting() {
        assert!(matches!(idle("pair"), TerminalCommand::Pair));
        assert!(matches!(idle(" PAIR\r\n"), TerminalCommand::Pair));
        assert!(matches!(idle("cancel"), TerminalCommand::Cancel));
        assert!(matches!(idle("retry"), TerminalCommand::Retry));
        assert!(matches!(idle("stop"), TerminalCommand::Stop));
        assert!(matches!(idle("resume"), TerminalCommand::Resume));
        assert!(matches!(idle("\u{feff}resume\n"), TerminalCommand::Resume));
        assert!(matches!(idle(""), TerminalCommand::Empty));
        assert!(matches!(idle(" \r\n"), TerminalCommand::Empty));
        assert!(matches!(idle("\u{feff}"), TerminalCommand::Empty));
        // A pairing answer with nothing to answer is just a word nobody knows.
        for (line, read) in [("y", "y"), ("No", "no"), ("o", "o"), ("Hello", "hello")] {
            assert!(
                matches!(idle(line), TerminalCommand::Unknown(ref w) if w.as_str() == read),
                "{line:?}"
            );
        }
    }

    /// With a request waiting, the answers and the prompt read as they always did.
    #[test]
    fn a_waiting_request_reads_as_before() {
        for (line, want) in [("y", true), ("YES", true), ("n", false), ("no", false)] {
            for pending in [live(), asks_role()] {
                assert!(
                    matches!(
                        TerminalCommand::read(line, Some(pending)),
                        TerminalCommand::Answer { accept, .. } if accept == want
                    ),
                    "{line:?}"
                );
            }
        }
        assert!(matches!(
            TerminalCommand::read("y", Some(live())),
            TerminalCommand::Answer { ref pending, .. } if pending.request_id == "req-1"
        ));
        for line in ["o", "owner", " Owner\r\n"] {
            assert!(
                matches!(
                    TerminalCommand::read(line, Some(asks_role())),
                    TerminalCommand::AnswerAsOwner(_)
                ),
                "{line:?}"
            );
        }
        // «Владелец» only where the PC has no owner: elsewhere `o` is just another line.
        assert!(matches!(
            TerminalCommand::read("o", Some(live())),
            TerminalCommand::StillWaiting(_)
        ));
        // Every answer waits while the request's link is down.
        for line in ["y", "yes", "n", "no", "o", "owner"] {
            assert!(
                matches!(
                    TerminalCommand::read(line, Some(link_down())),
                    TerminalCommand::AnswerWhileLinkDown(_)
                ),
                "{line:?}"
            );
        }
        // Any other line only repeats the prompt — the other commands included.
        for line in ["pair", "cancel", "retry", "stop", "resume", "", "hello"] {
            for pending in [live(), asks_role(), link_down()] {
                assert!(
                    matches!(
                        TerminalCommand::read(line, Some(pending)),
                        TerminalCommand::StillWaiting(_)
                    ),
                    "{line:?}"
                );
            }
        }
    }
}
