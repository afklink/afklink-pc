//! Pairing deep link + QR code.
//!
//! Where the link points — the bot and its Mini App — comes from the backend with each code
//! (`pairing_code`): it runs that bot and validates initData with its token, so a
//! link to any other bot cannot pair. `config.json` may override either value, for development.
//! With no bot known there is no link at all, and the window shows the code alone, never a
//! placeholder bot (`YourBot`) that a phone would open and find missing.

use anyhow::Result;
use base64::prelude::*;
use qrcode::render::svg;
use qrcode::QrCode;

/// Build the Telegram deep link that opens the Mini App with the pairing code:
/// `https://t.me/<bot>/<app>?startapp=<code>`.
///
/// No `mode`, the same as the bot's pairing link (backend `server/src/telegram/bot.ts`,
/// `pairingLink()`): a Direct Link Mini App opens at full height by default, which is what the
/// device list and pairing are laid out for. Only the viewer is ever fullscreen, and it asks for that
/// itself. An older agent's link and QR say `mode=fullscreen`, and the Mini App gives that
/// fullscreen back at start (miniapp `src/telegram.ts`, `dropUnwantedFullscreen`).
pub fn deep_link(bot_username: &str, miniapp_short_name: &str, code: &str) -> String {
    format!("https://t.me/{bot_username}/{miniapp_short_name}?startapp={code}")
}

/// How the pairing link opens, for the log next to its shape.
const LINK_OPENS: &str = "full height (no mode)";

/// Where one value of the pairing link came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkSource {
    /// `config.json` (`bot_username` / `miniapp_short_name`): a developer's override.
    Config,
    /// The backend's `pairing_code` (its `TG_BOT_USERNAME` / `TG_MINIAPP_SHORT_NAME`).
    Server,
}

impl LinkSource {
    /// For the log.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Server => "server",
        }
    }
}

/// The two values of a pairing link as one place has them. `None`, empty or blank: not set.
#[derive(Debug, Clone, Copy, Default)]
pub struct LinkNames<'a> {
    pub bot_username: Option<&'a str>,
    pub short_name: Option<&'a str>,
}

/// The bot and Mini App a pairing link opens: `t.me/<bot_username>/<short_name>`, and where each
/// came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkTarget {
    pub bot_username: String,
    pub short_name: String,
    pub bot_from: LinkSource,
    pub short_name_from: LinkSource,
}

impl LinkTarget {
    /// The deep link for `code`.
    pub fn link(&self, code: &str) -> String {
        deep_link(&self.bot_username, &self.short_name, code)
    }
}

/// Whether `value` can stand in `t.me/<bot>/<app>`: letters, digits and underscores, as Telegram
/// allows (mirrors `telegramNameSchema` in `packages/protocol/src/common.ts`).
fn is_telegram_name(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// `value`, trimmed, if it is set and a Telegram name. A value that is set but is not one is
/// ignored with a warning: it would make a link that opens nothing, or something else.
fn usable<'a>(field: &'static str, source: LinkSource, value: Option<&'a str>) -> Option<&'a str> {
    let value = value.map(str::trim).filter(|v| !v.is_empty())?;
    if is_telegram_name(value) {
        return Some(value);
    }
    tracing::warn!(
        field,
        source = source.as_str(),
        len = value.len(),
        value = %value.chars().take(64).collect::<String>(),
        "pairing link: not a Telegram name (letters, digits, _); ignored"
    );
    None
}

/// One value of the link: a usable `config.json` override wins, else the backend's, else none.
fn pick<'a>(
    field: &'static str,
    config: Option<&'a str>,
    server: Option<&'a str>,
) -> Option<(&'a str, LinkSource)> {
    let config = usable(field, LinkSource::Config, config);
    let server = usable(field, LinkSource::Server, server);
    match (config, server) {
        (Some(c), Some(s)) if !c.eq_ignore_ascii_case(s) => {
            // The backend validates initData with its own bot's token: a Mini App opened through
            // another bot is refused, so this override is right only on purpose.
            tracing::warn!(
                field,
                config = c,
                server = s,
                "pairing link: config.json overrides the backend's value; the link opens a \
                 different bot or app than the backend runs"
            );
            Some((c, LinkSource::Config))
        }
        (Some(c), server) => {
            tracing::debug!(
                field,
                value = c,
                server = server.unwrap_or("-"),
                "pairing link: config.json value used"
            );
            Some((c, LinkSource::Config))
        }
        (None, Some(s)) => Some((s, LinkSource::Server)),
        (None, None) => None,
    }
}

/// Where a pairing link should point, from the backend's values (`server`) and `config.json`'s
/// overrides (`config`); `None` when the bot or the Mini App is unknown, and then no link is offered
/// at all — no QR, no copy link, the code alone.
///
/// Called once per pairing code, not per render: it logs its decision — debug with the sources
/// when there is a link, a warning with the reason when there is none.
pub fn resolve_target(config: LinkNames<'_>, server: LinkNames<'_>) -> Option<LinkTarget> {
    let bot = pick("bot_username", config.bot_username, server.bot_username);
    let app = pick("miniapp_short_name", config.short_name, server.short_name);
    match (bot, app) {
        (Some((bot, bot_from)), Some((app, app_from))) => {
            // The link's shape, built by the same function as the link itself, with a placeholder
            // for the code: the code is a live credential while the panel is open and is never
            // logged (`agent.rs`, `PairingCode`).
            tracing::debug!(
                bot_username = bot,
                bot_from = bot_from.as_str(),
                miniapp_short_name = app,
                short_name_from = app_from.as_str(),
                link = %deep_link(bot, app, "<code>"),
                opens = LINK_OPENS,
                "pairing link target chosen"
            );
            Some(LinkTarget {
                bot_username: bot.to_string(),
                short_name: app.to_string(),
                bot_from,
                short_name_from: app_from,
            })
        }
        (bot, app) => {
            let missing = match (bot.is_none(), app.is_none()) {
                (true, true) => "the bot and the Mini App short name",
                (true, false) => "the bot",
                _ => "the Mini App short name",
            };
            tracing::warn!(
                bot_username = bot.map_or("-", |(v, _)| v),
                miniapp_short_name = app.map_or("-", |(v, _)| v),
                server_sent_bot = server.bot_username.is_some(),
                server_sent_short_name = server.short_name.is_some(),
                "no pairing link: {missing} unknown — the backend sent none (older than the field, \
                 or TG_BOT_USERNAME / TG_MINIAPP_SHORT_NAME unset) and config.json has no override; \
                 the window shows the code only"
            );
            None
        }
    }
}

/// Render `data` (typically a deep link) as an SVG QR code string.
pub fn qr_svg(data: &str) -> Result<String> {
    let code = QrCode::new(data.as_bytes())?;
    let svg = code
        .render::<svg::Color>()
        .min_dimensions(220, 220)
        .dark_color(svg::Color("#111111"))
        .light_color(svg::Color("#ffffff"))
        .build();
    Ok(svg)
}

/// Render `data` as an SVG QR code and wrap it in a `data:` URI (for `<img>`).
pub fn qr_svg_data_uri(data: &str) -> Result<String> {
    let svg = qr_svg(data)?;
    Ok(format!(
        "data:image/svg+xml;base64,{}",
        BASE64_STANDARD.encode(svg)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names<'a>(bot: Option<&'a str>, app: Option<&'a str>) -> LinkNames<'a> {
        LinkNames {
            bot_username: bot,
            short_name: app,
        }
    }

    const NONE: LinkNames<'static> = LinkNames {
        bot_username: None,
        short_name: None,
    };

    #[test]
    fn the_backends_values_make_the_link() {
        let target = resolve_target(NONE, names(Some("afklink_bot"), Some("app")))
            .expect("the backend named the bot");
        assert_eq!(target.bot_from, LinkSource::Server);
        assert_eq!(target.short_name_from, LinkSource::Server);
        assert_eq!(
            target.link("568048"),
            "https://t.me/afklink_bot/app?startapp=568048"
        );
    }

    /// Only the viewer is ever fullscreen. The PC's link and QR ask for no mode at
    /// all, as the bot's link does: full height, Telegram's default for a Direct Link Mini App.
    #[test]
    fn the_link_asks_for_no_mode() {
        let link = deep_link("afklink_bot", "app", "000123");
        assert!(!link.contains("mode="), "{link}");
        assert!(!link.contains('&'), "only `startapp`: {link}");
    }

    #[test]
    fn a_config_override_wins_value_by_value() {
        let target = resolve_target(
            names(Some("dev_bot"), None),
            names(Some("afklink_bot"), Some("app")),
        )
        .expect("a link");
        assert_eq!(target.bot_username, "dev_bot");
        assert_eq!(target.bot_from, LinkSource::Config);
        assert_eq!(target.short_name, "app");
        assert_eq!(target.short_name_from, LinkSource::Server);

        // Both overridden: the backend is not needed at all (a developer against an old backend).
        let target = resolve_target(names(Some("dev_bot"), Some("devapp")), NONE).expect("a link");
        assert_eq!(
            target.link("000123"),
            "https://t.me/dev_bot/devapp?startapp=000123"
        );
    }

    /// A config with `bot_username: null` and nothing from the backend either: no link, never a
    /// placeholder such as `YourBot`.
    #[test]
    fn no_bot_means_no_link() {
        assert_eq!(resolve_target(NONE, NONE), None);
        // Short name known, bot not: still nothing.
        assert_eq!(resolve_target(NONE, names(None, Some("app"))), None);
        assert_eq!(resolve_target(names(None, Some("app")), NONE), None);
        // Bot known, short name not: no guessed `app` either.
        assert_eq!(resolve_target(NONE, names(Some("afklink_bot"), None)), None);
    }

    #[test]
    fn blank_config_values_are_not_overrides() {
        let target = resolve_target(
            names(Some(""), Some("   ")),
            names(Some("afklink_bot"), Some("app")),
        )
        .expect("a link");
        assert_eq!(target.bot_from, LinkSource::Server);
        assert_eq!(target.short_name_from, LinkSource::Server);
    }

    #[test]
    fn a_value_that_is_not_a_telegram_name_is_ignored() {
        // A malformed override falls back to the backend's value…
        let target = resolve_target(
            names(Some("@afklink_bot"), None),
            names(Some("afklink_bot"), Some("app")),
        )
        .expect("a link");
        assert_eq!(target.bot_username, "afklink_bot");
        assert_eq!(target.bot_from, LinkSource::Server);
        // …and a malformed value from the backend is no value.
        for bad in ["evil.example/x", "a b", "bot?x=1", "x#y"] {
            assert_eq!(
                resolve_target(NONE, names(Some(bad), Some("app"))),
                None,
                "{bad}"
            );
            assert_eq!(
                resolve_target(NONE, names(Some("afklink_bot"), Some(bad))),
                None,
                "{bad}"
            );
        }
        assert_eq!(
            resolve_target(NONE, names(Some(&"x".repeat(65)), Some("app"))),
            None
        );
    }

    #[test]
    fn surrounding_whitespace_is_trimmed() {
        let target =
            resolve_target(NONE, names(Some(" afklink_bot\r"), Some("app\n"))).expect("a link");
        assert_eq!(target.bot_username, "afklink_bot");
        assert_eq!(target.short_name, "app");
    }

    #[test]
    fn an_override_equal_to_the_backends_value_is_still_the_config_one() {
        // Telegram names are case-insensitive: the same bot, spelled differently, is no conflict.
        let target = resolve_target(
            names(Some("AfkLink_Bot"), None),
            names(Some("afklink_bot"), Some("app")),
        )
        .expect("a link");
        assert_eq!(target.bot_username, "AfkLink_Bot");
        assert_eq!(target.bot_from, LinkSource::Config);
    }
}
