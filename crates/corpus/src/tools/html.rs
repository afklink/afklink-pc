//! The pages headless Edge renders: screen chrome (a VS Code-like editor, an Edge-like browser, the
//! Windows 11 desktop and taskbar, a File Explorer window, a video site) and the documents that
//! scroll inside them.
//!
//! Geometry is in CSS pixels on an 1800x1200 CSS screen (3600x2400 at 200%). The constants here
//! are shared with the scenario code, which composites the scrolled document into the viewport
//! rectangle the chrome leaves blank.

use std::fmt::Write as _;
use std::path::Path;

/// Screen size in CSS pixels.
pub const SCREEN_W: u32 = 1800;
pub const SCREEN_H: u32 = 1200;
/// Windows 11 taskbar height.
pub const TASKBAR_H: u32 = 48;
/// Height of one rendered document tile, CSS pixels.
pub const TILE_H: u32 = 1200;

/// A rectangle in CSS pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CssRect {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

/// The editor's text area (gutter + code), CSS pixels.
pub const EDITOR_VIEW: CssRect = CssRect {
    x: 48 + 300,
    y: 35 + 35 + 22,
    w: SCREEN_W - 48 - 300 - 14,
    h: SCREEN_H - TASKBAR_H - 22 - (35 + 35 + 22),
};
/// Editor line height and font size.
pub const CODE_LINE_H: u32 = 19;
/// The browser's page viewport, CSS pixels (a 15 px scrollbar sits to its right).
pub const BROWSER_VIEW: CssRect = CssRect {
    x: 0,
    y: 82,
    w: SCREEN_W - 15,
    h: SCREEN_H - TASKBAR_H - 82,
};

/// Escape text for HTML.
#[must_use]
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

fn file_url(p: &Path) -> String {
    format!("file:///{}", p.display().to_string().replace('\\', "/"))
}

const PAGE_HEAD: &str = "<!doctype html><html><head><meta charset=\"utf-8\"><style>\
html,body{margin:0;padding:0;overflow:hidden}\
*{box-sizing:border-box}\
body{font-family:'Segoe UI',sans-serif;-webkit-font-smoothing:auto}\
</style>";

/// The Windows 11 taskbar (dark), as a positioned block at the bottom of an 1800-wide screen.
fn taskbar(clock: &str, date: &str) -> String {
    let icon = |bg: &str, glyph: &str, active: bool| {
        format!(
            "<div style=\"width:40px;height:40px;border-radius:6px;display:flex;align-items:center;\
             justify-content:center;position:relative;{}\">\
             <div style=\"width:24px;height:24px;border-radius:5px;background:{bg};color:#fff;\
             font:600 13px 'Segoe UI';display:flex;align-items:center;justify-content:center\">{glyph}</div>{}</div>",
            if active { "background:#2d2d2d" } else { "" },
            if active {
                "<div style=\"position:absolute;bottom:1px;left:15px;width:10px;height:3px;border-radius:2px;background:#4cc2ff\"></div>"
            } else {
                ""
            }
        )
    };
    let start = "<div style=\"width:40px;height:40px;display:flex;align-items:center;justify-content:center\">\
        <div style=\"display:grid;grid-template-columns:10px 10px;gap:2px\">\
        <div style=\"width:10px;height:10px;background:#4cc2ff\"></div><div style=\"width:10px;height:10px;background:#4cc2ff\"></div>\
        <div style=\"width:10px;height:10px;background:#4cc2ff\"></div><div style=\"width:10px;height:10px;background:#4cc2ff\"></div></div></div>";
    let search =
        "<div style=\"width:210px;height:34px;border-radius:17px;background:#2b2b2b;color:#bdbdbd;\
        font:13px 'Segoe UI';display:flex;align-items:center;padding-left:14px;gap:10px\">\
        <span style=\"font-size:15px\">&#x2315;</span>Поиск</div>";
    format!(
        "<div style=\"position:absolute;left:0;bottom:0;width:{SCREEN_W}px;height:{TASKBAR_H}px;background:#1c1c1c;\
         border-top:1px solid #2e2e2e;\">\
         <div style=\"position:absolute;left:0;right:0;top:4px;display:flex;justify-content:center;gap:4px\">\
         {start}{search}{}{}{}{}{}{}</div>\
         <div style=\"position:absolute;right:12px;top:0;height:48px;display:flex;align-items:center;gap:14px;\
         color:#fff;font:12px 'Segoe UI'\">\
         <span style=\"color:#ccc\">&#x2303;</span><span>&#x1F5A7;</span><span>&#x1F50A;</span><span>РУС</span>\
         <div style=\"text-align:right;line-height:16px\">{clock}<br>{date}</div></div></div>",
        icon("#f0b429", "&#x1F4C1;", false),
        icon("#0c7ec2", "e", true),
        icon("#2b88d8", "&lt;/&gt;", true),
        icon("#2aa3e0", "&#x2708;", false),
        icon("#7a4fd6", "T", false),
        icon("#d13438", "&#x25B6;", false),
    )
}

/// A VS Code-like dark editor filling the screen above the taskbar. The text area
/// ([`EDITOR_VIEW`]) is left empty: the scenario composites the document there.
#[must_use]
pub fn editor_screen(file: &str, crumbs: &[&str], status_pos: &str) -> String {
    let v = EDITOR_VIEW;
    let tree = [
        (0, "▾ AFKLINK"),
        (1, "▸ .github"),
        (1, "▾ agent"),
        (2, "▸ app"),
        (2, "▾ crates"),
        (3, "▸ agent"),
        (3, "▾ capture"),
        (4, "▾ src"),
        (5, "lib.rs"),
        (5, "pace.rs"),
        (5, "wgc.rs"),
        (4, "Cargo.toml"),
        (3, "▾ core"),
        (4, "▸ examples"),
        (4, "▾ src"),
        (5, "agent.rs"),
        (5, "config.rs"),
        (5, "frame_dropper.rs"),
        (5, "lib.rs"),
        (5, "logging.rs"),
        (5, "quality.rs"),
        (5, "scale.rs"),
        (5, "types.rs"),
        (3, "▸ corpus"),
        (3, "▸ encode"),
        (3, "▸ input"),
        (3, "▸ protocol"),
        (3, "▸ transport"),
        (2, "Cargo.lock"),
        (2, "Cargo.toml"),
        (1, "▸ docs"),
        (1, "▸ infra"),
        (1, "▸ miniapp"),
        (1, "▸ packages"),
        (1, "▸ server"),
        (1, ".gitignore"),
        (1, "NOTES.md"),
        (1, "package.json"),
    ];
    let mut side = String::new();
    for (depth, name) in tree {
        let selected = name == file;
        let color = if name.ends_with(".rs") {
            "#dea584"
        } else if name.starts_with('▾') || name.starts_with('▸') {
            "#cccccc"
        } else {
            "#b5b5b5"
        };
        let _ = write!(
            side,
            "<div style=\"height:22px;line-height:22px;padding-left:{}px;color:{color};{}\">{}</div>",
            8 + depth * 12,
            if selected {
                "background:#37373d;outline:1px solid #0078d4;outline-offset:-1px"
            } else {
                ""
            },
            esc(name)
        );
    }
    let crumbs_html = crumbs
        .iter()
        .map(|c| esc(c))
        .collect::<Vec<_>>()
        .join(" <span style=\"color:#6e6e6e\">&#x203A;</span> ");
    let tabs = [file, "agent.rs", "Cargo.toml", "lib.rs"];
    let mut tab_html = String::new();
    for (i, t) in tabs.iter().enumerate() {
        let active = i == 0;
        let _ = write!(
            tab_html,
            "<div style=\"height:35px;padding:0 14px;display:flex;align-items:center;gap:8px;\
             font:13px 'Segoe UI';color:{};background:{};border-right:1px solid #2b2b2b;{}\">\
             <span style=\"color:#dea584;font-weight:600\">R</span>{}<span style=\"color:{};margin-left:6px\">&#x2715;</span></div>",
            if active { "#ffffff" } else { "#9d9d9d" },
            if active { "#1f1f1f" } else { "#181818" },
            if active { "border-top:1px solid #0078d4" } else { "" },
            esc(t),
            if active { "#cccccc" } else { "transparent" },
        );
    }
    let activity: String =
        ["&#x2630;", "&#x2315;", "&#x2387;", "&#x25B7;", "&#x25A6;"]
            .iter()
            .enumerate()
            .map(|(i, g)| {
                format!(
                "<div style=\"height:48px;display:flex;align-items:center;justify-content:center;\
                 font-size:22px;color:{};{}\">{g}</div>",
                if i == 0 { "#d7d7d7" } else { "#868686" },
                if i == 0 { "border-left:2px solid #0078d4" } else { "" }
            )
            })
            .collect();
    format!(
        "{PAGE_HEAD}</head><body style=\"width:{SCREEN_W}px;height:{SCREEN_H}px;background:#1f1f1f;position:relative\">\
<div style=\"position:absolute;left:0;top:0;width:{SCREEN_W}px;height:35px;background:#181818;border-bottom:1px solid #2b2b2b;\
color:#cccccc;font:13px 'Segoe UI';display:flex;align-items:center\">\
<div style=\"width:48px;text-align:center;color:#0078d4;font-size:16px\">&#x25C6;</div>\
<div style=\"display:flex;gap:16px\"><span>File</span><span>Edit</span><span>Selection</span><span>View</span><span>Go</span><span>Run</span><span>Terminal</span><span>Help</span></div>\
<div style=\"position:absolute;left:600px;width:600px;top:5px;height:24px;border:1px solid #3c3c3c;border-radius:6px;background:#1f1f1f;\
color:#9d9d9d;text-align:center;line-height:22px\">&#x2315; afklink</div>\
<div style=\"position:absolute;right:0;top:0;display:flex\"><div style=\"width:46px;text-align:center\">&#x2500;</div>\
<div style=\"width:46px;text-align:center\">&#x25A2;</div><div style=\"width:46px;text-align:center\">&#x2715;</div></div></div>\
<div style=\"position:absolute;left:0;top:35px;width:48px;bottom:{bottom}px;background:#181818;border-right:1px solid #2b2b2b\">{activity}</div>\
<div style=\"position:absolute;left:48px;top:35px;width:300px;bottom:{bottom}px;background:#181818;border-right:1px solid #2b2b2b;\
font:13px 'Segoe UI';color:#cccccc;overflow:hidden\">\
<div style=\"height:35px;line-height:35px;padding-left:20px;font-size:11px;letter-spacing:.5px;color:#cccccc\">EXPLORER</div>{side}</div>\
<div style=\"position:absolute;left:{vx}px;top:35px;right:0;height:35px;background:#181818;display:flex;border-bottom:1px solid #2b2b2b\">{tab_html}</div>\
<div style=\"position:absolute;left:{vx}px;top:70px;right:0;height:22px;background:#1f1f1f;color:#a9a9a9;font:13px 'Segoe UI';\
line-height:22px;padding-left:16px\">{crumbs_html}</div>\
<div style=\"position:absolute;left:{sbx}px;top:{vy}px;width:14px;height:{vh}px;background:#1f1f1f;border-left:1px solid #2b2b2b\"></div>\
<div style=\"position:absolute;left:0;bottom:{TASKBAR_H}px;width:{SCREEN_W}px;height:22px;background:#181818;border-top:1px solid #2b2b2b;\
color:#cccccc;font:12px 'Segoe UI';display:flex;align-items:center;gap:18px\">\
<div style=\"background:#0078d4;color:#fff;height:22px;line-height:22px;padding:0 10px\">&#x2B82;</div>\
<span>&#x2387; master</span><span>&#x2297; 0 &#x26A0; 0</span>\
<div style=\"margin-left:auto;display:flex;gap:22px;padding-right:18px\"><span>{status_pos}</span><span>Spaces: 4</span>\
<span>UTF-8</span><span>LF</span><span>{{ }} Rust</span><span>&#x1F514;</span></div></div>\
{taskbar}</body></html>",
        bottom = TASKBAR_H + 22,
        vx = v.x,
        vy = v.y,
        vh = v.h,
        sbx = v.x + v.w,
        taskbar = taskbar("21:04", "24.09.2026"),
    )
}

const CODE_CSS: &str = "<style>\
.d{background:#1f1f1f;font:14px Consolas,'Courier New',monospace;color:#cccccc}\
.l{height:19px;line-height:19px;white-space:pre;display:flex}\
.n{width:48px;text-align:right;color:#6e7681;flex:none}\
.n.cur{color:#cccccc}\
.c{padding-left:22px;flex:none}\
.k{color:#569cd6}.q{color:#c586c0}.t{color:#4ec9b0}.f{color:#dcdcaa}.s{color:#ce9178}\
.m{color:#6a9955}.u{color:#b5cea8}.a{color:#d7ba7d}.v{color:#9cdcfe}.p{color:#cccccc}\
.hide .n,.hide .c{color:transparent}.hide .c span{color:transparent}\
</style>";

/// One line of the editor document.
pub struct CodeLine {
    pub number: usize,
    pub text: String,
    /// Rendered transparent (a line not typed yet).
    pub hidden: bool,
    /// Gets `id="t{index}"` so a script can measure its characters.
    pub measure: Option<usize>,
}

/// The editor's text area content: gutter + highlighted code, `width` CSS pixels wide, shifted up
/// by `offset` CSS pixels (to render one tile of a long document).
#[must_use]
pub fn code_document(lines: &[CodeLine], width: u32, offset: u32, script: &str) -> String {
    let mut body = String::new();
    for l in lines {
        let _ = write!(
            body,
            "<div class=\"l{}\"><span class=\"n\">{}</span><span class=\"c\"{}>{}</span></div>",
            if l.hidden { " hide" } else { "" },
            l.number,
            l.measure
                .map(|i| format!(" id=\"t{i}\""))
                .unwrap_or_default(),
            highlight_rust(&l.text)
        );
    }
    format!(
        "{PAGE_HEAD}{CODE_CSS}</head><body class=\"d\" style=\"width:{width}px\">\
         <div style=\"position:relative;top:-{offset}px;padding-top:0\">{body}</div>{script}</body></html>"
    )
}

/// Height of a code document in CSS pixels.
#[must_use]
pub fn code_height(lines: usize) -> u32 {
    lines as u32 * CODE_LINE_H
}

const RUST_KEYWORDS: &[&str] = &[
    "as", "const", "crate", "dyn", "enum", "extern", "false", "fn", "impl", "let", "mod", "move",
    "mut", "pub", "ref", "self", "Self", "static", "struct", "super", "trait", "true", "type",
    "unsafe", "use", "where",
];
const RUST_CONTROL: &[&str] = &[
    "break", "continue", "else", "for", "if", "in", "loop", "match", "return", "while",
];

/// A small Rust highlighter with VS Code Dark Modern colours: enough that the code has the colour
/// density of the real editor (keywords, types, strings, comments, calls).
#[must_use]
pub fn highlight_rust(line: &str) -> String {
    let chars: Vec<char> = line.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    let span = |out: &mut String, class: &str, text: &str| {
        let _ = write!(out, "<span class=\"{class}\">{}</span>", esc(text));
    };
    while i < chars.len() {
        let c = chars[i];
        let rest: String = chars[i..].iter().collect();
        if rest.starts_with("//") {
            span(&mut out, "m", &rest);
            break;
        }
        if c == '#' && chars.get(i + 1).is_some_and(|n| *n == '[' || *n == '!') {
            span(&mut out, "a", &rest);
            break;
        }
        if c == '"' {
            let mut j = i + 1;
            while j < chars.len() && chars[j] != '"' {
                if chars[j] == '\\' {
                    j += 1;
                }
                j += 1;
            }
            let end = (j + 1).min(chars.len());
            span(&mut out, "s", &chars[i..end].iter().collect::<String>());
            i = end;
            continue;
        }
        if c == '\'' && chars.get(i + 2).is_some_and(|n| *n == '\'') {
            span(&mut out, "s", &chars[i..i + 3].iter().collect::<String>());
            i += 3;
            continue;
        }
        if c.is_ascii_digit() {
            let mut j = i;
            while j < chars.len()
                && (chars[j].is_ascii_alphanumeric() || chars[j] == '_' || chars[j] == '.')
            {
                j += 1;
            }
            span(&mut out, "u", &chars[i..j].iter().collect::<String>());
            i = j;
            continue;
        }
        if c.is_alphabetic() || c == '_' {
            let mut j = i;
            while j < chars.len() && (chars[j].is_alphanumeric() || chars[j] == '_') {
                j += 1;
            }
            let word: String = chars[i..j].iter().collect();
            let next = chars.get(j).copied();
            let class = if RUST_CONTROL.contains(&word.as_str()) {
                "q"
            } else if RUST_KEYWORDS.contains(&word.as_str()) || next == Some('!') {
                "k"
            } else if next == Some('(') {
                "f"
            } else if word.chars().next().is_some_and(char::is_uppercase) {
                "t"
            } else {
                "v"
            };
            span(&mut out, class, &word);
            i = j;
            continue;
        }
        let mut j = i;
        while j < chars.len()
            && !(chars[j].is_alphanumeric()
                || chars[j] == '_'
                || chars[j] == '"'
                || chars[j] == '\''
                || chars[j] == '#'
                || (chars[j] == '/' && chars.get(j + 1) == Some(&'/')))
        {
            j += 1;
        }
        if j == i {
            j = i + 1;
        }
        span(&mut out, "p", &chars[i..j].iter().collect::<String>());
        i = j;
    }
    out
}

/// An Edge-like browser (light theme) filling the screen above the taskbar, with the page
/// viewport ([`BROWSER_VIEW`]) left blank and its scrollbar track drawn.
#[must_use]
pub fn browser_screen(tab_title: &str, url: &str) -> String {
    let v = BROWSER_VIEW;
    let tab = |title: &str, active: bool| {
        format!(
            "<div style=\"height:34px;margin-top:6px;width:240px;padding:0 12px;display:flex;align-items:center;gap:8px;\
             border-radius:8px 8px 0 0;background:{};color:#1b1b1b;font:12px 'Segoe UI';overflow:hidden;white-space:nowrap\">\
             <span style=\"width:16px;height:16px;border-radius:4px;background:{};flex:none\"></span>{}\
             <span style=\"margin-left:auto;color:#666\">&#x2715;</span></div>",
            if active { "#ffffff" } else { "transparent" },
            if active { "#0f6cbd" } else { "#8a8a8a" },
            esc(title)
        )
    };
    format!(
        "{PAGE_HEAD}</head><body style=\"width:{SCREEN_W}px;height:{SCREEN_H}px;background:#ffffff;position:relative\">\
<div style=\"position:absolute;left:0;top:0;width:{SCREEN_W}px;height:40px;background:#e9e9e9;display:flex;padding-left:8px;gap:2px\">\
<div style=\"width:40px;height:40px;display:flex;align-items:center;justify-content:center;color:#444\">&#x25A3;</div>\
{}{}{}<div style=\"width:30px;height:40px;line-height:40px;color:#444;text-align:center\">+</div>\
<div style=\"position:absolute;right:0;top:0;display:flex;color:#222;font:13px 'Segoe UI'\"><div style=\"width:46px;height:32px;line-height:32px;text-align:center\">&#x2500;</div>\
<div style=\"width:46px;height:32px;line-height:32px;text-align:center\">&#x25A2;</div><div style=\"width:46px;height:32px;line-height:32px;text-align:center\">&#x2715;</div></div></div>\
<div style=\"position:absolute;left:0;top:40px;width:{SCREEN_W}px;height:42px;background:#ffffff;border-bottom:1px solid #e0e0e0;\
display:flex;align-items:center;gap:6px;padding-left:10px;color:#333;font:15px 'Segoe UI'\">\
<span style=\"width:32px;text-align:center\">&#x2190;</span><span style=\"width:32px;text-align:center;color:#aaa\">&#x2192;</span>\
<span style=\"width:32px;text-align:center\">&#x21BB;</span>\
<div style=\"flex:1;margin:0 10px;height:32px;border-radius:16px;background:#f1f1f1;display:flex;align-items:center;padding-left:16px;\
gap:10px;font:14px 'Segoe UI';color:#1b1b1b\"><span style=\"color:#555\">&#x1F512;</span>{}</div>\
<span style=\"width:32px;text-align:center\">&#x2606;</span><span style=\"width:32px;text-align:center\">&#x2B73;</span>\
<span style=\"width:32px;text-align:center\">&#x22EF;</span><div style=\"width:28px;height:28px;border-radius:14px;background:#6b69d6;margin:0 12px\"></div></div>\
<div style=\"position:absolute;left:{sx}px;top:{vy}px;width:15px;height:{vh}px;background:#f5f5f5;border-left:1px solid #e8e8e8\"></div>\
{taskbar}</body></html>",
        tab(tab_title, true),
        tab("Новая вкладка", false),
        tab("GitHub", false),
        esc(url),
        sx = v.x + v.w,
        vy = v.y,
        vh = v.h,
        taskbar = taskbar("21:04", "24.09.2026"),
    )
}

/// Inline markdown: `code`, **bold**, [links](...).
fn md_inline(s: &str) -> String {
    let s = esc(s);
    let mut out = String::new();
    let mut code = false;
    let mut bold = false;
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '`' => {
                out.push_str(if code { "</code>" } else { "<code>" });
                code = !code;
            }
            '*' if !code && it.peek() == Some(&'*') => {
                it.next();
                out.push_str(if bold { "</b>" } else { "<b>" });
                bold = !bold;
            }
            '[' if !code => {
                // [text](url) -> text as a link
                let text: String = it.by_ref().take_while(|ch| *ch != ']').collect();
                if it.peek() == Some(&'(') {
                    it.next();
                    let _url: String = it.by_ref().take_while(|ch| *ch != ')').collect();
                    let _ = write!(out, "<a>{text}</a>");
                } else {
                    let _ = write!(out, "[{text}]");
                }
            }
            _ => out.push(c),
        }
    }
    if code {
        out.push_str("</code>");
    }
    if bold {
        out.push_str("</b>");
    }
    out
}

/// Markdown to HTML, enough for the repository's docs: headings, paragraphs, lists, block quotes,
/// fenced code, tables, rules. `images` are inserted after the 2nd, 4th, ... level-2 heading.
#[must_use]
pub fn markdown(md: &str, images: &[&Path]) -> String {
    let mut out = String::new();
    let mut para: Vec<String> = Vec::new();
    let mut list: Option<&str> = None;
    let mut quote: Vec<String> = Vec::new();
    let mut table: Vec<Vec<String>> = Vec::new();
    let mut in_code = false;
    let mut h2 = 0usize;
    let mut next_image = 0usize;

    fn flush_para(out: &mut String, para: &mut Vec<String>) {
        if !para.is_empty() {
            let _ = write!(out, "<p>{}</p>", md_inline(&para.join(" ")));
            para.clear();
        }
    }
    fn flush_quote(out: &mut String, quote: &mut Vec<String>) {
        if !quote.is_empty() {
            let _ = write!(
                out,
                "<blockquote>{}</blockquote>",
                md_inline(&quote.join(" "))
            );
            quote.clear();
        }
    }
    fn flush_table(out: &mut String, table: &mut Vec<Vec<String>>) {
        if table.is_empty() {
            return;
        }
        out.push_str("<table>");
        for (i, row) in table.iter().enumerate() {
            out.push_str("<tr>");
            for cell in row {
                let tag = if i == 0 { "th" } else { "td" };
                let _ = write!(out, "<{tag}>{}</{tag}>", md_inline(cell));
            }
            out.push_str("</tr>");
        }
        out.push_str("</table>");
        table.clear();
    }

    for raw in md.lines() {
        let line = raw.trim_end();
        if line.trim_start().starts_with("```") {
            if in_code {
                out.push_str("</pre>");
            } else {
                flush_para(&mut out, &mut para);
                flush_quote(&mut out, &mut quote);
                flush_table(&mut out, &mut table);
                if let Some(tag) = list.take() {
                    let _ = write!(out, "</{tag}>");
                }
                out.push_str("<pre>");
            }
            in_code = !in_code;
            continue;
        }
        if in_code {
            let _ = writeln!(out, "{}", esc(line));
            continue;
        }
        let trimmed = line.trim_start();
        let is_item = trimmed.starts_with("- ")
            || trimmed.starts_with("* ")
            || trimmed
                .split_once(". ")
                .is_some_and(|(n, _)| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()));
        if !is_item {
            if let Some(tag) = list {
                if !(line.starts_with("  ") && !trimmed.is_empty()) {
                    let _ = write!(out, "</{tag}>");
                    list = None;
                }
            }
        }
        if !trimmed.starts_with('>') {
            flush_quote(&mut out, &mut quote);
        }
        if !trimmed.starts_with('|') {
            flush_table(&mut out, &mut table);
        }
        if trimmed.is_empty() {
            flush_para(&mut out, &mut para);
            continue;
        }
        if let Some(level) =
            (1..=6).find(|l| trimmed.starts_with(&"#".repeat(*l)) && trimmed[*l..].starts_with(' '))
        {
            flush_para(&mut out, &mut para);
            let text = &trimmed[level + 1..];
            if level == 2 {
                h2 += 1;
                if h2 >= 2 && h2.is_multiple_of(2) && next_image < images.len() {
                    let _ = write!(
                        out,
                        "<figure><img src=\"{}\"><figcaption>Рис. {}</figcaption></figure>",
                        file_url(images[next_image]),
                        next_image + 1
                    );
                    next_image += 1;
                }
            }
            let _ = write!(out, "<h{level}>{}</h{level}>", md_inline(text));
            continue;
        }
        if trimmed == "---" || trimmed == "***" {
            flush_para(&mut out, &mut para);
            out.push_str("<hr>");
            continue;
        }
        if let Some(q) = trimmed.strip_prefix('>') {
            flush_para(&mut out, &mut para);
            quote.push(q.trim().to_string());
            continue;
        }
        if trimmed.starts_with('|') {
            flush_para(&mut out, &mut para);
            let cells: Vec<String> = trimmed
                .trim_matches('|')
                .split('|')
                .map(|c| c.trim().to_string())
                .collect();
            if cells
                .iter()
                .all(|c| c.chars().all(|ch| ch == '-' || ch == ':'))
            {
                continue;
            }
            table.push(cells);
            continue;
        }
        if is_item {
            flush_para(&mut out, &mut para);
            let ordered = !(trimmed.starts_with("- ") || trimmed.starts_with("* "));
            let tag = if ordered { "ol" } else { "ul" };
            if list != Some(tag) {
                if let Some(t) = list {
                    let _ = write!(out, "</{t}>");
                }
                let _ = write!(out, "<{tag}>");
                list = Some(tag);
            }
            let text = if ordered {
                trimmed.split_once(". ").map_or(trimmed, |(_, t)| t)
            } else {
                &trimmed[2..]
            };
            let _ = write!(out, "<li>{}</li>", md_inline(text));
            continue;
        }
        para.push(trimmed.to_string());
    }
    flush_para(&mut out, &mut para);
    flush_quote(&mut out, &mut quote);
    flush_table(&mut out, &mut table);
    if let Some(tag) = list {
        let _ = write!(out, "</{tag}>");
    }
    if in_code {
        out.push_str("</pre>");
    }
    out
}

const ARTICLE_CSS: &str = "<style>\
body{background:#ffffff;color:#1f2328;font:16px/1.65 'Segoe UI',sans-serif}\
.site{height:64px;border-bottom:1px solid #d8dee4;display:flex;align-items:center;gap:28px;padding:0 48px;font-size:15px;color:#59636e}\
.site b{color:#1f2328;font-size:20px;margin-right:24px}\
.a{max-width:880px;margin:0 auto;padding:28px 40px 120px}\
h1{font-size:32px;line-height:1.25;margin:24px 0 16px}\
h2{font-size:24px;line-height:1.3;margin:36px 0 14px;padding-bottom:6px;border-bottom:1px solid #d8dee4}\
h3{font-size:19px;margin:28px 0 10px}\
p{margin:0 0 14px}ul,ol{margin:0 0 14px;padding-left:28px}li{margin:3px 0}\
code{font:14px Consolas,monospace;background:#eff1f3;padding:2px 5px;border-radius:4px}\
pre{font:14px/1.5 Consolas,monospace;background:#f6f8fa;padding:14px 16px;border-radius:6px;white-space:pre-wrap}\
blockquote{margin:0 0 14px;padding:4px 16px;border-left:4px solid #d0d7de;color:#59636e}\
table{border-collapse:collapse;margin:0 0 16px;font-size:15px}th,td{border:1px solid #d0d7de;padding:6px 12px;vertical-align:top}\
th{background:#f6f8fa}hr{border:0;border-top:1px solid #d8dee4;margin:24px 0}a{color:#0969da;text-decoration:underline}\
figure{margin:18px 0}figure img{width:100%;height:420px;object-fit:cover;border-radius:8px;display:block}\
figcaption{font-size:13px;color:#59636e;margin-top:6px}\
</style>";

/// A long article page: `md` rendered in a documentation-site layout, shifted up by `offset` CSS
/// pixels. `script` is appended at the end of the body (for measuring the page height).
#[must_use]
pub fn article_document(
    md: &str,
    images: &[&Path],
    width: u32,
    offset: u32,
    script: &str,
) -> String {
    format!(
        "{PAGE_HEAD}{ARTICLE_CSS}</head><body style=\"width:{width}px;overflow:hidden\">\
         <div style=\"position:relative;top:-{offset}px\"><div class=\"site\"><b>afklink</b><span>Документация</span>\
         <span>Протокол</span><span>Наблюдаемость</span><span>Развёртывание</span><span style=\"margin-left:auto\">&#x2315; Поиск</span></div>\
         <div class=\"a\">{}</div></div>{script}</body></html>",
        markdown(md, images)
    )
}

/// Script that writes the page height into `<pre id="measure">`. It runs inline at the end of the
/// body, not on `load`: `--dump-dom` serialises before a load handler's changes land, and nothing
/// the layout depends on loads late (system fonts; images have fixed heights).
pub const MEASURE_HEIGHT_JS: &str = "<script>(()=>{const o=document.createElement('pre');\
o.id='measure';o.style.display='none';o.textContent=JSON.stringify({h:document.body.firstElementChild.scrollHeight});\
document.body.appendChild(o);})();</script>";

/// Script that measures, for every element `#t0, #t1, ...`, the right edge of each character and
/// the line box, into `<pre id="measure">` as `[{top,bottom,left,rights:[...]}, ...]`. Inline, as
/// [`MEASURE_HEIGHT_JS`].
pub const MEASURE_CHARS_JS: &str = "<script>(()=>{const res=[];\
for(let i=0;;i++){const el=document.getElementById('t'+i);if(!el)break;const box=el.getBoundingClientRect();\
const rights=[];const w=document.createTreeWalker(el,NodeFilter.SHOW_TEXT);let n;\
while(n=w.nextNode()){for(let j=0;j<n.length;j++){const r=document.createRange();r.setStart(n,j);r.setEnd(n,j+1);\
rights.push(r.getBoundingClientRect().right);}}\
const num=el.parentElement.querySelector('.n').getBoundingClientRect();\
res.push({top:box.top,bottom:box.bottom,left:box.left,num_left:num.left,num_right:num.right,rights});}\
const o=document.createElement('pre');o.id='measure';o.style.display='none';o.textContent=JSON.stringify(res);\
document.body.appendChild(o);})();</script>";

/// The Windows 11 desktop: wallpaper, a column of icons, the taskbar.
#[must_use]
pub fn desktop_screen(wallpaper: &Path) -> String {
    let icons = [
        ("#5aa0e6", "Корзина"),
        ("#f0b429", "Этот компьютер"),
        ("#0c7ec2", "Microsoft Edge"),
        ("#2b88d8", "Visual Studio Code"),
        ("#2aa3e0", "Telegram"),
        ("#e8a33d", "Проекты"),
        ("#7a4fd6", "Документы"),
    ];
    let mut col = String::new();
    for (i, (color, label)) in icons.iter().enumerate() {
        let _ = write!(
            col,
            "<div style=\"position:absolute;left:10px;top:{}px;width:84px;text-align:center;color:#fff;font:12px 'Segoe UI';\
             text-shadow:0 1px 2px rgba(0,0,0,.8)\"><div style=\"width:48px;height:48px;margin:0 auto 4px;border-radius:8px;\
             background:{color};box-shadow:0 1px 3px rgba(0,0,0,.5)\"></div>{}</div>",
            12 + i * 96,
            esc(label)
        );
    }
    format!(
        "{PAGE_HEAD}</head><body style=\"width:{SCREEN_W}px;height:{SCREEN_H}px;position:relative;\
         background:url('{}') center/cover no-repeat #1b3d5f\">{col}{}</body></html>",
        file_url(wallpaper),
        taskbar("21:04", "24.09.2026")
    )
}

/// A File Explorer window (Windows 11 light), `w x h` CSS pixels, opaque.
#[must_use]
pub fn explorer_window(w: u32, h: u32) -> String {
    let rows = [
        ("agent", "24.09.2026 21:02", "Папка с файлами", ""),
        ("docs", "24.09.2026 18:40", "Папка с файлами", ""),
        ("infra", "19.09.2026 11:12", "Папка с файлами", ""),
        ("miniapp", "24.09.2026 20:55", "Папка с файлами", ""),
        ("packages", "24.09.2026 20:31", "Папка с файлами", ""),
        ("server", "23.09.2026 16:08", "Папка с файлами", ""),
        ("research_out", "19.09.2026 09:47", "Папка с файлами", ""),
        (
            ".gitignore",
            "24.09.2026 21:03",
            "Исходный файл Git",
            "1 КБ",
        ),
        ("biome.json", "12.09.2026 14:22", "Файл JSON", "2 КБ"),
        ("bun.lock", "22.09.2026 10:17", "Файл LOCK", "184 КБ"),
        ("NOTES.md", "24.09.2026 19:55", "Файл MD", "12 КБ"),
        ("package.json", "22.09.2026 10:17", "Файл JSON", "1 КБ"),
        ("README.md", "14.09.2026 17:30", "Файл MD", "6 КБ"),
        (
            "tsconfig.base.json",
            "12.09.2026 14:22",
            "Файл JSON",
            "1 КБ",
        ),
        (
            "live-session-0924.out.log",
            "24.09.2026 22:07",
            "Текстовый документ",
            "359 КБ",
        ),
        ("rate_surface.csv", "20.09.2026 13:41", "Файл CSV", "48 КБ"),
        (
            "screenshot-1.png",
            "21.09.2026 08:15",
            "Файл PNG",
            "2 410 КБ",
        ),
        (
            "screenshot-2.png",
            "21.09.2026 08:16",
            "Файл PNG",
            "2 388 КБ",
        ),
        (
            "notes.txt",
            "23.09.2026 22:40",
            "Текстовый документ",
            "3 КБ",
        ),
        (
            "plan.xlsx",
            "18.09.2026 12:05",
            "Лист Microsoft Excel",
            "27 КБ",
        ),
        (
            "session-analysis.docx",
            "24.09.2026 11:20",
            "Документ Microsoft Word",
            "88 КБ",
        ),
    ];
    let mut list = String::new();
    for (i, (name, date, kind, size)) in rows.iter().enumerate() {
        let folder = size.is_empty();
        let _ = write!(
            list,
            "<div style=\"display:flex;height:30px;align-items:center;font:13px 'Segoe UI';color:#1b1b1b;{}\">\
             <div style=\"width:360px;display:flex;align-items:center;gap:10px;padding-left:12px\">\
             <span style=\"width:18px;height:14px;border-radius:2px;background:{}\"></span>{}</div>\
             <div style=\"width:190px;color:#5d5d5d\">{}</div><div style=\"width:200px;color:#5d5d5d\">{}</div>\
             <div style=\"width:100px;color:#5d5d5d;text-align:right\">{}</div></div>",
            if i == 3 { "background:#e5f1fb" } else { "" },
            if folder { "#f0c24b" } else { "#c8d7e6" },
            esc(name),
            esc(date),
            esc(kind),
            esc(size)
        );
    }
    let nav = [
        "Главная",
        "Галерея",
        "OneDrive",
        "Рабочий стол",
        "Загрузки",
        "Документы",
        "Изображения",
        "Музыка",
        "Видео",
        "Этот компьютер",
        "Локальный диск (C:)",
        "Сеть",
    ];
    let mut nav_html = String::new();
    for (i, n) in nav.iter().enumerate() {
        let _ = write!(
            nav_html,
            "<div style=\"height:32px;line-height:32px;padding-left:{}px;font:13px 'Segoe UI';color:#1b1b1b;{}\">{}</div>",
            if i < 3 { 16 } else { 28 },
            if i == 5 { "background:#e5e5e5;border-radius:4px" } else { "" },
            esc(n)
        );
    }
    format!(
        "{PAGE_HEAD}</head><body style=\"width:{w}px;height:{h}px;background:#f3f3f3;position:relative;border:1px solid #8a8a8a;overflow:hidden\">\
<div style=\"height:40px;background:#e8e8e8;display:flex;align-items:flex-end;padding-left:10px\">\
<div style=\"height:34px;width:230px;background:#f9f9f9;border-radius:8px 8px 0 0;display:flex;align-items:center;gap:8px;padding-left:12px;\
font:12px 'Segoe UI'\"><span style=\"width:16px;height:12px;background:#f0c24b;border-radius:2px\"></span>afklink<span style=\"margin-left:auto;margin-right:10px\">&#x2715;</span></div>\
<span style=\"height:34px;line-height:34px;padding:0 12px\">+</span></div>\
<div style=\"position:absolute;right:0;top:0;display:flex;font:13px 'Segoe UI'\"><div style=\"width:46px;height:32px;line-height:32px;text-align:center\">&#x2500;</div>\
<div style=\"width:46px;height:32px;line-height:32px;text-align:center\">&#x25A2;</div><div style=\"width:46px;height:32px;line-height:32px;text-align:center\">&#x2715;</div></div>\
<div style=\"height:48px;background:#f9f9f9;display:flex;align-items:center;gap:8px;padding:0 10px;border-bottom:1px solid #e5e5e5;font:14px 'Segoe UI'\">\
<span>&#x2190;</span><span style=\"color:#aaa\">&#x2192;</span><span>&#x2191;</span><span>&#x21BB;</span>\
<div style=\"flex:1;height:32px;border:1px solid #e0e0e0;border-radius:4px;background:#fff;line-height:30px;padding-left:10px;font:13px 'Segoe UI'\">\
&#x1F5B5; &#x203A; Этот компьютер &#x203A; Локальный диск (C:) &#x203A; Пользователи &#x203A; user &#x203A; Документы &#x203A; afklink</div>\
<div style=\"width:260px;height:32px;border:1px solid #e0e0e0;border-radius:4px;background:#fff;line-height:30px;padding-left:10px;color:#777;font:13px 'Segoe UI'\">Поиск: afklink</div></div>\
<div style=\"height:44px;background:#f9f9f9;display:flex;align-items:center;gap:22px;padding:0 16px;border-bottom:1px solid #e5e5e5;font:13px 'Segoe UI';color:#1b1b1b\">\
<span>&#x2295; Создать &#x2304;</span><span>&#x2702;</span><span>&#x2398;</span><span>&#x1F4CB;</span><span>&#x270E;</span><span>&#x1F5D1;</span>\
<span>&#x21C5; Сортировать &#x2304;</span><span>&#x2630; Просмотреть &#x2304;</span><span>&#x22EF;</span></div>\
<div style=\"position:absolute;left:0;top:133px;width:240px;bottom:28px;background:#f3f3f3;border-right:1px solid #e5e5e5;padding-top:8px\">{nav_html}</div>\
<div style=\"position:absolute;left:241px;top:133px;right:0;bottom:28px;background:#ffffff\">\
<div style=\"display:flex;height:30px;align-items:center;font:12px 'Segoe UI';color:#5d5d5d;border-bottom:1px solid #eee\">\
<div style=\"width:360px;padding-left:40px\">Имя</div><div style=\"width:190px\">Дата изменения</div><div style=\"width:200px\">Тип</div>\
<div style=\"width:100px;text-align:right\">Размер</div></div>{list}</div>\
<div style=\"position:absolute;left:0;bottom:0;right:0;height:28px;background:#f3f3f3;font:12px 'Segoe UI';color:#1b1b1b;line-height:28px;padding-left:14px\">\
Элементов: 21 &nbsp;&nbsp; Выбран 1 элемент</div></body></html>"
    )
}

/// The player geometry of [`video_page`], CSS pixels.
pub const VIDEO_PLAYER: CssRect = CssRect {
    x: 24,
    y: 82 + 72,
    w: 1280,
    h: 720,
};

/// A video site page in the browser: header, the player rectangle ([`VIDEO_PLAYER`], left black),
/// title and description below, a column of recommendations on the right. `thumbs` are images for
/// the recommendation thumbnails.
#[must_use]
pub fn video_page(thumbs: &[&Path]) -> String {
    let p = VIDEO_PLAYER;
    let mut recs = String::new();
    let titles = [
        "Прохождение без комментариев — часть 12",
        "Лучшие моменты недели",
        "Как настроить удалённый рабочий стол за 5 минут",
        "Разбор сюжета: всё, что вы пропустили",
        "Саундтрек — полная версия",
        "10 советов для новичков",
        "Стрим: финальный босс",
        "Обзор обновления 1.4",
    ];
    for (i, t) in titles.iter().enumerate() {
        let img = thumbs
            .get(i % thumbs.len().max(1))
            .map(|pth| format!("<img src=\"{}\" style=\"width:168px;height:94px;object-fit:cover;border-radius:8px;flex:none\">", file_url(pth)))
            .unwrap_or_else(|| "<div style=\"width:168px;height:94px;border-radius:8px;background:#ccc;flex:none\"></div>".into());
        let _ = write!(
            recs,
            "<div style=\"display:flex;gap:10px;margin-bottom:12px\">{img}<div style=\"font:14px/1.35 'Segoe UI';color:#0f0f0f\">\
             <div style=\"font-weight:600\">{}</div><div style=\"color:#606060;font-size:12px;margin-top:4px\">Канал {}<br>{} тыс. просмотров · {} дн. назад</div></div></div>",
            esc(t),
            i + 1,
            12 + i * 37,
            1 + i * 3
        );
    }
    let browser = browser_screen(
        "Кат-сцена целиком — смотреть онлайн",
        "video.local/watch?v=cutscene",
    );
    // Inject the page content into the browser's viewport.
    let content = format!(
        "<div style=\"position:absolute;left:0;top:82px;width:{vw}px;height:{vh}px;background:#fff\">\
<div style=\"height:56px;display:flex;align-items:center;gap:18px;padding:0 24px;font:15px 'Segoe UI'\">\
<span style=\"font-size:20px\">&#x2630;</span><span style=\"color:#e00;font-size:22px\">&#x25B6;</span><b style=\"font-size:18px;margin-left:-10px\">Видео</b>\
<div style=\"margin-left:220px;width:560px;height:40px;border:1px solid #ccc;border-radius:20px;line-height:38px;padding-left:18px;color:#888\">Введите запрос</div>\
<div style=\"margin-left:auto;width:32px;height:32px;border-radius:16px;background:#6b69d6\"></div></div></div>\
<div style=\"position:absolute;left:{px}px;top:{py}px;width:{pw}px;height:{ph}px;background:#000;border-radius:12px\"></div>\
<div style=\"position:absolute;left:{px}px;top:{ty}px;width:{pw}px;font:20px/1.3 'Segoe UI';color:#0f0f0f\">\
<div style=\"font-weight:600\">Кат-сцена целиком: все диалоги и концовка (без комментариев)</div>\
<div style=\"display:flex;align-items:center;gap:12px;margin-top:12px;font-size:14px\"><div style=\"width:40px;height:40px;border-radius:20px;background:#b36b00\"></div>\
<div><b>Игровой архив</b><br><span style=\"color:#606060;font-size:12px\">248 тыс. подписчиков</span></div>\
<div style=\"margin-left:16px;background:#0f0f0f;color:#fff;border-radius:18px;padding:8px 16px\">Подписаться</div>\
<div style=\"margin-left:auto;background:#f2f2f2;border-radius:18px;padding:8px 16px\">&#x1F44D; 12 тыс. | &#x1F44E;</div>\
<div style=\"background:#f2f2f2;border-radius:18px;padding:8px 16px\">&#x27A6; Поделиться</div></div>\
<div style=\"margin-top:12px;background:#f2f2f2;border-radius:12px;padding:12px;font-size:14px;line-height:1.5\"><b>184 тыс. просмотров  3 дня назад</b><br>\
Полная кат-сцена в 4K без интерфейса. Записано на максимальных настройках графики. Таймкоды в комментариях.</div></div>\
<div style=\"position:absolute;left:{rx}px;top:{py}px;width:{rw}px\">{recs}</div>",
        vw = BROWSER_VIEW.w,
        vh = BROWSER_VIEW.h,
        px = p.x,
        py = p.y,
        pw = p.w,
        ph = p.h,
        ty = p.y + p.h + 12,
        rx = p.x + p.w + 24,
        rw = BROWSER_VIEW.w - (p.x + p.w + 24) - 16,
    );
    browser.replace("</body></html>", &format!("{content}</body></html>"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn highlighter_keeps_every_character_and_escapes() {
        let line = "    pub fn admit(now: Instant) -> (A, B) { let s = \"<x>\"; // done";
        let html = highlight_rust(line);
        assert!(html.contains("<span class=\"k\">pub</span>"));
        assert!(html.contains("<span class=\"f\">admit</span>"));
        assert!(html.contains("<span class=\"t\">Instant</span>"));
        assert!(html.contains("&lt;x&gt;"));
        assert!(html.contains("<span class=\"m\">// done</span>"));
        // Strip tags and unescape: the text must be exactly the line.
        let mut text = String::new();
        let mut in_tag = false;
        for c in html.chars() {
            match c {
                '<' => in_tag = true,
                '>' => in_tag = false,
                _ if !in_tag => text.push(c),
                _ => {}
            }
        }
        let text = text
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&amp;", "&");
        assert_eq!(text, line);
    }

    #[test]
    fn markdown_covers_the_docs_constructs() {
        let md = "# Title\n\nPara with `code` and **bold**.\n\n- a\n- b\n\n| x | y |\n|---|---|\n| 1 | 2 |\n\n> quote\n\n```\nfn x() {}\n```\n";
        let html = markdown(md, &[]);
        for needle in [
            "<h1>Title</h1>",
            "<code>code</code>",
            "<b>bold</b>",
            "<ul><li>a</li><li>b</li></ul>",
            "<th>x</th>",
            "<td>2</td>",
            "<blockquote>quote</blockquote>",
            "<pre>fn x() {}\n</pre>",
        ] {
            assert!(html.contains(needle), "missing {needle} in {html}");
        }
    }
}
