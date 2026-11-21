use std::{
    env,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::PathBuf,
};

use anyhow::{Context, Result, ensure};
use crossterm::{
    cursor::{Hide, MoveTo, Show},
    event::{
        self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEventKind,
        KeyModifiers,
    },
    execute, queue,
    style::{Color, Print, ResetColor, SetForegroundColor},
    terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::{Report, analyze, encoded_report, read_capture};

// AsphDex terminal portrait. See NOTICE for attribution and license.
const EMBLEM: &[&str] = &[
    "    ⣤⡶⠋⠉⠉⠁⣲⣤    ",
    "  ⢠⣾⡯⠠     ⠈⣿⡄  ",
    " ⢀⣟⣹⡅       ⣿⣿⡀ ",
    " ⣸⠏⢭⣄⣀⡀   ⣀⣠⣭⠝⣇ ",
    "⠉⢻⡄⣧⣀⢀⣈⠆⠸⣉⡀⢀⡼⢧⡟⠉",
    " ⠘⡵⠴⠆⠉    ⠉⠁⠖⢬⠃ ",
    "  ⠙⣧⠆       ⣶⠋  ",
    "  ⠘⠞⣷⡀     ⢰⠳⠃  ",
    "    ⠙⣷    ⡶⠋    ",
    "     ⠈⠹⢄⡤⠋⠁     ",
];
const MAX_INPUT_CHARS: usize = 4096;

struct Screen;

impl Screen {
    fn enter() -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        let guard = Self;
        execute!(io::stdout(), EnterAlternateScreen, EnableBracketedPaste)?;
        Ok(guard)
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        let _ = execute!(
            io::stdout(),
            ResetColor,
            Show,
            DisableBracketedPaste,
            LeaveAlternateScreen
        );
        let _ = terminal::disable_raw_mode();
    }
}

#[derive(Default)]
struct Workspace {
    english: bool,
    capture: Option<PathBuf>,
    report: Option<Report>,
    body: Option<Vec<String>>,
    status: Option<String>,
    input: Vec<char>,
    cursor: usize,
    scroll: usize,
}

impl Workspace {
    fn text<'a>(&self, tr: &'a str, en: &'a str) -> &'a str {
        if self.english { en } else { tr }
    }

    fn insert(&mut self, value: impl IntoIterator<Item = char>) {
        let remaining = MAX_INPUT_CHARS - self.input.len();
        let chars: Vec<_> = value
            .into_iter()
            .filter(|c| !c.is_control())
            .take(remaining)
            .collect();
        let count = chars.len();
        self.input.splice(self.cursor..self.cursor, chars);
        self.cursor += count;
    }

    fn submit(&mut self) -> Result<bool> {
        let raw: String = self.input.drain(..).collect();
        self.cursor = 0;
        self.scroll = 0;
        let line = raw.trim().trim_start_matches('/');
        let (command, arg) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
        let arg = arg.trim();
        self.status = None;
        match command {
            "" => {}
            "quit" | "exit" => return Ok(false),
            "clear" => self.body = None,
            "lang" => match arg {
                "tr" | "en" => {
                    self.english = arg == "en";
                    self.body = None;
                }
                _ => anyhow::bail!("lang tr|en"),
            },
            "help" => {
                self.body = Some(
                    [
                        self.text("  ◆ Çalışma alanı komutları", "  ◆ Workspace commands"),
                        "",
                        self.text(
                            "    open <dosya>     Telemetri JSON dosyasını seç",
                            "    open <file>     Select a telemetry JSON file",
                        ),
                        self.text(
                            "    analyze          Olayları işle ve özeti göster",
                            "    analyze         Process events and show a summary",
                        ),
                        self.text(
                            "    export <dosya>   Raporu yeni bir JSON dosyasına yaz",
                            "    export <file>   Write the report to a new JSON file",
                        ),
                        self.text(
                            "    lang tr|en       Arayüz dilini değiştir",
                            "    lang tr|en      Change the interface language",
                        ),
                        self.text(
                            "    clear            Karşılama ekranına dön",
                            "    clear           Return to the welcome screen",
                        ),
                        self.text(
                            "    quit             Çıkış",
                            "    quit            Close the workspace",
                        ),
                        "",
                        self.text(
                            "    PgUp / PgDn · Sonuçlarda gezin",
                            "    PgUp / PgDn · Scroll results",
                        ),
                    ]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                );
            }
            "open" => {
                let path = path_argument(arg)?;
                ensure!(fs::metadata(&path)?.is_file(), "expected a regular file");
                self.capture = Some(path);
                self.report = None;
                self.body = None;
                self.status = Some(
                    self.text("kayıt seçildi · analyze", "capture selected · analyze")
                        .into(),
                );
            }
            "analyze" => {
                let path = self.capture.as_ref().context("open <file>")?;
                self.report = None;
                self.body = None;
                let report = analyze(read_capture(path)?)?;
                let mut lines = vec![
                    self.text("  ◆ Davranış raporu", "  ◆ Behavior report")
                        .into(),
                    String::new(),
                    format!("    {}: {}", self.text("Vaka", "Case"), report.case_id),
                    format!("    SHA-256: {}", report.sample_sha256),
                    format!("    {}: {}", self.text("Kaynak", "Source"), report.source),
                    format!(
                        "    {}: {}",
                        self.text("Olay", "Events"),
                        report.events.len()
                    ),
                    format!(
                        "    {}: {}",
                        self.text("İlişkilendirilen süreç", "Attributed processes"),
                        report.processes.len()
                    ),
                    format!(
                        "    {}: {}",
                        self.text("Süreci bilinmeyen olay", "Unattributed events"),
                        report.unattributed_event_count
                    ),
                    String::new(),
                ];
                lines.extend(
                    report
                        .counts
                        .iter()
                        .map(|(kind, count)| format!("    {kind:<22} {count}")),
                );
                self.body = Some(lines);
                self.report = Some(report);
            }
            "export" => {
                let path = path_argument(arg)?;
                let report = self.report.as_ref().context("open <file> → analyze")?;
                let bytes = encoded_report(report)?;
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)?
                    .write_all(&bytes)?;
                self.status = Some(self.text("rapor kaydedildi", "report saved").into());
            }
            _ => anyhow::bail!(
                "{}",
                self.text("Bilinmeyen komut · help", "Unknown command · help")
            ),
        }
        Ok(true)
    }
}

fn path_argument(arg: &str) -> Result<PathBuf> {
    let path = arg
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(arg);
    ensure!(!path.is_empty(), "open <file> / export <file>");
    Ok(PathBuf::from(path))
}

fn fit(text: &str, width: usize) -> String {
    let mut used = 0;
    text.chars()
        .map(|c| if c.is_control() { '�' } else { c })
        .take_while(|c| {
            used += c.width().unwrap_or(0);
            used <= width
        })
        .collect()
}

fn centered(text: &str, width: usize) -> String {
    format!(
        "{}{}",
        " ".repeat(width.saturating_sub(text.width()) / 2),
        text
    )
}

fn render(out: &mut impl Write, workspace: &mut Workspace) -> io::Result<()> {
    let (cols, rows) = terminal::size()?;
    let width = usize::from(cols.saturating_sub(1));
    queue!(out, Hide, Clear(ClearType::All))?;
    if cols < 12 || rows < 8 {
        queue!(out, MoveTo(0, 0), Print(fit("VespDex", width)))?;
        return out.flush();
    }
    let mut row = |y, color, text: &str| -> io::Result<()> {
        queue!(
            out,
            MoveTo(0, y),
            SetForegroundColor(color),
            Print(fit(text, width))
        )
    };
    let divider = "─".repeat(width);
    row(
        0,
        Color::Green,
        &format!(
            "  ◇ VespDex   /   {}   v{}",
            workspace.text("analist çalışma alanı", "analyst workspace"),
            env!("CARGO_PKG_VERSION"),
        ),
    )?;
    let selected = workspace
        .capture
        .as_ref()
        .map(|path| format!("  ◉ {}", path.display()));
    row(
        1,
        Color::Grey,
        selected.as_deref().unwrap_or(workspace.text(
            "  ○ Kayıt seçilmedi · open ile başla",
            "  ○ No capture selected · start with open",
        )),
    )?;
    row(2, Color::DarkGrey, &divider)?;
    let footer = rows - 4;
    if let Some(body) = &workspace.body {
        let height = usize::from(footer - 3);
        workspace.scroll = workspace.scroll.min(body.len().saturating_sub(height));
        for (y, text) in (3..footer).zip(body.iter().skip(workspace.scroll)) {
            row(y, if y == 3 { Color::Green } else { Color::White }, text)?;
        }
    } else {
        let mut splash = vec!["VespDex", ""];
        if footer - 3 >= 15 {
            splash.extend(EMBLEM);
            splash.push("");
        }
        splash.push("open <file>  ·  analyze  ·  help");
        splash.push(workspace.text(
            "[TR] Türkçe  /  EN English  ·  /lang tr|en",
            "TR Türkçe  /  [EN] English  ·  /lang tr|en",
        ));
        for (i, (y, text)) in (3..footer).zip(splash).enumerate() {
            row(
                y,
                if i == 0 { Color::Green } else { Color::White },
                &centered(text, width),
            )?;
        }
    }
    row(footer, Color::DarkGrey, &divider)?;
    row(
        footer + 1,
        Color::Green,
        &format!(
            "  ● {}  ·  {}",
            workspace
                .status
                .as_deref()
                .unwrap_or(workspace.text("hazır", "ready")),
            workspace.text("TR", "EN")
        ),
    )?;

    let prefix = "  › ";
    let before_cursor: String = workspace.input[..workspace.cursor]
        .iter()
        .rev()
        .copied()
        .collect();
    let tail = fit(&before_cursor, width.saturating_sub(prefix.width() + 1));
    let first = workspace.cursor - tail.chars().count();
    let visible: String = workspace.input[first..].iter().collect();
    row(footer + 2, Color::White, &format!("{prefix}{visible}"))?;
    if let Ok(path) = env::current_dir() {
        row(
            footer + 3,
            Color::DarkGrey,
            &format!("  {}", path.display()),
        )?;
    }
    let cursor_x = (prefix.width() + tail.width()) as u16;
    queue!(out, ResetColor, MoveTo(cursor_x, footer + 2), Show)?;
    out.flush()
}

pub(crate) fn run() -> Result<()> {
    let _screen = Screen::enter()?;
    let mut out = io::stdout().lock();
    let mut workspace = Workspace::default();
    render(&mut out, &mut workspace)?;
    loop {
        match event::read()? {
            Event::Paste(text) => workspace.insert(text.chars()),
            Event::Resize(_, _) => {}
            Event::Key(key) if key.kind != KeyEventKind::Release => match key.code {
                KeyCode::Esc => break,
                KeyCode::Char('c' | 'd') if key.modifiers == KeyModifiers::CONTROL => break,
                KeyCode::Char(c)
                    if !key.modifiers.contains(KeyModifiers::CONTROL)
                        || key.modifiers.contains(KeyModifiers::ALT) =>
                {
                    workspace.insert([c])
                }
                KeyCode::Left => workspace.cursor = workspace.cursor.saturating_sub(1),
                KeyCode::Right => {
                    workspace.cursor = (workspace.cursor + 1).min(workspace.input.len())
                }
                KeyCode::Home => workspace.cursor = 0,
                KeyCode::End => workspace.cursor = workspace.input.len(),
                KeyCode::Backspace if workspace.cursor > 0 => {
                    workspace.cursor -= 1;
                    workspace.input.remove(workspace.cursor);
                }
                KeyCode::Delete if workspace.cursor < workspace.input.len() => {
                    workspace.input.remove(workspace.cursor);
                }
                KeyCode::PageUp => workspace.scroll = workspace.scroll.saturating_sub(5),
                KeyCode::PageDown => workspace.scroll = workspace.scroll.saturating_add(5),
                KeyCode::Enter => match workspace.submit() {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(error) => {
                        workspace.status =
                            Some(format!("{}: {error:#}", workspace.text("Hata", "Error")))
                    }
                },
                _ => continue,
            },
            _ => continue,
        }
        render(&mut out, &mut workspace)?;
    }
    Ok(())
}
