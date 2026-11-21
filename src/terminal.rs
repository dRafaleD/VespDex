use std::{
    env,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::PathBuf,
    time::Instant,
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

use crate::{EventKind, Report, analyze, encoded_report, normalize_guid, read_capture};

mod boot;
pub(crate) mod portrait;
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
    wrapped_body: Vec<String>,
    wrap_width: usize,
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
        self.wrap_width = 0;
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
                            "    timeline [tür|all] [GUID]  Zaman çizelgesini göster",
                            "    timeline [type|all] [GUID]  Show the event timeline",
                        ),
                        "      process-start · file-write · registry-write · network-connection · dns-query",
                        self.text(
                            "    processes        Süreçleri ve üst süreçlerini listele",
                            "    processes        List processes and their parents",
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
            "timeline" => self.body = Some(self.timeline(arg)?),
            "processes" => {
                ensure!(arg.is_empty(), "processes");
                self.body = Some(self.processes()?);
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

    fn timeline(&self, filters: &str) -> Result<Vec<String>> {
        let report = self.report.as_ref().context("open <file> → analyze")?;
        let mut args = filters.split_whitespace();
        let kind = args.next().filter(|value| *value != "all");
        let guid = args.next().map(normalize_guid).transpose()?;
        ensure!(args.next().is_none(), "timeline [type|all] [GUID]");
        if let Some(kind) = kind {
            ensure!(
                EventKind::ALL.iter().any(|item| item.key() == kind),
                "timeline [process-start|file-write|registry-write|network-connection|dns-query|all] [GUID]"
            );
        }
        let mut lines = vec![
            self.text("  ◆ Olay zaman çizelgesi", "  ◆ Event timeline")
                .into(),
            String::new(),
        ];
        let mut count = 0;
        for event in &report.events {
            if kind.is_some_and(|kind| event.kind.key() != kind)
                || guid
                    .as_ref()
                    .is_some_and(|guid| event.process_guid.as_ref() != Some(guid))
            {
                continue;
            }
            count += 1;
            lines.push(format!("    {}  {}", event.timestamp, event.kind.key()));
            if let Some(guid) = &event.process_guid {
                lines.push(format!("      GUID {guid}"));
            }
            lines.push(format!("      {}", event.detail));
        }
        lines[1] = format!(
            "    {count} / {} {}",
            report.events.len(),
            self.text("olay", "events")
        );
        if count == 0 {
            lines.push(
                self.text("    Eşleşen olay yok.", "    No matching events.")
                    .into(),
            );
        }
        Ok(lines)
    }

    fn processes(&self) -> Result<Vec<String>> {
        let report = self.report.as_ref().context("open <file> → analyze")?;
        let mut lines = vec![
            self.text("  ◆ Süreçler", "  ◆ Processes").into(),
            String::new(),
        ];
        for (guid, process) in &report.processes {
            let total: usize = process.counts.values().sum();
            lines.push(format!(
                "    {guid} · {total} {}",
                self.text("olay", "events")
            ));
            if let Some(image) = &process.image {
                lines.push(format!("      {image}"));
            }
            if let Some(parent) = &process.parent_process_guid {
                lines.push(format!(
                    "      {} {parent}",
                    self.text("Üst süreç:", "Parent:")
                ));
            }
        }
        if report.processes.is_empty() {
            lines.push(
                self.text(
                    "    İlişkilendirilen süreç yok.",
                    "    No attributed processes.",
                )
                .into(),
            );
        }
        Ok(lines)
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

fn wrap(text: &str, width: usize, lines: &mut Vec<String>) {
    let mut line = String::new();
    let mut cells = 0;
    for ch in text.chars() {
        let size = ch.width().unwrap_or(0);
        if cells + size > width {
            lines.push(std::mem::take(&mut line));
            cells = 0;
        }
        line.push(ch);
        cells += size;
    }
    lines.push(line);
}

fn render(
    out: &mut impl Write,
    workspace: &mut Workspace,
    progress: Option<f64>,
) -> io::Result<()> {
    let (cols, rows) = terminal::size()?;
    let width = usize::from(cols.saturating_sub(1));
    queue!(out, Hide)?;
    if cols < 12 || rows < 9 {
        queue!(
            out,
            MoveTo(0, 0),
            Clear(ClearType::All),
            Print(fit("VespDex", width))
        )?;
        return out.flush();
    }
    let boot_frame = progress
        .filter(|_| width >= 32 && rows >= 12)
        .map(|progress| boot::Frame {
            width,
            height: usize::from(rows),
            progress,
            english: workspace.english,
        });
    let mut row = |y, color, text: &str| -> io::Result<()> {
        queue!(out, MoveTo(0, y), Clear(ClearType::CurrentLine))?;
        let (line, tone) = match boot_frame {
            Some(frame) => frame.row(y, text, color),
            None => (text.to_owned(), color),
        };
        queue!(out, SetForegroundColor(tone), Print(fit(&line, width)))
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
    let footer = rows - 5;
    if let Some(body) = &workspace.body {
        if workspace.wrap_width != width {
            workspace.wrapped_body.clear();
            for line in body {
                wrap(line, width, &mut workspace.wrapped_body);
            }
            workspace.wrap_width = width;
        }
        let body = &workspace.wrapped_body;
        let height = usize::from(footer - 3);
        workspace.scroll = workspace.scroll.min(body.len().saturating_sub(height));
        for y in 3..footer {
            let text = body
                .get(usize::from(y - 3) + workspace.scroll)
                .map(String::as_str)
                .unwrap_or("");
            row(y, if y == 3 { Color::Green } else { Color::White }, text)?;
        }
    } else {
        let room = usize::from(footer - 3);
        let wide = cols >= 80 && rows >= 26;
        let budget = if wide {
            room.saturating_sub(2)
        } else {
            room.saturating_sub(5)
        };
        let budget = budget.min(width * 5 / 8);
        let mask = if budget >= 5 {
            portrait::mask(budget)
        } else {
            &[]
        };
        let mask_width = mask.iter().map(|line| line.width()).max().unwrap_or(0);
        let language = workspace.text(
            "[TR] Türkçe  /  EN English  ·  /lang tr|en",
            "TR Türkçe  /  [EN] English  ·  /lang tr|en",
        );
        let mut splash = vec![
            (
                centered(
                    if wide {
                        "◇  V E S P D E X  ◇"
                    } else {
                        "VespDex"
                    },
                    width,
                ),
                Color::Green,
            ),
            (String::new(), Color::White),
        ];
        if wide {
            let info = [
                format!("VespDex {}", env!("CARGO_PKG_VERSION")),
                "─".repeat(27),
                format!(
                    "{}   {} · {}",
                    workspace.text("Sistem", "System"),
                    env::consts::OS,
                    env::consts::ARCH
                ),
                workspace
                    .text("Mod      Davranış analizi", "Mode     Behavior analysis")
                    .into(),
                workspace.text("Dil      Türkçe", "Language English").into(),
                String::new(),
                "open <file>  ·  analyze".into(),
                "help  ·  lang tr|en".into(),
            ];
            let info_width = info.iter().map(|line| line.width()).max().unwrap_or(0);
            let inset = " ".repeat(width.saturating_sub(mask_width + 5 + info_width) / 2);
            for index in 0..mask.len().max(info.len()) {
                let line = mask.get(index).copied().unwrap_or("");
                let padding = " ".repeat(mask_width.saturating_sub(line.width()) + 5);
                let label = info.get(index).map(String::as_str).unwrap_or("");
                splash.push((format!("{inset}{line}{padding}{label}"), Color::Green));
            }
        } else {
            let inset = " ".repeat(width.saturating_sub(mask_width) / 2);
            splash.extend(
                mask.iter()
                    .map(|line| (format!("{inset}{line}"), Color::Green)),
            );
            splash.push((String::new(), Color::White));
            splash.push((
                centered("open <file>  ·  analyze  ·  help", width),
                Color::Green,
            ));
            splash.push((centered(language, width), Color::Green));
        }
        for y in 3..footer {
            let i = usize::from(y - 3);
            let (text, color) = splash
                .get(i)
                .map(|(text, color)| (text.as_str(), *color))
                .unwrap_or(("", Color::White));
            row(y, color, text)?;
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
    row(footer + 3, Color::Grey, "")?;
    let directory = env::current_dir()
        .map(|path| format!("  {}", path.display()))
        .unwrap_or_default();
    row(footer + 4, Color::DarkGrey, &directory)?;
    let cursor_x = (prefix.width() + tail.width()) as u16;
    queue!(out, ResetColor, MoveTo(cursor_x, footer + 2))?;
    if boot_frame.is_none() {
        queue!(out, Show)?;
    }
    out.flush()
}

fn play_opening(out: &mut impl Write, workspace: &mut Workspace) -> io::Result<Option<Event>> {
    let (columns, rows) = terminal::size()?;
    if columns < 33 || rows < 12 {
        return Ok(None);
    }
    let start = Instant::now();
    loop {
        let elapsed = start.elapsed();
        if elapsed >= boot::DURATION {
            return Ok(None);
        }
        render(
            out,
            workspace,
            Some(elapsed.as_secs_f64() / boot::DURATION.as_secs_f64()),
        )?;
        if !event::poll(boot::INTERVAL.min(boot::DURATION.saturating_sub(start.elapsed())))? {
            continue;
        }
        match event::read()? {
            Event::Key(key) if key.kind != KeyEventKind::Release => {
                return Ok((key.code != KeyCode::Esc).then_some(Event::Key(key)));
            }
            Event::Paste(text) => return Ok(Some(Event::Paste(text))),
            _ => {}
        }
    }
}

pub(crate) fn run() -> Result<()> {
    let _screen = Screen::enter()?;
    let mut out = io::stdout().lock();
    let mut workspace = Workspace::default();
    let mut pending = play_opening(&mut out, &mut workspace)?;
    render(&mut out, &mut workspace, None)?;
    loop {
        let next = match pending.take() {
            Some(event) => event,
            None => event::read()?,
        };
        match next {
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
        render(&mut out, &mut workspace, None)?;
    }
    Ok(())
}
