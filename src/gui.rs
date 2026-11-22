use std::{
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
    sync::mpsc::{self, Receiver, TryRecvError},
};

use anyhow::Result;
use eframe::egui::{self, Color32, RichText, Stroke, Vec2};

use crate::{EventKind, Report, analyze, encoded_report, read_capture};

mod sysmon;

// AsphDex's green Dark palette (css/style.css).
const BG: Color32 = Color32::from_rgb(5, 8, 6);
const SURFACE: Color32 = Color32::from_rgb(9, 16, 12);
const ACTIVE: Color32 = Color32::from_rgb(13, 22, 17);
const LINE: Color32 = Color32::from_rgb(27, 51, 36);
const LINE_HOT: Color32 = Color32::from_rgb(46, 107, 64);
const ACCENT: Color32 = Color32::from_rgb(40, 255, 115);
const TEXT: Color32 = Color32::from_rgb(229, 244, 233);
const MUTED: Color32 = Color32::from_rgb(130, 153, 138);

#[derive(Default, PartialEq, Eq)]
enum View {
    #[default]
    Start,
    ChooseProcess,
    Overview,
    Timeline,
    Processes,
}

impl View {
    fn label(&self) -> &'static str {
        match self {
            Self::Start => "Başlangıç",
            Self::ChooseProcess => "Başlangıç süreci",
            Self::Overview => "Genel Bakış",
            Self::Timeline => "Zaman Çizelgesi",
            Self::Processes => "Süreçler",
        }
    }

    fn group(&self) -> &'static str {
        match self {
            Self::Start | Self::ChooseProcess | Self::Overview => "Analiz",
            Self::Timeline | Self::Processes => "İnceleme",
        }
    }
}

#[derive(Default)]
struct Workspace {
    mask: Option<egui::TextureHandle>,
    path: Option<PathBuf>,
    report: Option<Report>,
    pending: Option<Receiver<Result<Loaded>>>,
    candidates: Vec<sysmon::Candidate>,
    process_search: String,
    message: Option<(bool, String)>,
    view: View,
    event_kind: Option<EventKind>,
    process_guid: Option<String>,
    selected_event: Option<usize>,
}

enum Loaded {
    Report(Report),
    Processes(Vec<sysmon::Candidate>),
}

pub(crate) fn run(path: Option<PathBuf>) -> Result<()> {
    let mask = eframe::icon_data::from_png_bytes(include_bytes!("../assets/asphdex-mask.png"))?;
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1220.0, 820.0])
            .with_min_inner_size([760.0, 520.0])
            .with_icon(mask.clone()),
        ..Default::default()
    };
    eframe::run_native(
        "VespDex",
        options,
        Box::new(move |cc| {
            let mut visuals = egui::Visuals::dark();
            visuals.panel_fill = BG;
            visuals.window_fill = SURFACE;
            visuals.window_stroke = Stroke::new(1.0_f32, LINE);
            visuals.override_text_color = Some(TEXT);
            visuals.selection.bg_fill = ACTIVE;
            visuals.selection.stroke = Stroke::new(1.0_f32, LINE_HOT);
            for widgets in [
                &mut visuals.widgets.inactive,
                &mut visuals.widgets.hovered,
                &mut visuals.widgets.active,
            ] {
                widgets.bg_fill = SURFACE;
                widgets.weak_bg_fill = ACTIVE;
                widgets.corner_radius = egui::CornerRadius::same(2);
                widgets.bg_stroke = Stroke::new(1.0_f32, LINE);
                widgets.fg_stroke = Stroke::new(1.0_f32, TEXT);
            }
            visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, LINE_HOT);
            visuals.widgets.active.bg_stroke = Stroke::new(1.0_f32, ACCENT);
            cc.egui_ctx.set_visuals(visuals);
            let texture = cc.egui_ctx.load_texture(
                "asphdex-mask",
                egui::ColorImage::from_rgba_unmultiplied(
                    [mask.width as usize, mask.height as usize],
                    &mask.rgba,
                ),
                egui::TextureOptions::LINEAR,
            );
            let mut workspace = Workspace {
                mask: Some(texture),
                ..Workspace::default()
            };
            if let Some(path) = path {
                workspace.load(path, &cc.egui_ctx);
            }
            Ok(Box::new(workspace))
        }),
    )
    .map_err(|error| anyhow::anyhow!("desktop workspace failed: {error}"))
}

impl Workspace {
    fn load(&mut self, path: PathBuf, ctx: &egui::Context) {
        self.path = Some(path.clone());
        self.report = None;
        self.candidates.clear();
        self.process_search.clear();
        self.view = View::Start;
        self.event_kind = None;
        self.process_guid = None;
        self.selected_event = None;
        let evtx = path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("evtx"));
        self.start_job(ctx, move || {
            if evtx {
                sysmon::list(&path).map(Loaded::Processes)
            } else {
                read_capture(&path).and_then(analyze).map(Loaded::Report)
            }
        });
    }

    fn start_job(
        &mut self,
        ctx: &egui::Context,
        job: impl FnOnce() -> Result<Loaded> + Send + 'static,
    ) {
        let (sender, receiver) = mpsc::channel();
        let ctx = ctx.clone();
        self.pending = Some(receiver);
        self.message = None;
        std::thread::spawn(move || {
            let _ = sender.send(job());
            ctx.request_repaint();
        });
    }

    fn poll(&mut self) {
        let Some(pending) = &self.pending else { return };
        match pending.try_recv() {
            Ok(result) => {
                self.pending = None;
                match result {
                    Ok(Loaded::Report(report)) => {
                        self.report = Some(report);
                        self.event_kind = None;
                        self.process_guid = None;
                        self.selected_event = None;
                        self.view = View::Overview;
                    }
                    Ok(Loaded::Processes(candidates)) => {
                        self.candidates = candidates;
                        self.view = View::ChooseProcess;
                    }
                    Err(error) => {
                        self.message = Some((true, format!("Kayıt açılamadı: {error:#}")))
                    }
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.pending = None;
                self.message = Some((true, "Analiz işlemi beklenmedik şekilde kapandı.".into()));
            }
        }
    }

    fn export(&mut self) {
        let Some(report) = &self.report else { return };
        let Some(path) = rfd::FileDialog::new()
            .add_filter("JSON", &["json"])
            .set_file_name("behavior.json")
            .save_file()
        else {
            return;
        };
        let result = encoded_report(report).and_then(|bytes| {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?
                .write_all(&bytes)?;
            Ok(())
        });
        self.message = Some(match result {
            Ok(()) => (false, format!("Rapor kaydedildi: {}", path.display())),
            Err(error) => (
                true,
                format!("Rapor kaydedilemedi. Yeni bir dosya adı seç. ({error})"),
            ),
        });
    }
}

impl eframe::App for Workspace {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        if self.pending.is_none() {
            let dropped = ctx.input(|input| {
                input
                    .raw
                    .dropped_files
                    .first()
                    .and_then(|file| file.path.clone())
            });
            if let Some(path) = dropped {
                self.load(path, ctx);
            }
        }

        egui::TopBottomPanel::top("header")
            .frame(panel(BG, 22, 14))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    self.show_mask(ui, 30.0);
                    ui.label(egui::RichText::new("Vesp").size(22.0).strong());
                    ui.add_space(-8.0);
                    ui.label(egui::RichText::new("Dex").size(22.0).strong().color(ACCENT));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                                .small()
                                .monospace()
                                .color(MUTED),
                        );
                        ui.add_space(8.0);
                        open_button(ui, self, ctx);
                    });
                });
            });
        egui::TopBottomPanel::bottom("status")
            .frame(panel(BG, 22, 5))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if self.pending.is_some() {
                        ui.spinner();
                        ui.label("Kayıt analiz ediliyor");
                    } else if let Some((error, message)) = &self.message {
                        ui.colored_label(if *error { Color32::LIGHT_RED } else { ACCENT }, message);
                    } else {
                        ui.label(
                            RichText::new("YEREL ANALİZ")
                                .small()
                                .monospace()
                                .color(MUTED),
                        );
                    }
                });
            });
        egui::SidePanel::left("navigation")
            .resizable(false)
            .exact_width(198.0)
            .frame(panel(BG, 14, 20))
            .show(ctx, |ui| {
                ui.strong("Analiz");
                ui.add_space(8.0);
                nav(ui, &mut self.view, View::Start, true);
                if !self.candidates.is_empty() {
                    nav(ui, &mut self.view, View::ChooseProcess, true);
                }
                nav(ui, &mut self.view, View::Overview, self.report.is_some());
                ui.add_space(23.0);
                ui.strong("İnceleme");
                ui.add_space(8.0);
                nav(ui, &mut self.view, View::Timeline, self.report.is_some());
                nav(ui, &mut self.view, View::Processes, self.report.is_some());
            });

        egui::CentralPanel::default()
            .frame(panel(BG, 0, 0))
            .show(ctx, |ui| {
                panel(BG, 26, 14).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(self.view.group()).small().color(MUTED));
                        ui.strong(self.view.label());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let name = self
                                .path
                                .as_ref()
                                .and_then(|path| path.file_name())
                                .map(|name| name.to_string_lossy())
                                .unwrap_or_else(|| "Henüz kayıt yok".into());
                            ui.add(
                                egui::Label::new(
                                    RichText::new(name).small().monospace().color(MUTED),
                                )
                                .truncate(),
                            );
                        });
                    });
                });
                egui::Frame::new()
                    .inner_margin(egui::Margin::symmetric(24, 22))
                    .show(ui, |ui| match self.view {
                        View::Start => self.start(ui, ctx),
                        View::ChooseProcess => self.choose_process(ui, ctx),
                        View::Overview if self.report.is_some() => self.overview(ui),
                        View::Timeline if self.report.is_some() => {
                            let report = self.report.as_ref().expect("view has a report");
                            panel_heading(ui, "Olay zaman çizelgesi");
                            panel(SURFACE, 14, 12).show(ui, |ui| {
                                timeline(
                                    ui,
                                    report,
                                    &mut self.event_kind,
                                    &mut self.process_guid,
                                    &mut self.selected_event,
                                );
                            });
                        }
                        View::Processes if self.report.is_some() => {
                            let report = self.report.as_ref().expect("view has a report");
                            panel_heading(ui, "Süreçler");
                            if let Some(guid) = processes(ui, report) {
                                self.process_guid = Some(guid);
                                self.event_kind = None;
                                self.selected_event = None;
                                self.view = View::Timeline;
                            }
                        }
                        _ => self.start(ui, ctx),
                    });
            });
    }
}

impl Workspace {
    fn choose_process(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        panel_heading(ui, "Başlangıç sürecini seç");
        ui.label(RichText::new("Sysmon tarafından SHA-256 değeri kaydedilmiş süreçler. Seçilen süreç ve alt süreçleri rapora girer.").color(MUTED));
        ui.add_space(8.0);
        ui.add(
            egui::TextEdit::singleline(&mut self.process_search)
                .hint_text("Dosya adı, süreç GUID veya SHA-256 ile ara")
                .char_limit(160)
                .desired_width(370.0),
        );
        let filter = self.process_search.trim().to_lowercase();
        let entries: Vec<_> = self
            .candidates
            .iter()
            .filter(|candidate| {
                filter.is_empty()
                    || candidate.image.to_lowercase().contains(&filter)
                    || candidate.guid.contains(&filter)
                    || candidate.sha256.contains(&filter)
            })
            .collect();
        ui.label(
            RichText::new(format!(
                "{} / {} süreç",
                entries.len(),
                self.candidates.len()
            ))
            .color(MUTED),
        );

        let mut selected = None;
        let available = self.pending.is_none();
        egui::ScrollArea::vertical()
            .id_salt(("sysmon-processes", &filter))
            .auto_shrink([false, false])
            .show_rows(ui, 28.0, entries.len(), |ui, rows| {
                for candidate in &entries[rows] {
                    let name = std::path::Path::new(&candidate.image)
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or(&candidate.image);
                    let label = format!("{name}    {}    {}", candidate.timestamp, candidate.guid);
                    let response = ui
                        .add_enabled(
                            available,
                            egui::Button::new(label)
                                .truncate()
                                .min_size(Vec2::new(ui.available_width(), 28.0)),
                        )
                        .on_hover_text(format!(
                            "{}\nSHA-256 {}",
                            candidate.image, candidate.sha256
                        ));
                    if response.clicked() {
                        selected = Some((candidate.guid.clone(), candidate.sha256.clone()));
                    }
                }
            });
        if let (Some((guid, expected_hash)), Some(path)) = (selected, self.path.clone()) {
            self.start_job(ctx, move || {
                let report = sysmon::convert(&path, &guid)?;
                anyhow::ensure!(
                    report.sample_sha256 == expected_hash,
                    "selected process no longer matches the EVTX process list"
                );
                Ok(Loaded::Report(report))
            });
        }
    }

    fn show_mask(&self, ui: &mut egui::Ui, size: f32) {
        if let Some(mask) = &self.mask {
            ui.image((mask.id(), Vec2::splat(size)));
        }
    }

    fn start(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.vertical_centered(|ui| {
            ui.set_max_width(780.0);
            ui.add_space(24.0);
            panel_heading(ui, "Yeni inceleme");
            panel(SURFACE, 22, 22).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.vertical_centered(|ui| {
                    self.show_mask(ui, 160.0);
                    ui.add_space(18.0);
                    ui.heading("Telemetri kaydı yükle");
                    ui.label(
                        RichText::new("Telemetri JSON veya Sysmon EVTX dosyasını buraya sürükle.")
                            .color(MUTED),
                    );
                    ui.add_space(12.0);
                    open_button(ui, self, ctx);
                    ui.add_space(7.0);
                });
            });
        });
    }

    fn overview(&mut self, ui: &mut egui::Ui) {
        let mut export = false;
        ui.horizontal(|ui| {
            ui.label(RichText::new("Davranış özeti").size(26.0).strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                export = ui
                    .button(RichText::new("RAPORU KAYDET").color(ACCENT))
                    .clicked();
            });
        });
        ui.separator();
        ui.add_space(12.0);
        if let Some(report) = &self.report {
            panel(SURFACE, 16, 14).show(ui, |ui| {
                ui.columns(3, |columns| {
                    metric(&mut columns[0], "KAYITLI OLAY", report.events.len());
                    metric(&mut columns[1], "SÜREÇ", report.processes.len());
                    metric(
                        &mut columns[2],
                        "SÜRECİ BİLİNMEYEN OLAY",
                        report.unattributed_event_count,
                    );
                });
            });
            ui.add_space(12.0);
            panel(SURFACE, 16, 14).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.strong("Kayıt bilgileri");
                ui.add_space(8.0);
                ui.label(format!("Vaka  {}", report.case_id));
                ui.label(format!("Kaynak  {}", report.source));
                ui.label(
                    RichText::new(format!("SHA-256  {}", report.sample_sha256))
                        .monospace()
                        .color(MUTED),
                );
                if let Some(window) = &report.capture_window {
                    ui.label(
                        RichText::new(format!("Gözlem  {} – {}", window.start, window.end))
                            .color(MUTED),
                    );
                }
                ui.add_space(10.0);
                if ui
                    .button(RichText::new("ZAMAN ÇİZELGESİNİ AÇ").color(ACCENT))
                    .clicked()
                {
                    self.view = View::Timeline;
                }
            });
            ui.add_space(12.0);
            panel(SURFACE, 16, 14).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.strong("Olay türleri");
                ui.add_space(6.0);
                for kind in EventKind::ALL {
                    if let Some(count) = report.counts.get(kind.key()) {
                        ui.horizontal(|ui| {
                            ui.label(event_label(kind));
                            ui.label(RichText::new(count.to_string()).monospace().color(ACCENT));
                        });
                    }
                }
                if report.counts.is_empty() {
                    ui.label(RichText::new("Kayıt olay içermiyor.").color(MUTED));
                }
            });
        }
        if export {
            self.export();
        }
    }
}

fn panel(fill: Color32, x: i8, y: i8) -> egui::Frame {
    egui::Frame::new()
        .fill(fill)
        .stroke(Stroke::new(1.0_f32, LINE))
        .inner_margin(egui::Margin::symmetric(x, y))
        .corner_radius(2)
}

fn panel_heading(ui: &mut egui::Ui, title: &str) {
    ui.label(RichText::new(title).size(26.0).strong());
    ui.separator();
    ui.add_space(12.0);
}

fn open_button(ui: &mut egui::Ui, workspace: &mut Workspace, ctx: &egui::Context) {
    let button = egui::Button::new(RichText::new("DOSYA SEÇ").color(BG).strong())
        .fill(ACCENT)
        .min_size(Vec2::new(110.0, 30.0));
    if ui
        .add_enabled(workspace.pending.is_none(), button)
        .clicked()
        && let Some(path) = rfd::FileDialog::new()
            .add_filter("Telemetri kayıtları", &["json", "evtx"])
            .pick_file()
    {
        workspace.load(path, ctx);
    }
}

fn nav(ui: &mut egui::Ui, current: &mut View, destination: View, enabled: bool) {
    let selected = *current == destination;
    let button = egui::Button::new(RichText::new(destination.label()).color(if selected {
        TEXT
    } else {
        MUTED
    }))
    .selected(selected)
    .fill(if selected { ACTIVE } else { BG })
    .stroke(Stroke::NONE)
    .min_size(Vec2::new(ui.available_width(), 30.0));
    let response = ui.add_enabled(enabled, button);
    if selected {
        let rect = response.rect;
        ui.painter().line_segment(
            [rect.left_top(), rect.left_bottom()],
            Stroke::new(2.0_f32, TEXT),
        );
    }
    if response.clicked() {
        *current = destination;
    }
}

fn metric(ui: &mut egui::Ui, label: &str, number: usize) {
    ui.label(RichText::new(label).small().monospace().color(MUTED));
    ui.label(
        RichText::new(number.to_string())
            .size(32.0)
            .strong()
            .color(ACCENT),
    );
}

fn event_label(kind: EventKind) -> &'static str {
    match kind {
        EventKind::ProcessStart => "Süreç başlangıcı",
        EventKind::FileWrite => "Dosya yazma",
        EventKind::RegistryWrite => "Kayıt defteri",
        EventKind::NetworkConnection => "Ağ bağlantısı",
        EventKind::DnsQuery => "DNS sorgusu",
    }
}

fn timeline(
    ui: &mut egui::Ui,
    report: &Report,
    kind: &mut Option<EventKind>,
    process: &mut Option<String>,
    selected: &mut Option<usize>,
) {
    ui.horizontal_wrapped(|ui| {
        let previous = *kind;
        egui::ComboBox::from_id_salt("event-kind")
            .width(160.0)
            .selected_text(kind.map(event_label).unwrap_or("Tüm olay türleri"))
            .show_ui(ui, |ui| {
                ui.selectable_value(kind, None, "Tüm olay türleri");
                for event in EventKind::ALL {
                    ui.selectable_value(kind, Some(event), event_label(event));
                }
            });
        if previous != *kind {
            *selected = None;
        }
        if let Some(guid) = process.as_ref() {
            ui.label(RichText::new(guid.as_str()).monospace());
            if ui.small_button("Süreç filtresini kaldır").clicked() {
                *process = None;
                *selected = None;
            }
        }
    });
    let visible: Vec<_> = report
        .events
        .iter()
        .enumerate()
        .filter(|(_, event)| {
            kind.is_none_or(|kind| kind == event.kind)
                && process
                    .as_ref()
                    .is_none_or(|guid| event.process_guid.as_ref() == Some(guid))
        })
        .collect();
    ui.label(
        RichText::new(format!("{} / {} olay", visible.len(), report.events.len())).color(MUTED),
    );
    if let Some(index) = *selected
        && let Some(event) = report.events.get(index)
    {
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.strong(event_label(event.kind));
                if ui.small_button("Kapat").clicked() {
                    *selected = None;
                }
            });
            ui.label(&event.timestamp);
            if let Some(guid) = &event.process_guid {
                ui.label(RichText::new(guid).monospace().color(MUTED));
            }
            egui::ScrollArea::vertical()
                .id_salt("event-detail")
                .max_height(95.0)
                .show(ui, |ui| {
                    ui.add(egui::Label::new(&event.detail).wrap().selectable(true));
                });
        });
    }
    if visible.is_empty() {
        ui.label("Bu filtreyle eşleşen olay yok.");
        return;
    }
    egui::ScrollArea::vertical()
        .id_salt(("timeline", kind.map(EventKind::key), process.clone()))
        .auto_shrink([false, false])
        .show_rows(ui, 24.0, visible.len(), |ui, rows| {
            for (index, event) in &visible[rows] {
                let label = format!(
                    "{}    {}    {}",
                    event.timestamp,
                    event_label(event.kind),
                    event.detail
                );
                let button = egui::Button::new(label)
                    .selected(*selected == Some(*index))
                    .truncate();
                if ui.add_sized([ui.available_width(), 24.0], button).clicked() {
                    *selected = Some(*index);
                }
            }
        });
}

fn processes(ui: &mut egui::Ui, report: &Report) -> Option<String> {
    let mut filter = None;
    if report.processes.is_empty() {
        ui.label("Bu kayıtta süreç kimliği bulunamadı.");
    }
    egui::ScrollArea::vertical()
        .id_salt("process-list")
        .show(ui, |ui| {
            for (guid, process) in &report.processes {
                panel(SURFACE, 14, 10).show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.strong(
                            process
                                .image
                                .as_deref()
                                .unwrap_or("Yürütülebilir dosya bilinmiyor"),
                        );
                        if ui.small_button("Olayları göster").clicked() {
                            filter = Some(guid.clone());
                        }
                    });
                    ui.label(RichText::new(guid).monospace().color(MUTED));
                    if let Some(parent) = &process.parent_process_guid {
                        ui.label(
                            RichText::new(format!("Üst süreç  {parent}"))
                                .monospace()
                                .color(MUTED),
                        );
                    }
                    ui.horizontal_wrapped(|ui| {
                        for event in EventKind::ALL {
                            if let Some(count) = process.counts.get(event.key()) {
                                ui.label(format!("{} {count}", event_label(event)));
                            }
                        }
                    });
                });
            }
        });
    filter
}
