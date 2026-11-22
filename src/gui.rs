use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, TryRecvError},
    },
};

use anyhow::Result;
use eframe::egui::{self, Color32, RichText, Stroke, Vec2};

use crate::{EventKind, Report, analyze, demo_report, read_capture, save_report};

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
    report: Option<Box<Report>>,
    pending: Option<PendingLoad>,
    candidate_path: Option<PathBuf>,
    candidates: Vec<sysmon::Candidate>,
    process_search: String,
    message: Option<(bool, String)>,
    view: View,
    timeline: Timeline,
}

#[derive(Default)]
struct Timeline {
    kind: Option<EventKind>,
    process: Option<String>,
    query: String,
    selected: Option<usize>,
    focus_search: bool,
}

enum Loaded {
    Report(Box<Report>),
    Processes(Vec<sysmon::Candidate>),
}

struct PendingLoad {
    path: PathBuf,
    result: Receiver<Result<Loaded>>,
    cancelled: Arc<AtomicBool>,
}

pub(crate) fn run(path: Option<PathBuf>, demo: bool) -> Result<()> {
    let mask = eframe::icon_data::from_png_bytes(include_bytes!("../assets/asphdex-mask.png"))?;
    let mut setup = eframe::egui_wgpu::WgpuSetupCreateNew::default();
    setup.instance_descriptor.backends = wgpu::Backends::DX12;
    setup
        .instance_descriptor
        .backend_options
        .dx12
        .shader_compiler = wgpu::Dx12Compiler::Fxc;
    setup.native_adapter_selector = Some(Arc::new(|adapters, surface| {
        let adapter = adapters
            .iter()
            .filter(|adapter| surface.is_none_or(|surface| adapter.is_surface_supported(surface)))
            .min_by_key(|adapter| match adapter.get_info().device_type {
                wgpu::DeviceType::DiscreteGpu => 0,
                wgpu::DeviceType::IntegratedGpu => 1,
                wgpu::DeviceType::VirtualGpu => 2,
                wgpu::DeviceType::Cpu => 4,
                _ => 3,
            })
            .ok_or_else(|| {
                "No Direct3D 12 hardware or software adapter supports the VespDex window."
                    .to_owned()
            })?;
        Ok(adapter.clone())
    }));
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1220.0, 820.0])
            .with_min_inner_size([760.0, 520.0])
            .with_icon(mask.clone()),
        renderer: eframe::Renderer::Wgpu,
        wgpu_options: eframe::egui_wgpu::WgpuConfiguration {
            wgpu_setup: setup.into(),
            ..Default::default()
        },
        ..Default::default()
    };
    eframe::run_native(
        "VespDex",
        options,
        Box::new(move |cc| {
            if let Some(render) = &cc.wgpu_render_state {
                let adapter = render.adapter.get_info();
                eprintln!(
                    "VespDex desktop renderer: {:?} / {:?}",
                    adapter.backend, adapter.device_type
                );
            }
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
            } else if demo {
                workspace.load_demo();
            }
            Ok(Box::new(workspace))
        }),
    )
    .map_err(|error| anyhow::anyhow!("desktop workspace failed: {error}"))
}

impl Workspace {
    fn keyboard_actions(&mut self, ctx: &egui::Context) {
        if let Some(pending) = &self.pending
            && ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
        {
            pending.cancelled.store(true, Ordering::Relaxed);
        }
        if self.pending.is_none()
            && ctx.input_mut(|input| input.consume_key(egui::Modifiers::CTRL, egui::Key::O))
        {
            self.pick_capture(ctx);
        }
        if self.report.is_some() {
            if ctx.input_mut(|input| input.consume_key(egui::Modifiers::CTRL, egui::Key::S)) {
                self.export();
            }
            if ctx.input_mut(|input| input.consume_key(egui::Modifiers::CTRL, egui::Key::F)) {
                self.view = View::Timeline;
                self.timeline.focus_search = true;
            }
        }
    }

    fn pick_capture(&mut self, ctx: &egui::Context) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("Telemetri kayıtları", &["json", "evtx"])
            .pick_file()
        {
            self.load(path, ctx);
        }
    }

    fn load(&mut self, path: PathBuf, ctx: &egui::Context) {
        let evtx = path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("evtx"));
        self.start_job(ctx, path, move |path, cancelled| {
            if evtx {
                sysmon::list(path, cancelled).map(Loaded::Processes)
            } else {
                read_capture(path)
                    .and_then(analyze)
                    .map(Box::new)
                    .map(Loaded::Report)
            }
        });
    }

    fn start_job(
        &mut self,
        ctx: &egui::Context,
        path: PathBuf,
        job: impl FnOnce(&std::path::Path, &AtomicBool) -> Result<Loaded> + Send + 'static,
    ) {
        let (sender, receiver) = mpsc::channel();
        let ctx = ctx.clone();
        let cancelled = Arc::new(AtomicBool::new(false));
        self.pending = Some(PendingLoad {
            path: path.clone(),
            result: receiver,
            cancelled: Arc::clone(&cancelled),
        });
        self.message = None;
        std::thread::spawn(move || {
            let _ = sender.send(job(&path, &cancelled));
            ctx.request_repaint();
        });
    }

    fn poll(&mut self) {
        let Some(pending) = &self.pending else { return };
        let result = match pending.result.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => Err(anyhow::anyhow!(
                "Analiz işlemi beklenmedik şekilde kapandı."
            )),
        };
        let pending = self.pending.take().expect("finished load is present");
        if pending.cancelled.load(Ordering::Relaxed) {
            self.message = Some((false, "Kayıt açma iptal edildi.".into()));
        } else {
            self.finish_load(pending.path, result);
        }
    }

    fn finish_load(&mut self, path: PathBuf, result: Result<Loaded>) {
        match result {
            Ok(Loaded::Report(report)) => self.commit_report(Some(path), report),
            Ok(Loaded::Processes(candidates)) => {
                self.candidate_path = Some(path);
                self.candidates = candidates;
                self.process_search.clear();
                self.view = View::ChooseProcess;
            }
            Err(error) => {
                let file = path
                    .file_name()
                    .unwrap_or(path.as_os_str())
                    .to_string_lossy();
                self.message = Some((true, format!("Kayıt açılamadı ({file}): {error:#}")));
            }
        }
    }

    fn commit_report(&mut self, path: Option<PathBuf>, report: Box<Report>) {
        if self.candidate_path != path {
            self.candidate_path = None;
            self.candidates.clear();
            self.process_search.clear();
        }
        self.path = path;
        self.report = Some(report);
        self.timeline = Timeline::default();
        self.view = View::Overview;
        self.message = None;
    }

    fn load_demo(&mut self) {
        match demo_report() {
            Ok(report) => self.commit_report(None, Box::new(report)),
            Err(error) => self.message = Some((true, format!("Örnek kayıt açılamadı: {error:#}"))),
        }
    }

    fn visible_path(&self) -> Option<&std::path::Path> {
        match self.view {
            View::Start => None,
            View::ChooseProcess => self.candidate_path.as_deref(),
            _ => self.path.as_deref(),
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
        self.message = Some(match save_report(report, &path) {
            Ok(()) => (false, format!("Rapor kaydedildi: {}", path.display())),
            Err(error) => (true, format!("Rapor kaydedilemedi: {error:#}")),
        });
    }
}

impl eframe::App for Workspace {
    fn on_exit(&mut self) {
        if let Some(pending) = &self.pending {
            pending.cancelled.store(true, Ordering::Relaxed);
            let _ = pending
                .result
                .recv_timeout(std::time::Duration::from_millis(500));
        }
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        self.keyboard_actions(ctx);
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
                    if let Some(pending) = &self.pending {
                        ui.spinner();
                        if pending.cancelled.load(Ordering::Relaxed) {
                            ui.label("İptal ediliyor");
                        } else {
                            ui.label("Kayıt analiz ediliyor");
                            if ui.small_button("İptal").on_hover_text("Esc").clicked() {
                                pending.cancelled.store(true, Ordering::Relaxed);
                            }
                        }
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
                                .visible_path()
                                .and_then(|path| path.file_name())
                                .map(|name| name.to_string_lossy())
                                .unwrap_or_else(|| {
                                    if self.view != View::Start
                                        && self.report.is_some()
                                        && self.path.is_none()
                                    {
                                        "Yerleşik örnek".into()
                                    } else {
                                        "Henüz kayıt yok".into()
                                    }
                                });
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
                        View::Overview if self.report.is_some() => {
                            egui::ScrollArea::vertical()
                                .id_salt("report-overview")
                                .auto_shrink([false, false])
                                .show(ui, |ui| self.overview(ui));
                        }
                        View::Timeline if self.report.is_some() => {
                            let report = self.report.as_ref().expect("view has a report");
                            panel_heading(ui, "Olay zaman çizelgesi");
                            panel(SURFACE, 14, 12).show(ui, |ui| {
                                timeline(ui, report, &mut self.timeline);
                            });
                        }
                        View::Processes if self.report.is_some() => {
                            let report = self.report.as_ref().expect("view has a report");
                            panel_heading(ui, "Süreçler");
                            if let Some(guid) = processes(ui, report) {
                                self.timeline = Timeline {
                                    process: Some(guid),
                                    ..Timeline::default()
                                };
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
        if let (Some((guid, expected_hash)), Some(path)) = (selected, self.candidate_path.clone()) {
            self.start_job(ctx, path, move |path, cancelled| {
                let report = sysmon::convert(path, &guid, cancelled)?;
                anyhow::ensure!(
                    report.sample_sha256 == expected_hash,
                    "selected process no longer matches the EVTX process list"
                );
                Ok(Loaded::Report(Box::new(report)))
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
                    if ui
                        .add_enabled(self.pending.is_none(), egui::Button::new("ÖRNEK KAYDI AÇ"))
                        .clicked()
                    {
                        self.load_demo();
                    }
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
                    .on_hover_text("Ctrl+S")
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
                if self.path.is_some() {
                    ui.label(
                        RichText::new(format!("SHA-256  {}", report.sample_sha256))
                            .monospace()
                            .color(MUTED),
                    );
                } else {
                    ui.label(RichText::new("Sentetik örnek · SHA-256 yer tutucu").color(MUTED));
                }
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
                ui.strong("Kayıt kapsamı");
                ui.add_space(6.0);
                ui.label(RichText::new("Toplamanın eksiksiz olup olmadığı bilinmiyor. Sıfır, bu kayıtta ilgili olayın görünmediğini belirtir.").color(MUTED));
                ui.add_space(6.0);
                for kind in EventKind::ALL {
                    let count = report.coverage.observed_kind_counts[kind.key()];
                    ui.horizontal(|ui| {
                        ui.label(event_label(kind));
                        ui.label(RichText::new(count.to_string()).monospace().color(if count > 0 { ACCENT } else { MUTED }));
                    });
                }
                ui.add_space(6.0);
                ui.label(format!("Başlangıç olayı olmayan süreç: {}", report.coverage.processes_without_start));
                ui.label(format!("Üst süreci kayıtta olmayan süreç: {}", report.coverage.processes_with_unseen_parent));
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
        .on_hover_text("Ctrl+O")
        .clicked()
    {
        workspace.pick_capture(ctx);
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

fn timeline(ui: &mut egui::Ui, report: &Report, timeline: &mut Timeline) {
    let mut reset_scroll = false;
    ui.horizontal_wrapped(|ui| {
        let previous = timeline.kind;
        egui::ComboBox::from_id_salt("event-kind")
            .width(160.0)
            .selected_text(timeline.kind.map(event_label).unwrap_or("Tüm olay türleri"))
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut timeline.kind, None, "Tüm olay türleri");
                for event in EventKind::ALL {
                    ui.selectable_value(&mut timeline.kind, Some(event), event_label(event));
                }
            });
        reset_scroll |= previous != timeline.kind;
        let search = ui.add(
            egui::TextEdit::singleline(&mut timeline.query)
                .hint_text("Olay ayrıntılarında ara")
                .char_limit(160)
                .desired_width(204.0),
        );
        if std::mem::take(&mut timeline.focus_search) {
            search.request_focus();
        }
        reset_scroll |= search.changed();
        if !timeline.query.is_empty() && ui.small_button("Aramayı temizle").clicked() {
            timeline.query.clear();
            reset_scroll = true;
        }
        if let Some(guid) = timeline.process.as_ref() {
            ui.label(RichText::new(guid.as_str()).monospace());
            if ui.small_button("Süreç filtresini kaldır").clicked() {
                timeline.process = None;
                reset_scroll = true;
            }
        }
    });
    if reset_scroll {
        timeline.selected = None;
    }
    let query = timeline.query.trim().to_lowercase();
    let visible: Vec<_> = report
        .events
        .iter()
        .enumerate()
        .filter(|(_, event)| timeline_matches(event, timeline, &query))
        .collect();
    ui.label(
        RichText::new(format!("{} / {} olay", visible.len(), report.events.len())).color(MUTED),
    );
    if let Some(index) = timeline.selected
        && let Some(event) = report.events.get(index)
    {
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.strong(event_label(event.kind));
                if ui.small_button("Kapat").clicked() {
                    timeline.selected = None;
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
    let mut scroll = egui::ScrollArea::vertical()
        .id_salt((
            "timeline",
            timeline.kind.map(EventKind::key),
            timeline.process.as_deref(),
        ))
        .auto_shrink([false, false]);
    if reset_scroll {
        scroll = scroll.vertical_scroll_offset(0.0);
    }
    scroll.show_rows(ui, 24.0, visible.len(), |ui, rows| {
        for (index, event) in &visible[rows] {
            let label = format!(
                "{}    {}    {}",
                event.timestamp,
                event_label(event.kind),
                event.detail
            );
            let button = egui::Button::new(label)
                .selected(timeline.selected == Some(*index))
                .truncate();
            if ui.add_sized([ui.available_width(), 24.0], button).clicked() {
                timeline.selected = Some(*index);
            }
        }
    });
}

fn timeline_matches(event: &crate::Event, timeline: &Timeline, query: &str) -> bool {
    timeline.kind.is_none_or(|kind| kind == event.kind)
        && timeline
            .process
            .as_ref()
            .is_none_or(|guid| event.process_guid.as_ref() == Some(guid))
        && (query.is_empty()
            || event.detail.to_lowercase().contains(query)
            || event
                .process_guid
                .as_ref()
                .is_some_and(|guid| guid.contains(query))
            || event.kind.key().contains(query))
}

fn processes(ui: &mut egui::Ui, report: &Report) -> Option<String> {
    let mut filter = None;
    if report.processes.is_empty() {
        ui.label("Bu kayıtta süreç kimliği bulunamadı.");
        return None;
    }
    egui::ScrollArea::vertical()
        .id_salt("process-list")
        .show(ui, |ui| {
            for (guid, depth) in process_tree(report) {
                let process = &report.processes[guid];
                panel(SURFACE, 14, 10).show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.horizontal_top(|ui| {
                        ui.add_space(12.0 * depth.min(6) as f32);
                        ui.vertical(|ui| {
                            ui.horizontal_wrapped(|ui| {
                                if depth > 0 {
                                    ui.colored_label(ACCENT, "└");
                                }
                                ui.strong(
                                    process
                                        .image
                                        .as_deref()
                                        .unwrap_or("Yürütülebilir dosya bilinmiyor"),
                                );
                                if ui.small_button("Olayları göster").clicked() {
                                    filter = Some(guid.to_owned());
                                }
                            });
                            ui.label(RichText::new(guid).monospace().color(MUTED));
                            if let Some(parent) = &process.parent_process_guid {
                                let title = if report.processes.contains_key(parent) {
                                    "Üst süreç"
                                } else {
                                    "Üst süreç kayıtta yok"
                                };
                                ui.label(
                                    RichText::new(format!("{title}  {parent}"))
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
                            if depth > 6 {
                                ui.label(
                                    RichText::new(format!("Ağaç derinliği {depth}")).color(MUTED),
                                );
                            }
                        });
                    });
                });
            }
        });
    filter
}

fn process_tree(report: &Report) -> Vec<(&str, usize)> {
    let mut roots = Vec::new();
    let mut children = BTreeMap::<&str, Vec<&str>>::new();
    for (guid, process) in &report.processes {
        match process.parent_process_guid.as_deref() {
            Some(parent) if report.processes.contains_key(parent) => {
                children.entry(parent).or_default().push(guid);
            }
            _ => roots.push(guid.as_str()),
        }
    }

    let mut rows = Vec::with_capacity(report.processes.len());
    let mut pending: Vec<_> = roots.into_iter().rev().map(|guid| (guid, 0)).collect();
    // The analyzer rejects ancestry cycles. An explicit stack bounds call depth.
    while let Some((guid, depth)) = pending.pop() {
        rows.push((guid, depth));
        if let Some(branch) = children.get(guid) {
            pending.extend(branch.iter().rev().map(|child| (*child, depth + 1)));
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_f_opens_the_timeline_and_focuses_search() {
        let capture = serde_json::from_str(include_str!("../examples/capture.json")).unwrap();
        let report = analyze(capture).unwrap();
        let mut workspace = Workspace::default();
        workspace.finish_load("sample.json".into(), Ok(Loaded::Report(Box::new(report))));
        let ctx = egui::Context::default();
        let _ = ctx.run(
            egui::RawInput {
                modifiers: egui::Modifiers::CTRL,
                events: vec![egui::Event::Key {
                    key: egui::Key::F,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: egui::Modifiers::CTRL,
                }],
                ..Default::default()
            },
            |ctx| workspace.keyboard_actions(ctx),
        );
        assert!(workspace.view == View::Timeline);
        assert!(workspace.timeline.focus_search);
    }

    #[test]
    fn invalid_import_preserves_the_current_report_and_filters() {
        let mut workspace = Workspace::default();
        let capture = serde_json::from_str(include_str!("../examples/capture.json")).unwrap();
        workspace.finish_load(
            "valid.json".into(),
            Ok(Loaded::Report(Box::new(analyze(capture).unwrap()))),
        );
        workspace.view = View::Timeline;
        workspace.timeline.query = "example.org".into();

        workspace.finish_load(
            "invalid.evtx".into(),
            Err(anyhow::anyhow!("invalid event log")),
        );

        assert_eq!(
            workspace.visible_path(),
            Some(std::path::Path::new("valid.json"))
        );
        assert!(workspace.view == View::Timeline);
        assert_eq!(workspace.timeline.query, "example.org");
        assert!(workspace.report.is_some());
        assert!(
            workspace
                .message
                .as_ref()
                .is_some_and(|(error, text)| *error && text.contains("invalid.evtx"))
        );
    }

    #[test]
    fn a_cancelled_import_does_not_commit_a_late_result() {
        let capture = serde_json::from_str(include_str!("../examples/capture.json")).unwrap();
        let (sender, receiver) = mpsc::channel();
        sender
            .send(Ok(Loaded::Report(Box::new(analyze(capture).unwrap()))))
            .unwrap();
        let mut workspace = Workspace {
            pending: Some(PendingLoad {
                path: "cancelled.json".into(),
                result: receiver,
                cancelled: Arc::new(AtomicBool::new(true)),
            }),
            ..Workspace::default()
        };
        workspace.poll();
        assert!(workspace.report.is_none());
        assert!(workspace.path.is_none());
        assert!(workspace.pending.is_none());
    }

    #[test]
    fn selecting_a_new_evtx_does_not_relabel_the_previous_report() {
        let mut workspace = Workspace::default();
        let capture = serde_json::from_str(include_str!("../examples/capture.json")).unwrap();
        workspace.finish_load(
            "valid.json".into(),
            Ok(Loaded::Report(Box::new(analyze(capture).unwrap()))),
        );
        workspace.finish_load("new.evtx".into(), Ok(Loaded::Processes(Vec::new())));
        assert_eq!(
            workspace.visible_path(),
            Some(std::path::Path::new("new.evtx"))
        );
        workspace.view = View::Overview;
        assert_eq!(
            workspace.visible_path(),
            Some(std::path::Path::new("valid.json"))
        );
        assert!(workspace.report.is_some());
    }

    #[test]
    fn shows_parents_before_children_and_keeps_external_parents_as_roots() {
        let capture = serde_json::from_str(include_str!("../examples/capture.json")).unwrap();
        let mut report = analyze(capture).unwrap();
        let root = "11111111-1111-1111-1111-111111111111";
        let child = "22222222-2222-2222-2222-222222222222";
        assert_eq!(process_tree(&report), [(root, 0), (child, 1)]);

        report.processes.remove(root);
        assert_eq!(process_tree(&report), [(child, 0)]);
    }

    #[test]
    fn combines_text_event_kind_and_process_filters() {
        let capture = serde_json::from_str(include_str!("../examples/capture.json")).unwrap();
        let report = analyze(capture).unwrap();
        let dns = report
            .events
            .iter()
            .find(|event| event.kind == EventKind::DnsQuery)
            .unwrap();
        let mut view = Timeline {
            kind: Some(EventKind::DnsQuery),
            process: dns.process_guid.clone(),
            ..Timeline::default()
        };
        assert!(timeline_matches(dns, &view, "example.org"));
        assert!(!timeline_matches(dns, &view, "other.example"));
        view.kind = Some(EventKind::FileWrite);
        assert!(!timeline_matches(dns, &view, "example.org"));
        view.kind = None;
        view.process = Some("11111111-1111-1111-1111-111111111111".into());
        assert!(!timeline_matches(dns, &view, "example.org"));
    }
}
