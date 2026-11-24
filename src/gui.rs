use std::{
    collections::{BTreeMap, HashSet},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, TryRecvError},
    },
};

use anyhow::Result;
use eframe::egui::{self, Color32, RichText, Stroke, Vec2};
use time::Duration;

use crate::{EventKind, Report, analyze, demo_report, read_recording, save_report};

mod compare;
mod csv;
mod language;
mod preferences;
mod sysmon;

mod theme;

use language::Language;
use theme::{Palette, Theme};

#[derive(Default, PartialEq, Eq)]
enum View {
    #[default]
    Start,
    ChooseProcess,
    Overview,
    Timeline,
    Processes,
    Compare,
}

impl View {
    fn label(&self, lang: Language) -> &'static str {
        match self {
            Self::Start => lang.text("Başlangıç", "Start"),
            Self::ChooseProcess => lang.text("Başlangıç süreci", "Root process"),
            Self::Overview => lang.text("Genel Bakış", "Overview"),
            Self::Timeline => lang.text("Zaman Çizelgesi", "Timeline"),
            Self::Processes => lang.text("Süreçler", "Processes"),
            Self::Compare => lang.text("Karşılaştırma", "Compare"),
        }
    }

    fn group(&self, lang: Language) -> &'static str {
        match self {
            Self::Start | Self::ChooseProcess | Self::Overview => lang.text("Analiz", "Analysis"),
            Self::Timeline | Self::Processes | Self::Compare => lang.text("İnceleme", "Review"),
        }
    }
}

#[derive(Default)]
struct Workspace {
    theme: Theme,
    language: Language,
    mask: Option<egui::TextureHandle>,
    header_mask: Option<egui::TextureHandle>,
    path: Option<PathBuf>,
    report: Option<Box<Report>>,
    comparison: Option<Comparison>,
    pending: Option<PendingLoad>,
    candidate_path: Option<PathBuf>,
    candidates: Vec<sysmon::Candidate>,
    process_search: String,
    process_tree_search: String,
    message: Option<(bool, String)>,
    view: View,
    timeline: Timeline,
}

#[derive(Default)]
struct Timeline {
    kind: Option<EventKind>,
    process: Option<String>,
    query: String,
    from_seconds: String,
    to_seconds: String,
    selected: Option<usize>,
    detail_copied: bool,
    focus_search: bool,
    newest_first: bool,
    marked: HashSet<usize>,
    only_marked: bool,
}

impl Timeline {
    fn focus_process(&mut self, guid: &str) {
        self.process = Some(guid.to_owned());
        self.kind = None;
        self.query.clear();
        self.from_seconds.clear();
        self.to_seconds.clear();
        self.only_marked = false;
    }
}

struct ElapsedRange {
    from: Option<f64>,
    to: Option<f64>,
}

impl ElapsedRange {
    const ALL: Self = Self {
        from: None,
        to: None,
    };

    fn parse(from: &str, to: &str, lang: Language) -> Result<Self, &'static str> {
        let seconds = |value: &str| match value.trim() {
            "" => Ok(None),
            value => value
                .replace(',', ".")
                .parse::<f64>()
                .ok()
                .filter(|n| n.is_finite() && *n >= 0.0)
                .map(Some)
                .ok_or(lang.text(
                    "Süreyi sıfır veya pozitif bir sayı olarak gir.",
                    "Enter a number of seconds greater than or equal to zero.",
                )),
        };
        let from = seconds(from)?;
        let to = seconds(to)?;
        if let (Some(from), Some(to)) = (from, to)
            && from > to
        {
            return Err(lang.text(
                "Başlangıç, bitişten sonra olamaz.",
                "The start time must be at or before the end time.",
            ));
        }
        Ok(Self { from, to })
    }

    fn contains(&self, elapsed: f64) -> bool {
        self.from.is_none_or(|from| elapsed >= from) && self.to.is_none_or(|to| elapsed <= to)
    }
}

fn elapsed_label(elapsed: Duration, lang: Language) -> String {
    let seconds = elapsed.whole_seconds();
    let nanoseconds = elapsed.subsec_nanoseconds();
    let unit = lang.text("sn", "s");
    if nanoseconds == 0 {
        return format!("+{seconds} {unit}");
    }
    let fraction = format!("{nanoseconds:09}");
    let separator = lang.text(",", ".");
    format!(
        "+{seconds}{separator}{} {unit}",
        fraction.trim_end_matches('0')
    )
}

enum Loaded {
    Report(Box<Report>),
    Processes(Vec<sysmon::Candidate>),
    Comparison(Box<Report>),
}

struct Comparison {
    path: PathBuf,
    report: Box<Report>,
    event_review: Option<compare::EventReview>,
    changed_only: bool,
}

struct PendingLoad {
    path: PathBuf,
    result: Receiver<Result<Loaded>>,
    cancelled: Arc<AtomicBool>,
}

pub(crate) fn run(path: Option<PathBuf>, demo: bool) -> Result<()> {
    let mask = eframe::icon_data::from_png_bytes(include_bytes!("../assets/vespdex-mask.png"))?;
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
            .with_inner_size([1220.0, 720.0])
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
            let theme = Theme::load();
            theme.palette().apply(&cc.egui_ctx);
            cc.egui_ctx.style_mut(|style| {
                style.spacing.item_spacing = Vec2::new(8.0, 6.0);
                style.spacing.button_padding = Vec2::new(11.0, 5.0);
            });
            let texture = cc.egui_ctx.load_texture(
                "vespdex-mask",
                egui::ColorImage {
                    size: [mask.width as usize, mask.height as usize],
                    pixels: mask
                        .rgba
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .map(|pixel| Color32::from_white_alpha(pixel[1]))
                        .collect(),
                },
                egui::TextureOptions::LINEAR,
            );
            let header_texture = cc.egui_ctx.load_texture(
                "vespdex-header-mask",
                header_mask_image(&mask),
                egui::TextureOptions::LINEAR,
            );
            let mut workspace = Workspace {
                theme,
                language: Language::load(),
                mask: Some(texture),
                header_mask: Some(header_texture),
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

fn header_mask_image(mask: &egui::IconData) -> egui::ColorImage {
    // The source has broad black margins and dots smaller than one header pixel.
    // Crop to the supplied figure and keep the strongest dot in each output cell.
    let [left, top, right, bottom] = [54, 16, 256, 265];
    let [width, height] = [35, 43];
    let stride = mask.width as usize * 4;
    let mut image = egui::ColorImage::new([width, height], Color32::TRANSPARENT);
    for y in 0..height {
        let source_y = top + y * (bottom - top) / height;
        let next_y = top + (y + 1) * (bottom - top) / height;
        for x in 0..width {
            let source_x = left + x * (right - left) / width;
            let next_x = left + (x + 1) * (right - left) / width;
            let mut green = 0;
            for row in source_y..next_y {
                for column in source_x..next_x {
                    green = green.max(mask.rgba[row * stride + column * 4 + 1]);
                }
            }
            image.pixels[y * width + x] = Color32::from_white_alpha(green);
        }
    }
    image
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
        let lang = self.language;
        if let Some(path) = rfd::FileDialog::new()
            .add_filter(
                lang.text(
                    "Telemetri kayıtları ve raporlar",
                    "Telemetry captures and reports",
                ),
                &["json", "evtx"],
            )
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
                read_recording(path)
                    .and_then(analyze)
                    .map(Box::new)
                    .map(Loaded::Report)
            }
        });
    }

    fn pick_comparison(&mut self, ctx: &egui::Context) {
        let lang = self.language;
        if let Some(path) = rfd::FileDialog::new()
            .add_filter(
                lang.text(
                    "Davranış raporu veya telemetri JSON",
                    "Behavior report or telemetry JSON",
                ),
                &["json"],
            )
            .pick_file()
        {
            self.start_job(ctx, path, |path, _| {
                read_recording(path)
                    .and_then(analyze)
                    .map(Box::new)
                    .map(Loaded::Comparison)
            });
        }
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
        let lang = self.language;
        let Some(pending) = &self.pending else { return };
        let result = match pending.result.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => Err(anyhow::anyhow!(lang.text(
                "Analiz işlemi beklenmedik şekilde kapandı.",
                "The analysis worker exited unexpectedly."
            ))),
        };
        let pending = self.pending.take().expect("finished load is present");
        if pending.cancelled.load(Ordering::Relaxed) {
            self.message = Some((
                false,
                lang.text(
                    "Kayıt açma iptal edildi.",
                    "Opening the recording was cancelled.",
                )
                .into(),
            ));
        } else {
            self.finish_load(pending.path, result);
        }
    }

    fn finish_load(&mut self, path: PathBuf, result: Result<Loaded>) {
        let lang = self.language;
        match result {
            Ok(Loaded::Report(report)) => self.commit_report(Some(path), report),
            Ok(Loaded::Comparison(report)) => {
                self.comparison = Some(Comparison {
                    path,
                    report,
                    event_review: None,
                    changed_only: false,
                });
                self.view = View::Compare;
            }
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
                let label = lang.text("Kayıt açılamadı", "Could not open the recording");
                self.message = Some((true, format!("{label} ({file}): {error:#}")));
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
        self.comparison = None;
        self.timeline = Timeline::default();
        self.process_tree_search.clear();
        self.view = View::Overview;
        self.message = None;
    }

    fn load_demo(&mut self) {
        let lang = self.language;
        match demo_report() {
            Ok(report) => self.commit_report(None, Box::new(report)),
            Err(error) => {
                let label = lang.text("Örnek kayıt açılamadı", "Could not open the example");
                self.message = Some((true, format!("{label}: {error:#}")));
            }
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
        let lang = self.language;
        let Some(report) = &self.report else { return };
        let Some(path) = rfd::FileDialog::new()
            .add_filter("JSON", &["json"])
            .set_file_name("behavior.json")
            .save_file()
        else {
            return;
        };
        self.message = Some(match save_report(report, &path) {
            Ok(()) => (
                false,
                format!(
                    "{}: {}",
                    lang.text("Rapor kaydedildi", "Report saved"),
                    path.display()
                ),
            ),
            Err(error) => (
                true,
                format!(
                    "{}: {error:#}",
                    lang.text("Rapor kaydedilemedi", "Could not save the report")
                ),
            ),
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
        let mut selected_theme = self.theme;
        let lang = self.language;
        let mut selected_language = lang;
        let palette = self.theme.palette();
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
            .frame(palette.panel(palette.bg, 22, 10))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    palette.panel(palette.surface, 8, 4).show(ui, |ui| {
                        if let Some(mask) = &self.header_mask {
                            ui.add(
                                egui::Image::new((mask.id(), Vec2::new(23.0, 28.0)))
                                    .tint(palette.accent),
                            );
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 0.0;
                        ui.strong(RichText::new("Vesp").size(24.0));
                        ui.label(
                            RichText::new("Dex")
                                .size(24.0)
                                .strong()
                                .color(palette.accent),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                                .small()
                                .monospace()
                                .color(palette.muted),
                        );
                        ui.add_space(8.0);
                        open_button(ui, self, ctx);
                        egui::ComboBox::from_id_salt("workspace-theme")
                            .selected_text(self.theme.label())
                            .width(112.0)
                            .show_ui(ui, |ui| {
                                for theme in Theme::ALL {
                                    ui.selectable_value(&mut selected_theme, theme, theme.label());
                                }
                            })
                            .response
                            .on_hover_text(lang.text("Tema", "Theme"));
                        ui.label(RichText::new(lang.text("Tema", "Theme")).color(palette.muted));
                        egui::ComboBox::from_id_salt("workspace-language")
                            .selected_text(lang.label())
                            .width(78.0)
                            .show_ui(ui, |ui| {
                                for language in [Language::Turkish, Language::English] {
                                    ui.selectable_value(
                                        &mut selected_language,
                                        language,
                                        language.label(),
                                    );
                                }
                            })
                            .response
                            .on_hover_text("Dil / Language");
                    });
                });
            });
        egui::TopBottomPanel::bottom("status")
            .frame(palette.panel(palette.bg, 22, 5))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if let Some(pending) = &self.pending {
                        ui.spinner();
                        if pending.cancelled.load(Ordering::Relaxed) {
                            ui.label(lang.text("İptal ediliyor", "Cancelling"));
                        } else {
                            ui.label(lang.text("Kayıt analiz ediliyor", "Analyzing recording"));
                            if ui
                                .small_button(lang.text("İptal", "Cancel"))
                                .on_hover_text("Esc")
                                .clicked()
                            {
                                pending.cancelled.store(true, Ordering::Relaxed);
                            }
                        }
                    } else if let Some((error, message)) = &self.message {
                        ui.colored_label(
                            if *error {
                                palette.error
                            } else {
                                palette.accent
                            },
                            message,
                        );
                    } else {
                        ui.label(RichText::new("●").small().color(palette.accent));
                        ui.label(
                            RichText::new(lang.text("Yerel analiz", "Local analysis"))
                                .small()
                                .monospace()
                                .color(palette.muted),
                        );
                    }
                });
            });
        egui::SidePanel::left("navigation")
            .resizable(false)
            .exact_width(206.0)
            .frame(palette.panel(palette.surface, 12, 22).corner_radius(0))
            .show(ctx, |ui| {
                ui.label(
                    RichText::new(lang.text("ANALİZ", "ANALYSIS"))
                        .small()
                        .monospace()
                        .color(palette.muted),
                );
                nav(ui, &mut self.view, View::Start, true, palette, lang);
                if !self.candidates.is_empty() {
                    nav(ui, &mut self.view, View::ChooseProcess, true, palette, lang);
                }
                nav(
                    ui,
                    &mut self.view,
                    View::Overview,
                    self.report.is_some(),
                    palette,
                    lang,
                );
                ui.add_space(18.0);
                ui.label(
                    RichText::new(lang.text("İNCELEME", "REVIEW"))
                        .small()
                        .monospace()
                        .color(palette.muted),
                );
                nav(
                    ui,
                    &mut self.view,
                    View::Timeline,
                    self.report.is_some(),
                    palette,
                    lang,
                );
                nav(
                    ui,
                    &mut self.view,
                    View::Processes,
                    self.report.is_some(),
                    palette,
                    lang,
                );
                nav(
                    ui,
                    &mut self.view,
                    View::Compare,
                    self.report.is_some(),
                    palette,
                    lang,
                );
            });

        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(palette.bg))
            .show(ctx, |ui| {
                palette
                    .panel(palette.surface, 24, 11)
                    .corner_radius(0)
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            let available = ui.available_width();
                            ui.label(
                                RichText::new(self.view.group(lang))
                                    .small()
                                    .color(palette.muted),
                            );
                            ui.label(RichText::new("/").color(palette.muted));
                            ui.strong(self.view.label(lang));
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    let name = self
                                        .visible_path()
                                        .and_then(|path| path.file_name())
                                        .map(|name| name.to_string_lossy())
                                        .unwrap_or_else(|| {
                                            if self.view != View::Start
                                                && self.report.is_some()
                                                && self.path.is_none()
                                            {
                                                lang.text("Yerleşik örnek", "Built-in example")
                                                    .into()
                                            } else {
                                                lang.text("Henüz kayıt yok", "No recording open")
                                                    .into()
                                            }
                                        });
                                    ui.allocate_ui_with_layout(
                                        egui::vec2((available * 0.44).min(330.0), 20.0),
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            ui.add(
                                                egui::Label::new(
                                                    RichText::new(name)
                                                        .monospace()
                                                        .size(12.0)
                                                        .color(palette.accent_soft),
                                                )
                                                .truncate(),
                                            );
                                        },
                                    );
                                },
                            );
                        });
                    });
                egui::Frame::new()
                    .inner_margin(egui::Margin::symmetric(24, 22))
                    .show(ui, |ui| match self.view {
                        View::Start => {
                            egui::ScrollArea::vertical()
                                .id_salt("start")
                                .auto_shrink([false, false])
                                .show(ui, |ui| self.start(ui, ctx));
                        }
                        View::ChooseProcess => self.choose_process(ui, ctx),
                        View::Overview if self.report.is_some() => {
                            egui::ScrollArea::vertical()
                                .id_salt("report-overview")
                                .auto_shrink([false, false])
                                .show(ui, |ui| self.overview(ui));
                        }
                        View::Timeline if self.report.is_some() => {
                            let report = self.report.as_ref().expect("view has a report");
                            panel_heading(ui, lang.text("Olay zaman çizelgesi", "Event timeline"));
                            let export_status = palette
                                .panel(palette.surface, 16, 14)
                                .show(ui, |ui| {
                                    timeline(ui, report, &mut self.timeline, palette, lang)
                                })
                                .inner;
                            if let Some(status) = export_status {
                                self.message = Some(status);
                            }
                        }
                        View::Processes if self.report.is_some() => {
                            let report = self.report.as_ref().expect("view has a report");
                            panel_heading(ui, lang.text("Süreçler", "Processes"));
                            if let Some(guid) =
                                processes(ui, report, &mut self.process_tree_search, palette, lang)
                            {
                                self.timeline.focus_process(&guid);
                                self.timeline.selected = None;
                                self.timeline.detail_copied = false;
                                self.view = View::Timeline;
                            }
                        }
                        View::Compare if self.report.is_some() => {
                            self.compare_reports(ui, ctx, palette);
                        }
                        _ => self.start(ui, ctx),
                    });
            });
        if selected_theme != self.theme {
            self.theme = selected_theme;
            selected_theme.palette().apply(ctx);
            if let Err(error) = selected_theme.save() {
                let label = lang.text(
                    "Tema tercihi kaydedilemedi",
                    "Could not save the theme preference",
                );
                self.message = Some((true, format!("{label}: {error}")));
            }
            ctx.request_repaint();
        }
        if selected_language != lang {
            self.language = selected_language;
            self.message = selected_language.save().err().map(|error| {
                (
                    true,
                    format!(
                        "{}: {error}",
                        selected_language.text(
                            "Dil tercihi kaydedilemedi",
                            "Could not save the language preference"
                        )
                    ),
                )
            });
            ctx.request_repaint();
        }
    }
}

impl Workspace {
    fn compare_reports(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, palette: Palette) {
        let lang = self.language;
        panel_heading(
            ui,
            lang.text(
                "Davranış kayıtlarını karşılaştır",
                "Compare behavior recordings",
            ),
        );
        let available = self.pending.is_none();
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    available,
                    egui::Button::new(
                        lang.text("İkinci JSON kaydını aç", "Open second JSON recording"),
                    ),
                )
                .clicked()
            {
                self.pick_comparison(ctx);
            }
            if self.comparison.is_some()
                && ui
                    .add_enabled(
                        available,
                        egui::Button::new(
                            lang.text("İkinci kaydı kaldır", "Remove second recording"),
                        ),
                    )
                    .clicked()
            {
                self.comparison = None;
                self.message = None;
            }
        });
        let Some(comparison) = &mut self.comparison else {
            ui.label(lang.text(
                "Olay sayılarını ve kayıt kapsamını görmek için ikinci bir kayıt seç.",
                "Select a second recording to compare event counts and coverage.",
            ));
            return;
        };
        let base = self.report.as_ref().expect("comparison view has a report");
        egui::ScrollArea::vertical()
            .id_salt("comparison")
            .show(ui, |ui| {
                compare::show(ui, base, self.path.as_deref(), comparison, palette, lang);
            });
    }

    fn choose_process(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let lang = self.language;
        let palette = self.theme.palette();
        panel_heading(
            ui,
            lang.text("Başlangıç sürecini seç", "Select the root process"),
        );
        ui.label(RichText::new(lang.text("Sysmon tarafından SHA-256 değeri kaydedilmiş süreçler. Seçilen süreç ve alt süreçleri rapora girer.", "Sysmon recorded SHA-256 hashes for these processes. The report includes the selected process and its descendants.")).color(palette.muted));
        ui.add_space(8.0);
        ui.add(
            egui::TextEdit::singleline(&mut self.process_search)
                .hint_text(lang.text(
                    "Dosya adı, süreç GUID veya SHA-256 ile ara",
                    "Search filename, process GUID or SHA-256",
                ))
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
                "{} / {} {}",
                entries.len(),
                self.candidates.len(),
                lang.text("süreç", "processes"),
            ))
            .color(palette.muted),
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

    fn paint_mask(&self, ui: &mut egui::Ui, bounds: egui::Rect) {
        if let Some(mask) = &self.mask {
            let dimensions = mask.size_vec2();
            let scale = (bounds.width() / dimensions.x).min(bounds.height() / dimensions.y);
            ui.painter().image(
                mask.id(),
                egui::Rect::from_center_size(bounds.center(), dimensions * scale),
                egui::Rect::from_min_max(egui::Pos2::ZERO, egui::pos2(1.0, 1.0)),
                self.theme.palette().accent,
            );
        }
    }

    fn start(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let lang = self.language;
        let palette = self.theme.palette();
        ui.add_space(10.0);
        let dragging = ctx.input(|input| !input.raw.hovered_files.is_empty());
        let edge = if dragging {
            palette.accent
        } else {
            palette.line_hot
        };
        palette
            .panel(palette.surface, 26, 24)
            .stroke(Stroke::new(1.0_f32, edge))
            .show(ui, |ui| {
                let width = ui.available_width();
                ui.set_min_width(width);
                ui.horizontal(|ui| {
                    let art_width = (width * 0.42).max(124.0);
                    let copy_width = width - art_width - 22.0;
                    ui.allocate_ui_with_layout(
                        egui::vec2(copy_width, 244.0),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            ui.set_width(copy_width);
                            ui.add_space(38.0);
                            ui.label(
                                RichText::new("JSON / SYSMON EVTX")
                                    .monospace()
                                    .size(12.0)
                                    .color(palette.accent_soft),
                            );
                            ui.label(
                                RichText::new(
                                    lang.text("Telemetri kaydı aç", "Open a telemetry recording"),
                                )
                                .size(32.0)
                                .strong(),
                            );
                            ui.label(
                                RichText::new(lang.text(
                                    "Bir kayıt seç veya dosyayı bu alana bırak.",
                                    "Choose a recording or drop a file here.",
                                ))
                                .color(palette.muted),
                            );
                            ui.add_space(12.0);
                            ui.horizontal_wrapped(|ui| {
                                open_button(ui, self, ctx);
                                if ui
                                    .add_enabled(
                                        self.pending.is_none(),
                                        egui::Button::new(
                                            lang.text("Örnek kaydı aç", "Open example"),
                                        )
                                        .min_size(Vec2::new(0.0, 36.0)),
                                    )
                                    .clicked()
                                {
                                    self.load_demo();
                                }
                            });
                        },
                    );
                    ui.add_space(6.0);
                    let (rect, _) =
                        ui.allocate_exact_size(egui::vec2(art_width, 244.0), egui::Sense::hover());
                    let painter = ui.painter_at(rect);
                    painter.rect(
                        rect,
                        2,
                        palette.bg,
                        Stroke::new(1.0_f32, palette.line),
                        egui::StrokeKind::Inside,
                    );
                    let center = rect.center();
                    let radius = (art_width * 0.36).min(97.0);
                    let grid = palette.line.gamma_multiply(0.58);
                    for y in ((rect.top() as i32 + 12)..(rect.bottom() as i32 - 8)).step_by(16) {
                        for x in ((rect.left() as i32 + 12)..(rect.right() as i32 - 8)).step_by(16)
                        {
                            painter.circle_filled(egui::pos2(x as f32, y as f32), 0.7, grid);
                        }
                    }
                    for ring in [radius * 0.78, radius] {
                        painter.circle_stroke(center, ring, Stroke::new(1.0_f32, palette.line));
                    }
                    let tick = Stroke::new(1.0_f32, edge);
                    for axis in [egui::Vec2::X, egui::Vec2::Y] {
                        for sign in [-1.0, 1.0] {
                            painter.line_segment(
                                [
                                    center + axis * sign * (radius - 5.0),
                                    center + axis * sign * (radius + 8.0),
                                ],
                                tick,
                            );
                        }
                    }
                    let mask_rect =
                        egui::Rect::from_center_size(center, egui::Vec2::splat(radius * 1.35));
                    self.paint_mask(ui, mask_rect);
                });
            });
    }

    fn overview(&mut self, ui: &mut egui::Ui) {
        let lang = self.language;
        let palette = self.theme.palette();
        let mut export = false;
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(lang.text("Davranış özeti", "Behavior overview"))
                    .size(26.0)
                    .strong(),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                export = ui
                    .button(
                        RichText::new(lang.text("Raporu kaydet", "Save report"))
                            .color(palette.accent_soft),
                    )
                    .on_hover_text("Ctrl+S")
                    .clicked();
            });
        });
        ui.add_space(14.0);
        if let Some(report) = &self.report {
            ui.columns(3, |columns| {
                metric(
                    &mut columns[0],
                    lang.text("Kayıtlı olay", "Recorded events"),
                    report.events.len(),
                    palette,
                );
                metric(
                    &mut columns[1],
                    lang.text("Süreç", "Processes"),
                    report.processes.len(),
                    palette,
                );
                metric(
                    &mut columns[2],
                    lang.text("Süreci belirsiz olay", "Unattributed events"),
                    report.unattributed_event_count,
                    palette,
                );
            });
            ui.add_space(12.0);
            let mut open_timeline = false;
            let mut information = |ui: &mut egui::Ui| {
                palette.panel(palette.surface, 16, 14).show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.strong(lang.text("Kayıt bilgileri", "Recording information"));
                    ui.add_space(8.0);
                    ui.label(format!("{}  {}", lang.text("Vaka", "Case"), report.case_id));
                    ui.label(format!(
                        "{}  {}",
                        lang.text("Kaynak", "Source"),
                        report.source
                    ));
                    let is_demo = report.source == "synthetic-demo"
                        && report.sample_sha256.bytes().all(|byte| byte == b'0');
                    if !is_demo {
                        ui.horizontal(|ui| {
                            let copy = ui
                                .small_button("SHA-256")
                                .on_hover_text(lang.text("SHA-256 kopyala", "Copy SHA-256"));
                            if copy.clicked() {
                                ui.ctx().copy_text(report.sample_sha256.clone());
                            }
                            ui.add(
                                egui::Label::new(
                                    RichText::new(&report.sample_sha256)
                                        .monospace()
                                        .color(palette.muted),
                                )
                                .truncate(),
                            )
                            .on_hover_text(&report.sample_sha256);
                        });
                    } else {
                        ui.label(
                            RichText::new(lang.text(
                                "Sentetik örnek · SHA-256 yer tutucu",
                                "Synthetic example · placeholder SHA-256",
                            ))
                            .color(palette.muted),
                        );
                    }
                    if let Some(window) = &report.capture_window {
                        ui.label(
                            RichText::new(format!(
                                "{}  {} – {}",
                                lang.text("Gözlem", "Observation"),
                                window.start,
                                window.end
                            ))
                            .color(palette.muted),
                        );
                    }
                    ui.add_space(10.0);
                    open_timeline = ui
                        .button(
                            RichText::new(lang.text("Zaman çizelgesini aç", "Open timeline"))
                                .color(palette.accent_soft),
                        )
                        .clicked();
                });
            };
            let coverage = |ui: &mut egui::Ui| {
                palette.panel(palette.surface, 16, 14).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.strong(lang.text("Kayıt kapsamı", "Recording coverage"));
                ui.add_space(6.0);
                ui.label(RichText::new(lang.text("Toplamanın eksiksiz olup olmadığı bilinmiyor. Sıfır, bu kayıtta ilgili olayın görünmediğini belirtir.", "Recording completeness is unknown. A zero means this event type was absent from the recording.")).color(palette.muted));
                ui.add_space(10.0);
                let max_count = report
                    .coverage
                    .observed_kind_counts
                    .values()
                    .copied()
                    .max()
                    .unwrap_or(0)
                    .max(1);
                for kind in EventKind::ALL {
                    let count = report.coverage.observed_kind_counts[kind.key()];
                    ui.horizontal(|ui| {
                        ui.add_sized([150.0, 24.0], egui::Label::new(event_label(kind, lang)));
                        let (track, _) = ui.allocate_exact_size(
                            egui::vec2((ui.available_width() - 95.0).clamp(48.0, 430.0), 4.0),
                            egui::Sense::hover(),
                        );
                        ui.painter().rect_filled(track, 1, palette.line);
                        if count > 0 {
                            let fill = egui::Rect::from_min_size(
                                track.min,
                                egui::vec2(track.width() * count as f32 / max_count as f32, 4.0),
                            );
                            ui.painter().rect_filled(fill, 1, palette.accent);
                        }
                        ui.label(RichText::new(count.to_string()).monospace().color(
                            if count > 0 { palette.accent_soft } else { palette.muted },
                        ));
                    });
                }
                ui.separator();
                ui.add_space(6.0);
                ui.label(format!("{}: {}", lang.text("Başlangıç olayı olmayan süreç", "Processes without a recorded start"), report.coverage.processes_without_start));
                ui.label(format!("{}: {}", lang.text("Üst süreci kayıtta olmayan süreç", "Processes whose parent is absent"), report.coverage.processes_with_unseen_parent));
                });
            };
            if ui.available_width() >= 820.0 {
                ui.columns(2, |columns| {
                    information(&mut columns[0]);
                    coverage(&mut columns[1]);
                });
            } else {
                information(ui);
                ui.add_space(12.0);
                coverage(ui);
            }
            if open_timeline {
                self.view = View::Timeline;
            }
        }
        if export {
            self.export();
        }
    }
}

fn panel_heading(ui: &mut egui::Ui, title: &str) {
    ui.label(RichText::new(title).size(28.0).strong());
    ui.add_space(10.0);
}

fn open_button(ui: &mut egui::Ui, workspace: &mut Workspace, ctx: &egui::Context) {
    let palette = workspace.theme.palette();
    let lang = workspace.language;
    let button = egui::Button::new(
        RichText::new(lang.text("Dosya seç", "Open file"))
            .color(palette.bg)
            .strong(),
    )
    .fill(palette.accent)
    .min_size(Vec2::new(116.0, 36.0));
    if ui
        .add_enabled(workspace.pending.is_none(), button)
        .on_hover_text("Ctrl+O")
        .clicked()
    {
        workspace.pick_capture(ctx);
    }
}

fn nav(
    ui: &mut egui::Ui,
    current: &mut View,
    destination: View,
    enabled: bool,
    palette: Palette,
    lang: Language,
) {
    let selected = *current == destination;
    let text_color = if selected {
        palette.accent_soft
    } else {
        palette.text
    };
    let button = egui::Button::new(RichText::new(destination.label(lang)).color(text_color))
        .selected(selected)
        .fill(if selected {
            palette.active
        } else {
            Color32::TRANSPARENT
        })
        .min_size(Vec2::new(ui.available_width(), 34.0));
    let response = ui
        .scope(|ui| {
            ui.spacing_mut().button_padding.x = 27.0;
            ui.visuals_mut().widgets.inactive.bg_stroke = Stroke::NONE;
            ui.add_enabled(enabled, button)
        })
        .inner;
    if selected {
        let rect = response.rect;
        ui.painter().line_segment(
            [rect.left_top(), rect.left_bottom()],
            Stroke::new(2.0_f32, palette.accent),
        );
    }
    let center = egui::pos2(response.rect.left() + 14.0, response.rect.center().y);
    let icon_color = if selected {
        palette.accent
    } else {
        palette.muted
    };
    nav_icon(
        ui,
        &destination,
        center,
        if enabled {
            icon_color
        } else {
            icon_color.gamma_multiply(0.5)
        },
    );
    if response.clicked() {
        *current = destination;
    }
}

fn nav_icon(ui: &egui::Ui, view: &View, center: egui::Pos2, color: Color32) {
    let painter = ui.painter();
    let stroke = Stroke::new(1.3_f32, color);
    let point = |x, y| center + egui::vec2(x, y);
    let line = |points: &[(f32, f32)]| {
        painter.add(egui::Shape::line(
            points.iter().map(|&(x, y)| point(x, y)).collect(),
            stroke,
        ));
    };
    match view {
        View::Start => line(&[
            (-6.0, 1.0),
            (0.0, -5.0),
            (6.0, 1.0),
            (4.0, 1.0),
            (4.0, 6.0),
            (-4.0, 6.0),
            (-4.0, 1.0),
            (-6.0, 1.0),
        ]),
        View::Overview => {
            for x in [-4.0, 4.0] {
                for y in [-4.0, 4.0] {
                    painter.rect_stroke(
                        egui::Rect::from_center_size(point(x, y), egui::Vec2::splat(5.0)),
                        0,
                        stroke,
                        egui::StrokeKind::Inside,
                    );
                }
            }
        }
        View::ChooseProcess | View::Processes => {
            line(&[(0.0, -3.0), (0.0, 1.0), (-5.0, 1.0), (-5.0, 3.0)]);
            line(&[(0.0, 1.0), (5.0, 1.0), (5.0, 3.0)]);
            for (x, y) in [(0.0, -5.0), (-5.0, 5.0), (5.0, 5.0)] {
                painter.circle_stroke(point(x, y), 2.0, stroke);
            }
        }
        View::Timeline => {
            painter.circle_stroke(center, 6.0, stroke);
            line(&[(0.0, -3.0), (0.0, 0.0), (3.0, 2.0)]);
        }
        View::Compare => {
            line(&[(-6.0, -3.0), (6.0, -3.0), (3.0, -6.0)]);
            line(&[(6.0, 3.0), (-6.0, 3.0), (-3.0, 6.0)]);
        }
    }
}

fn metric(ui: &mut egui::Ui, label: &str, number: usize, palette: Palette) {
    let card = palette.panel(palette.surface, 16, 13).show(ui, |ui| {
        ui.set_min_size(egui::vec2(ui.available_width(), 70.0));
        ui.label(
            RichText::new(number.to_string())
                .monospace()
                .size(32.0)
                .color(palette.text),
        );
        ui.label(RichText::new(label).color(palette.muted));
    });
    let corner = card.response.rect.left_top() + egui::vec2(1.0, 1.0);
    ui.painter().line_segment(
        [corner, corner + egui::vec2(38.0, 0.0)],
        Stroke::new(2.0_f32, palette.accent),
    );
}

fn event_label(kind: EventKind, lang: Language) -> &'static str {
    match kind {
        EventKind::ProcessStart => lang.text("Süreç başlangıcı", "Process start"),
        EventKind::FileWrite => lang.text("Dosya yazma", "File write"),
        EventKind::RegistryWrite => lang.text("Kayıt defteri", "Registry write"),
        EventKind::NetworkConnection => lang.text("Ağ bağlantısı", "Network connection"),
        EventKind::DnsQuery => lang.text("DNS sorgusu", "DNS query"),
    }
}

fn timeline(
    ui: &mut egui::Ui,
    report: &Report,
    timeline: &mut Timeline,
    palette: Palette,
    lang: Language,
) -> Option<(bool, String)> {
    let mut reset_scroll = false;
    let initial_order = timeline.newest_first;
    ui.horizontal_wrapped(|ui| {
        let previous = timeline.kind;
        egui::ComboBox::from_id_salt("event-kind")
            .width(160.0)
            .selected_text(
                timeline
                    .kind
                    .map(|kind| event_label(kind, lang))
                    .unwrap_or(lang.text("Tüm olay türleri", "All event types")),
            )
            .show_ui(ui, |ui| {
                ui.selectable_value(
                    &mut timeline.kind,
                    None,
                    lang.text("Tüm olay türleri", "All event types"),
                );
                for event in EventKind::ALL {
                    ui.selectable_value(&mut timeline.kind, Some(event), event_label(event, lang));
                }
            });
        reset_scroll |= previous != timeline.kind;
        let search = ui.add(
            egui::TextEdit::singleline(&mut timeline.query)
                .hint_text(lang.text("Olay veya süreç ara", "Search events or processes"))
                .char_limit(160)
                .desired_width(204.0),
        );
        if std::mem::take(&mut timeline.focus_search) {
            search.request_focus();
        }
        reset_scroll |= search.changed();
        if !timeline.query.is_empty()
            && ui
                .small_button(lang.text("Aramayı temizle", "Clear search"))
                .clicked()
        {
            timeline.query.clear();
            reset_scroll = true;
        }
        if let Some(guid) = timeline.process.as_ref() {
            let name = process_image(report, guid)
                .and_then(|path| path.rsplit(['\\', '/']).next())
                .unwrap_or(guid);
            ui.label(RichText::new(name).monospace())
                .on_hover_text(guid);
            if ui
                .small_button(lang.text("Süreç filtresini kaldır", "Clear process filter"))
                .clicked()
            {
                timeline.process = None;
                reset_scroll = true;
            }
        }
        egui::ComboBox::from_id_salt("event-order")
            .width(120.0)
            .selected_text(if timeline.newest_first {
                lang.text("Yeniden eskiye", "Newest first")
            } else {
                lang.text("Eskiden yeniye", "Oldest first")
            })
            .show_ui(ui, |ui| {
                ui.selectable_value(
                    &mut timeline.newest_first,
                    false,
                    lang.text("Eskiden yeniye", "Oldest first"),
                );
                ui.selectable_value(
                    &mut timeline.newest_first,
                    true,
                    lang.text("Yeniden eskiye", "Newest first"),
                );
            });
        reset_scroll |= ui
            .checkbox(
                &mut timeline.only_marked,
                lang.text("Yalnızca işaretliler", "Marked only"),
            )
            .changed();
    });
    ui.horizontal_wrapped(|ui| {
        ui.label(lang.text("İlk olaydan itibaren (sn)", "Seconds since the first event"));
        reset_scroll |= ui
            .add(
                egui::TextEdit::singleline(&mut timeline.from_seconds)
                    .hint_text(lang.text("Başlangıç", "Start"))
                    .char_limit(24)
                    .desired_width(84.0),
            )
            .changed();
        reset_scroll |= ui
            .add(
                egui::TextEdit::singleline(&mut timeline.to_seconds)
                    .hint_text(lang.text("Bitiş", "End"))
                    .char_limit(24)
                    .desired_width(84.0),
            )
            .changed();
        if (!timeline.from_seconds.is_empty() || !timeline.to_seconds.is_empty())
            && ui
                .small_button(lang.text("Aralığı temizle", "Clear time range"))
                .clicked()
        {
            timeline.from_seconds.clear();
            timeline.to_seconds.clear();
            reset_scroll = true;
        }
        if let Some(last) = report.events.last() {
            ui.label(
                RichText::new(format!(
                    "{} {}",
                    lang.text("Son olay", "Last event"),
                    elapsed_label(last.elapsed, lang)
                ))
                .small()
                .color(palette.muted),
            );
        }
    });
    if reset_scroll {
        timeline.selected = None;
        timeline.detail_copied = false;
    }
    let range = match ElapsedRange::parse(&timeline.from_seconds, &timeline.to_seconds, lang) {
        Ok(range) => range,
        Err(error) => {
            ui.colored_label(palette.error, error);
            return None;
        }
    };
    let mut visible = visible_timeline_events(report, timeline, &range);
    let order_changed = initial_order != timeline.newest_first;
    let side_by_side = ui.available_width() >= 800.0
        && timeline
            .selected
            .is_some_and(|index| timeline_row(&visible, index).is_some());
    let layout = if side_by_side {
        egui::Layout::right_to_left(egui::Align::Min)
    } else {
        egui::Layout::top_down(egui::Align::Min)
    };
    ui.with_layout(layout, |ui| {
        let update = event_inspector(ui, report, timeline, &visible, palette, lang, side_by_side);
        if update.process_changed {
            visible = visible_timeline_events(report, timeline, &ElapsedRange::ALL);
        } else if update.marks_changed {
            visible = visible_timeline_events(report, timeline, &range);
        }
        let scroll_to_row = if order_changed || update.process_changed {
            timeline
                .selected
                .and_then(|index| timeline_row(&visible, index))
        } else {
            update.scroll_to_row
        }
        .or_else(|| (reset_scroll || order_changed || update.process_changed).then_some(0));
        ui.allocate_ui_with_layout(
            ui.available_size(),
            egui::Layout::top_down(egui::Align::Min),
            |ui| timeline_list(ui, report, timeline, &visible, palette, lang, scroll_to_row),
        )
        .inner
    })
    .inner
}

#[derive(Default)]
struct InspectorUpdate {
    scroll_to_row: Option<usize>,
    process_changed: bool,
    marks_changed: bool,
}

fn event_inspector(
    ui: &mut egui::Ui,
    report: &Report,
    timeline: &mut Timeline,
    visible: &[(usize, &crate::Event)],
    palette: Palette,
    lang: Language,
    side_by_side: bool,
) -> InspectorUpdate {
    let mut update = InspectorUpdate::default();
    let Some(row) = timeline
        .selected
        .and_then(|index| timeline_row(visible, index))
    else {
        return update;
    };
    let width = if side_by_side {
        (ui.available_width() * 0.35).clamp(300.0, 390.0)
    } else {
        ui.available_width()
    };
    let detail_height = if side_by_side {
        (ui.available_height() * 0.45).clamp(95.0, 280.0)
    } else {
        95.0
    };
    ui.allocate_ui_with_layout(
        egui::vec2(width, 0.0),
        egui::Layout::top_down(egui::Align::Min),
        |ui| {
            ui.set_width(width);
            palette.panel(palette.active, 13, 10).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.strong(lang.text("Olay ayrıntısı", "Event details"));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button(lang.text("Kapat", "Close")).clicked() {
                            timeline.selected = None;
                            timeline.detail_copied = false;
                        }
                    });
                });
                ui.separator();
                let row = ui
                    .horizontal_wrapped(|ui| {
                        let previous = ui
                            .add_enabled(
                                row > 0,
                                egui::Button::new(lang.text("Önceki", "Previous")),
                            )
                            .clicked();
                        let next = ui
                            .add_enabled(
                                row + 1 < visible.len(),
                                egui::Button::new(lang.text("Sonraki", "Next")),
                            )
                            .clicked();
                        let selected = if previous {
                            row - 1
                        } else if next {
                            row + 1
                        } else {
                            row
                        };
                        ui.label(
                            RichText::new(format!("{} / {}", selected + 1, visible.len()))
                                .monospace()
                                .color(palette.muted),
                        );
                        if selected != row {
                            timeline.selected = Some(visible[selected].0);
                            timeline.detail_copied = false;
                            update.scroll_to_row = Some(selected);
                        }
                        selected
                    })
                    .inner;
                let (index, event) = visible[row];
                ui.label(
                    RichText::new(event_label(event.kind, lang))
                        .size(18.0)
                        .color(palette.accent_soft)
                        .strong(),
                );
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(elapsed_label(event.elapsed, lang)).monospace());
                    ui.label(
                        RichText::new(&event.timestamp)
                            .monospace()
                            .color(palette.muted),
                    );
                    if let Some(guid) = &event.process_guid {
                        if let Some(image) = process_image(report, guid) {
                            let name = image.rsplit(['\\', '/']).next().unwrap_or(image);
                            ui.label(RichText::new(name).strong()).on_hover_text(image);
                        }
                        ui.label(
                            RichText::new(format!("{}  {guid}", lang.text("Süreç", "Process")))
                                .monospace()
                                .color(palette.muted),
                        );
                        if ui
                            .small_button(
                                lang.text("Bu sürecin olayları", "Show this process's events"),
                            )
                            .on_hover_text(lang.text(
                                "Arama, tür, süre ve işaret filtrelerini temizler.",
                                "Clears search, type, time, and marked-only filters.",
                            ))
                            .clicked()
                        {
                            timeline.focus_process(guid);
                            update.process_changed = true;
                        }
                    }
                });
                ui.separator();
                egui::ScrollArea::vertical()
                    .id_salt(("event-detail", index))
                    .max_height(detail_height)
                    .show(ui, |ui| {
                        ui.add(egui::Label::new(&event.detail).wrap().selectable(true));
                    });
                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    let marked = timeline.marked.contains(&index);
                    if ui
                        .small_button(if marked {
                            lang.text("İşareti kaldır", "Unmark")
                        } else {
                            lang.text("İşaretle", "Mark for review")
                        })
                        .clicked()
                    {
                        if marked {
                            timeline.marked.remove(&index);
                        } else {
                            timeline.marked.insert(index);
                        }
                        if timeline.only_marked {
                            timeline.selected = None;
                            timeline.detail_copied = false;
                            update.marks_changed = true;
                        }
                    }
                    let copy_label = if timeline.detail_copied {
                        lang.text("Kopyalandı", "Copied")
                    } else {
                        lang.text("Ayrıntıyı kopyala", "Copy details")
                    };
                    if ui.small_button(copy_label).clicked() {
                        ui.ctx().copy_text(event.detail.clone());
                        timeline.detail_copied = true;
                    }
                });
            });
        },
    );
    update
}

fn timeline_list(
    ui: &mut egui::Ui,
    report: &Report,
    timeline: &mut Timeline,
    visible: &[(usize, &crate::Event)],
    palette: Palette,
    lang: Language,
    scroll_to_row: Option<usize>,
) -> Option<(bool, String)> {
    ui.add_space(4.0);
    ui.separator();
    let mut export = false;
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!(
                "{} / {} {}",
                visible.len(),
                report.events.len(),
                lang.text("olay", "events")
            ))
            .small()
            .monospace()
            .color(palette.muted),
        );
        if !timeline.marked.is_empty() {
            ui.label(
                RichText::new(format!(
                    "{} {}",
                    timeline.marked.len(),
                    lang.text("işaretli", "marked")
                ))
                .small()
                .color(palette.muted),
            );
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            export = ui
                .add_enabled(
                    !visible.is_empty(),
                    egui::Button::new(
                        lang.text("Görünen olayları CSV kaydet", "Save visible events as CSV"),
                    ),
                )
                .on_hover_text(lang.text(
                    "Etkin filtrelere uyan olayların tamamını kaydeder.",
                    "Exports all events that match the active filters.",
                ))
                .clicked();
        });
    });
    if visible.is_empty() {
        ui.label(lang.text(
            "Bu filtreyle eşleşen olay yok.",
            "No events match these filters.",
        ));
        return None;
    }
    let status = if export {
        csv::export(report, visible.iter().map(|(_, event)| *event), lang)
    } else {
        None
    };
    let mut scroll = egui::ScrollArea::vertical()
        .id_salt((
            "timeline",
            timeline.kind.map(EventKind::key),
            timeline.process.as_deref(),
        ))
        .auto_shrink([false, false]);
    const ROW_HEIGHT: f32 = 37.0;
    if let Some(row) = scroll_to_row {
        scroll =
            scroll.vertical_scroll_offset(row as f32 * (ROW_HEIGHT + ui.spacing().item_spacing.y));
    }
    scroll.show_rows(ui, ROW_HEIGHT, visible.len(), |ui, rows| {
        let mono = egui::FontId::monospace(12.0);
        let body = egui::FontId::proportional(14.0);
        let compact = ui.available_width() < 620.0;
        for (row, (index, event)) in visible[rows.clone()].iter().enumerate() {
            let mut label = egui::text::LayoutJob::default();
            let elapsed = elapsed_label(event.elapsed, lang);
            let prefix = if timeline.marked.contains(index) {
                format!("★  {elapsed}")
            } else {
                elapsed
            };
            let kind = event_label(event.kind, lang);
            let column_gap = |width: f32, text: &str, font: &egui::FontId| {
                let used = ui.fonts(|fonts| {
                    fonts
                        .layout_no_wrap(text.to_owned(), font.clone(), palette.text)
                        .size()
                        .x
                });
                (width - used).max(12.0)
            };
            label.append(
                &prefix,
                0.0,
                egui::TextFormat {
                    font_id: mono.clone(),
                    color: palette.accent_soft,
                    ..Default::default()
                },
            );
            if !compact {
                label.append(
                    &event.timestamp,
                    column_gap(78.0, &prefix, &mono),
                    egui::TextFormat {
                        font_id: mono.clone(),
                        color: palette.muted,
                        ..Default::default()
                    },
                );
            }
            label.append(
                kind,
                if compact {
                    column_gap(78.0, &prefix, &mono)
                } else {
                    column_gap(218.0, &event.timestamp, &mono)
                },
                egui::TextFormat {
                    font_id: body.clone(),
                    color: palette.accent_soft,
                    ..Default::default()
                },
            );
            label.append(
                &event.detail,
                column_gap(132.0, kind, &body),
                egui::TextFormat {
                    font_id: body.clone(),
                    color: palette.text,
                    ..Default::default()
                },
            );
            let selected = timeline.selected == Some(*index);
            let button = egui::Button::new(label)
                .selected(selected)
                .min_size(Vec2::new(ui.available_width(), ROW_HEIGHT))
                .truncate();
            let response = ui
                .scope(|ui| {
                    if !selected {
                        let inactive = &mut ui.visuals_mut().widgets.inactive;
                        inactive.bg_stroke = Stroke::NONE;
                        inactive.weak_bg_fill = if (rows.start + row) % 2 == 0 {
                            palette.bg
                        } else {
                            palette.surface
                        };
                    }
                    ui.add(button)
                })
                .inner;
            if response.clicked() {
                timeline.selected = Some(*index);
                timeline.detail_copied = false;
            }
        }
    });
    status
}

fn visible_timeline_events<'a>(
    report: &'a Report,
    timeline: &Timeline,
    range: &ElapsedRange,
) -> Vec<(usize, &'a crate::Event)> {
    let query = timeline.query.trim().to_lowercase();
    let mut events = report
        .events
        .iter()
        .enumerate()
        .filter(|(index, event)| {
            (!timeline.only_marked || timeline.marked.contains(index))
                && range.contains(event.elapsed.as_seconds_f64())
                && timeline_matches(event, report, timeline, &query)
        })
        .collect::<Vec<_>>();
    if timeline.newest_first {
        events.reverse();
    }
    events
}

fn timeline_row(events: &[(usize, &crate::Event)], index: usize) -> Option<usize> {
    events.iter().position(|(candidate, _)| *candidate == index)
}

fn process_image<'a>(report: &'a Report, guid: &str) -> Option<&'a str> {
    report.processes.get(guid)?.image.as_deref()
}

fn timeline_matches(
    event: &crate::Event,
    report: &Report,
    timeline: &Timeline,
    query: &str,
) -> bool {
    timeline.kind.is_none_or(|kind| kind == event.kind)
        && timeline
            .process
            .as_ref()
            .is_none_or(|guid| event.process_guid.as_ref() == Some(guid))
        && (query.is_empty()
            || event.detail.to_lowercase().contains(query)
            || event.process_guid.as_ref().is_some_and(|guid| {
                guid.contains(query)
                    || process_image(report, guid)
                        .is_some_and(|image| image.to_lowercase().contains(query))
            })
            || event.kind.key().contains(query))
}

fn processes(
    ui: &mut egui::Ui,
    report: &Report,
    search: &mut String,
    palette: Palette,
    lang: Language,
) -> Option<String> {
    let mut filter = None;
    if report.processes.is_empty() {
        ui.label(lang.text(
            "Bu kayıtta süreç kimliği bulunamadı.",
            "No processes could be identified in this recording.",
        ));
        return None;
    }
    let mut reset_scroll = false;
    ui.horizontal_wrapped(|ui| {
        reset_scroll = ui
            .add(
                egui::TextEdit::singleline(search)
                    .hint_text(lang.text(
                        "Dosya adı, yol veya süreç GUID ile ara",
                        "Search by file name, path, or process GUID",
                    ))
                    .char_limit(160)
                    .desired_width(310.0),
            )
            .changed();
        if !search.is_empty()
            && ui
                .small_button(lang.text("Aramayı temizle", "Clear search"))
                .clicked()
        {
            search.clear();
            reset_scroll = true;
        }
    });
    let query = search.trim().to_lowercase();
    let tree = process_tree(report);
    let matches = matching_processes(report, &query);
    let visible = visible_processes(report, &matches);
    ui.label(
        RichText::new(format!(
            "{} / {} {}",
            matches.len(),
            tree.len(),
            lang.text("süreç", "processes")
        ))
        .small()
        .monospace()
        .color(palette.muted),
    );
    if matches.is_empty() {
        ui.label(lang.text(
            "Bu aramayla eşleşen süreç yok.",
            "No processes match this search.",
        ));
        return None;
    }
    let mut scroll = egui::ScrollArea::vertical().id_salt("process-list");
    if reset_scroll {
        scroll = scroll.vertical_scroll_offset(0.0);
    }
    scroll.show(ui, |ui| {
        for (guid, depth) in tree {
            if !visible.contains(guid) {
                continue;
            }
            let process = &report.processes[guid];
            palette.panel(palette.surface, 14, 10).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal_top(|ui| {
                    ui.add_space(12.0 * depth.min(6) as f32);
                    ui.vertical(|ui| {
                        ui.horizontal_wrapped(|ui| {
                            if depth > 0 {
                                ui.colored_label(palette.accent, "└");
                            }
                            ui.strong(process.image.as_deref().unwrap_or(
                                lang.text("Yürütülebilir dosya bilinmiyor", "Unknown executable"),
                            ));
                            if !matches.contains(guid) {
                                ui.label(
                                    RichText::new(lang.text("Üst süreç bağlamı", "Ancestor"))
                                        .small()
                                        .color(palette.muted),
                                );
                            }
                            if ui
                                .small_button(lang.text("Olayları göster", "Show events"))
                                .clicked()
                            {
                                filter = Some(guid.to_owned());
                            }
                        });
                        ui.label(RichText::new(guid).monospace().color(palette.muted));
                        if let Some(parent) = &process.parent_process_guid {
                            let title = if report.processes.contains_key(parent) {
                                lang.text("Üst süreç", "Parent process")
                            } else {
                                lang.text(
                                    "Üst süreç kayıtta yok",
                                    "Parent process absent from recording",
                                )
                            };
                            ui.label(
                                RichText::new(format!("{title}  {parent}"))
                                    .monospace()
                                    .color(palette.muted),
                            );
                        }
                        ui.horizontal_wrapped(|ui| {
                            for event in EventKind::ALL {
                                if let Some(count) = process.counts.get(event.key()) {
                                    ui.label(format!("{} {count}", event_label(event, lang)));
                                }
                            }
                        });
                        if depth > 6 {
                            ui.label(
                                RichText::new(format!(
                                    "{} {depth}",
                                    lang.text("Ağaç derinliği", "Tree depth")
                                ))
                                .color(palette.muted),
                            );
                        }
                    });
                });
            });
        }
    });
    filter
}

fn matching_processes<'a>(report: &'a Report, query: &str) -> HashSet<&'a str> {
    report
        .processes
        .iter()
        .filter(|(guid, process)| {
            guid.contains(query)
                || process
                    .image
                    .as_ref()
                    .is_some_and(|image| image.to_lowercase().contains(query))
        })
        .map(|(guid, _)| guid.as_str())
        .collect()
}

fn visible_processes<'a>(report: &'a Report, matches: &HashSet<&'a str>) -> HashSet<&'a str> {
    let mut visible = matches.clone();
    for guid in matches {
        let mut parent = report.processes[*guid].parent_process_guid.as_deref();
        while let Some(guid) = parent {
            let Some(process) = report.processes.get(guid) else {
                break;
            };
            if !visible.insert(guid) {
                break;
            }
            parent = process.parent_process_guid.as_deref();
        }
    }
    visible
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
    fn comparison_loads_separately_and_failed_replacements_keep_the_pair() {
        let mut workspace = Workspace::default();
        workspace.load_demo();
        workspace.timeline.query = "example.org".into();

        let mut other = demo_report().unwrap();
        other.case_id = "second-case".into();
        workspace.finish_load(
            "second.json".into(),
            Ok(Loaded::Comparison(Box::new(other))),
        );
        let comparison = workspace.comparison.as_ref().unwrap();
        assert_eq!(comparison.path, PathBuf::from("second.json"));
        assert_eq!(comparison.report.case_id, "second-case");
        assert_eq!(workspace.report.as_ref().unwrap().case_id, "demo-001");
        assert_eq!(workspace.timeline.query, "example.org");
        assert!(workspace.view == View::Compare);

        workspace.finish_load("invalid.json".into(), Err(anyhow::anyhow!("invalid JSON")));
        assert_eq!(
            workspace.comparison.as_ref().unwrap().report.case_id,
            "second-case"
        );
        let (sender, receiver) = mpsc::channel();
        sender
            .send(Ok(Loaded::Comparison(Box::new(demo_report().unwrap()))))
            .unwrap();
        workspace.pending = Some(PendingLoad {
            path: "cancelled.json".into(),
            result: receiver,
            cancelled: Arc::new(AtomicBool::new(true)),
        });
        workspace.poll();
        assert_eq!(
            workspace.comparison.as_ref().unwrap().report.case_id,
            "second-case"
        );
        workspace.load_demo();
        assert!(workspace.comparison.is_none());
        assert!(workspace.view == View::Overview);
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
    fn process_search_keeps_ancestors_and_excludes_unrelated_processes() {
        let mut report = demo_report().unwrap();
        let root = "11111111-1111-1111-1111-111111111111";
        let child = "22222222-2222-2222-2222-222222222222";
        let other = "33333333-3333-3333-3333-333333333333";
        report.processes.insert(other.into(), Default::default());

        let matches = matching_processes(&report, "demo-worker.exe");
        assert_eq!(matches, HashSet::from([child]));
        assert_eq!(
            visible_processes(&report, &matches),
            HashSet::from([root, child])
        );
        assert_eq!(matching_processes(&report, "3333"), HashSet::from([other]));

        report.processes.remove(root);
        let matches = matching_processes(&report, "demo-worker.exe");
        assert_eq!(visible_processes(&report, &matches), HashSet::from([child]));
        assert!(matching_processes(&report, "does-not-match").is_empty());
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
        assert!(timeline_matches(dns, &report, &view, "example.org"));
        assert!(timeline_matches(dns, &report, &view, "demo-worker.exe"));
        assert!(!timeline_matches(dns, &report, &view, "other.example"));
        view.kind = Some(EventKind::FileWrite);
        assert!(!timeline_matches(dns, &report, &view, "example.org"));
        view.kind = None;
        view.process = Some("11111111-1111-1111-1111-111111111111".into());
        assert!(!timeline_matches(dns, &report, &view, "example.org"));
    }

    #[test]
    fn focusing_on_the_selected_process_shows_its_full_history() {
        let report = demo_report().unwrap();
        let index = report
            .events
            .iter()
            .position(|event| event.kind == EventKind::DnsQuery)
            .unwrap();
        let guid = report.events[index].process_guid.as_deref().unwrap();
        let mut view = Timeline {
            kind: Some(EventKind::DnsQuery),
            query: "example.org".into(),
            from_seconds: "1".into(),
            to_seconds: "2".into(),
            selected: Some(index),
            ..Timeline::default()
        };
        view.focus_process(guid);
        assert_eq!(view.selected, Some(index));
        assert_eq!(view.process.as_deref(), Some(guid));
        assert!(view.kind.is_none());
        assert!(view.query.is_empty());
        assert!(view.from_seconds.is_empty() && view.to_seconds.is_empty());
        assert_eq!(
            report
                .events
                .iter()
                .filter(|event| timeline_matches(event, &report, &view, &view.query))
                .count(),
            3
        );
    }

    #[test]
    fn elapsed_range_accepts_inclusive_offsets_and_validates_input() {
        let mut capture: serde_json::Value =
            serde_json::from_str(include_str!("../examples/capture.json")).unwrap();
        capture["events"][3]["timestamp"] = "2026-11-21T13:00:00.5+03:00".into();
        let report = analyze(serde_json::from_value(capture).unwrap()).unwrap();
        assert_eq!(report.events[1].elapsed, Duration::milliseconds(500));
        assert_eq!(
            elapsed_label(report.events[1].elapsed, Language::Turkish),
            "+0,5 sn"
        );
        assert_eq!(
            elapsed_label(Duration::nanoseconds(1), Language::Turkish),
            "+0,000000001 sn"
        );
        let range = ElapsedRange::parse("0,5", "1.0", Language::Turkish).unwrap();
        let visible = visible_timeline_events(&report, &Timeline::default(), &range);
        assert_eq!(
            visible.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
            [1, 2]
        );
        assert!(!range.contains(0.499));
        assert!(!range.contains(1.001));
        assert!(
            ElapsedRange::parse("", "0", Language::Turkish)
                .unwrap()
                .contains(0.0)
        );
        assert!(
            ElapsedRange::parse("2", "", Language::Turkish)
                .unwrap()
                .contains(3.0)
        );
        for (from, to) in [
            ("2", "1"),
            ("-1", ""),
            ("NaN", ""),
            ("", "inf"),
            ("1,2.3", ""),
        ] {
            assert!(
                ElapsedRange::parse(from, to, Language::Turkish).is_err(),
                "{from} .. {to}"
            );
        }
    }

    #[test]
    fn english_timeline_translates_actions_events_and_elapsed_time() {
        assert_eq!(View::Overview.label(Language::English), "Overview");
        assert_eq!(View::Compare.label(Language::English), "Compare");
        let report = demo_report().unwrap();
        let ctx = egui::Context::default();
        let mut state = Timeline {
            selected: Some(3),
            ..Timeline::default()
        };
        let frame = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    Vec2::new(970.0, 620.0),
                )),
                ..egui::RawInput::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    timeline(
                        ui,
                        &report,
                        &mut state,
                        Theme::Dark.palette(),
                        Language::English,
                    );
                });
            },
        );
        let positions: Vec<_> = frame
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::epaint::Shape::Text(label) => Some((label.galley.text(), label.pos)),
                _ => None,
            })
            .collect();
        let position = |caption| {
            positions
                .iter()
                .find(|(label, _)| *label == caption)
                .unwrap_or_else(|| panic!("{caption} is missing"))
                .1
        };
        for label in ["Mark for review", "DNS query", "+2 s"] {
            position(label);
        }
        let details = position("Event details");
        let export = position("Save visible events as CSV");
        assert!(details.x > export.x && (details.y - export.y).abs() < 30.0);
        assert_eq!(
            elapsed_label(Duration::milliseconds(500), Language::English),
            "+0.5 s"
        );
        assert_eq!(
            ElapsedRange::parse("2", "1", Language::English).err(),
            Some("The start time must be at or before the end time.")
        );
    }

    #[test]
    fn event_detail_buttons_step_within_the_filtered_timeline() {
        let report = demo_report().unwrap();
        let mut state = Timeline {
            query: "demo-worker.exe".into(),
            from_seconds: "1".into(),
            selected: Some(2),
            detail_copied: true,
            ..Timeline::default()
        };
        let ctx = egui::Context::default();
        let draw = |state: &mut Timeline, events| {
            ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        Vec2::new(780.0, 520.0),
                    )),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        timeline(ui, &report, state, Theme::Dark.palette(), Language::Turkish);
                    });
                },
            )
        };
        let click = |state: &mut Timeline, caption: &str| {
            let frame = draw(state, vec![]);
            let pos = frame
                .shapes
                .iter()
                .find_map(|shape| match &shape.shape {
                    egui::epaint::Shape::Text(text) if text.galley.text() == caption => {
                        Some(text.pos + text.galley.rect.center().to_vec2())
                    }
                    _ => None,
                })
                .unwrap();
            for pressed in [true, false] {
                draw(
                    state,
                    vec![
                        egui::Event::PointerMoved(pos),
                        egui::Event::PointerButton {
                            pos,
                            button: egui::PointerButton::Primary,
                            pressed,
                            modifiers: egui::Modifiers::NONE,
                        },
                    ],
                );
            }
        };
        let narrow = draw(&mut state, vec![]);
        let caption_y = |caption| {
            narrow
                .shapes
                .iter()
                .find_map(|shape| match &shape.shape {
                    egui::epaint::Shape::Text(text) if text.galley.text() == caption => {
                        Some(text.pos.y)
                    }
                    _ => None,
                })
                .unwrap()
        };
        assert!(caption_y("Olay ayrıntısı") < caption_y("Görünen olayları CSV kaydet"));

        click(&mut state, "Önceki");
        assert_eq!(state.selected, Some(2));
        click(&mut state, "Sonraki");
        assert_eq!(state.selected, Some(3));
        assert!(!state.detail_copied);
        click(&mut state, "Sonraki");
        assert_eq!(state.selected, Some(3));
        click(&mut state, "Önceki");
        assert_eq!(state.selected, Some(2));
        assert_eq!(state.query, "demo-worker.exe");
        assert_eq!(state.from_seconds, "1");

        state.newest_first = true;
        click(&mut state, "Sonraki");
        assert_eq!(state.selected, Some(2));
        click(&mut state, "Önceki");
        assert_eq!(state.selected, Some(3));

        click(&mut state, "İşaretle");
        assert_eq!(state.marked, HashSet::from([3]));
        click(&mut state, "Yalnızca işaretliler");
        assert!(state.only_marked);
        let range = ElapsedRange::parse("1", "", Language::Turkish).unwrap();
        let rows = visible_timeline_events(&report, &state, &range);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, 3);
        state.selected = Some(3);
        click(&mut state, "İşareti kaldır");
        assert!(state.marked.is_empty());
        assert!(state.selected.is_none());
        assert!(visible_timeline_events(&report, &state, &range).is_empty());
    }
}
