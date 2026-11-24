use std::path::Path;

use eframe::egui::{self, RichText, Vec2};

use crate::{EventKind, Report};

use super::{Comparison, Palette, event_label};

#[derive(PartialEq, Eq)]
enum Identity {
    Same,
    Different,
    Unknown,
}

fn identity(base: &Report, other: &Report) -> Identity {
    let is_placeholder = |hash: &str| hash.bytes().all(|byte| byte == b'0');
    if is_placeholder(&base.sample_sha256) || is_placeholder(&other.sample_sha256) {
        Identity::Unknown
    } else if base.sample_sha256 == other.sample_sha256 {
        Identity::Same
    } else {
        Identity::Different
    }
}

pub(super) fn show(
    ui: &mut egui::Ui,
    base: &Report,
    base_path: Option<&Path>,
    comparison: &Comparison,
    palette: Palette,
) {
    let other = &comparison.report;
    let file_identity = match identity(base, other) {
        Identity::Same => "Dosya SHA-256 değerleri eşleşiyor.",
        Identity::Different => "Dosya SHA-256 değerleri farklı.",
        Identity::Unknown => {
            "Dosya kimliği belirsiz. Kayıtlardan biri yer tutucu SHA-256 kullanıyor."
        }
    };
    ui.strong(file_identity);
    ui.columns(2, |columns| {
        recording_card(&mut columns[0], "1. Açık kayıt", base_path, base, palette);
        recording_card(
            &mut columns[1],
            "2. Karşılaştırılan kayıt",
            Some(&comparison.path),
            other,
            palette,
        );
    });
    ui.add_space(8.0);
    palette.panel(palette.surface, 12, 10).show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.strong("Olay ve kapsam farkları");
        ui.label(
            RichText::new("Sayım farkları kaydedilen olayları gösterir. Gözlem aralığı ve Sysmon ayarları sonuçları etkileyebilir.")
                .color(palette.muted),
        );
        egui::Grid::new("comparison-counts")
            .min_col_width(46.0)
            .spacing(Vec2::new(16.0, 6.0))
            .striped(true)
            .show(ui, |ui| {
                for label in ["Ölçüm", "1. kayıt", "2. kayıt", "Fark"] {
                    ui.strong(label);
                }
                ui.end_row();
                count_row(ui, "Toplam olay", base.events.len(), other.events.len(), palette);
                for kind in EventKind::ALL {
                    let key = kind.key();
                    count_row(
                        ui,
                        event_label(kind),
                        base.coverage.observed_kind_counts[key],
                        other.coverage.observed_kind_counts[key],
                        palette,
                    );
                }
                count_row(ui, "Süreç", base.processes.len(), other.processes.len(), palette);
                count_row(
                    ui,
                    "Süreci belirsiz olay",
                    base.unattributed_event_count,
                    other.unattributed_event_count,
                    palette,
                );
                count_row(
                    ui,
                    "Başlangıcı görünmeyen süreç",
                    base.coverage.processes_without_start,
                    other.coverage.processes_without_start,
                    palette,
                );
                count_row(
                    ui,
                    "Üst süreci kayıtta yok",
                    base.coverage.processes_with_unseen_parent,
                    other.coverage.processes_with_unseen_parent,
                    palette,
                );
            });
    });
}

fn recording_card(
    ui: &mut egui::Ui,
    title: &str,
    path: Option<&Path>,
    report: &Report,
    palette: Palette,
) {
    palette.panel(palette.surface, 12, 10).show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.strong(title);
        let filename = path
            .and_then(Path::file_name)
            .map(|name| name.to_string_lossy())
            .unwrap_or_else(|| "Yerleşik örnek".into());
        ui.add(egui::Label::new(filename.as_ref()).truncate())
            .on_hover_text(filename);
        for value in [
            format!("Vaka  {}", report.case_id),
            format!("Kaynak  {}", report.source),
            format!("SHA-256  {}", report.sample_sha256),
        ] {
            ui.add(
                egui::Label::new(
                    RichText::new(&value)
                        .small()
                        .monospace()
                        .color(palette.muted),
                )
                .truncate(),
            )
            .on_hover_text(&value);
        }
        if let Some(window) = &report.capture_window {
            ui.label(RichText::new("Gözlem aralığı").small().strong());
            for timestamp in [&window.start, &window.end] {
                ui.add(egui::Label::new(RichText::new(timestamp).small().monospace()).truncate())
                    .on_hover_text(timestamp);
            }
        } else {
            ui.label(
                RichText::new("Gözlem aralığı belirtilmemiş")
                    .small()
                    .color(palette.muted),
            );
        }
    });
}

fn count_row(ui: &mut egui::Ui, label: &str, base: usize, other: usize, palette: Palette) {
    ui.label(label);
    ui.monospace(base.to_string());
    ui.monospace(other.to_string());
    let delta = other as isize - base as isize;
    let value = if delta == 0 {
        "0".to_owned()
    } else {
        format!("{delta:+}")
    };
    let color = if delta == 0 {
        palette.muted
    } else {
        palette.accent_soft
    };
    ui.label(RichText::new(value).monospace().color(color));
    ui.end_row();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo_report;

    #[test]
    fn zero_hashes_do_not_identify_a_sample() {
        let mut base = demo_report().unwrap();
        let mut other = demo_report().unwrap();
        assert!(identity(&base, &other) == Identity::Unknown);
        base.sample_sha256 = "1".repeat(64);
        assert!(identity(&base, &other) == Identity::Unknown);
        other.sample_sha256.clone_from(&base.sample_sha256);
        assert!(identity(&base, &other) == Identity::Same);
        other.sample_sha256 = "2".repeat(64);
        assert!(identity(&base, &other) == Identity::Different);
    }

    #[test]
    fn comparison_renders_the_recorded_dns_difference() {
        let base = demo_report().unwrap();
        let mut capture: serde_json::Value =
            serde_json::from_str(include_str!("../../examples/capture.json")).unwrap();
        capture["events"]
            .as_array_mut()
            .unwrap()
            .retain(|event| event["kind"] != "dns-query");
        let comparison = Comparison {
            path: "second.json".into(),
            report: Box::new(crate::analyze(serde_json::from_value(capture).unwrap()).unwrap()),
        };
        let ctx = egui::Context::default();
        let frame = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    Vec2::new(760.0, 520.0),
                )),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    show(
                        ui,
                        &base,
                        None,
                        &comparison,
                        crate::gui::Theme::Dark.palette(),
                    );
                });
            },
        );
        let labels: Vec<_> = frame
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::epaint::Shape::Text(label) => Some(label),
                _ => None,
            })
            .collect();
        let dns = labels
            .iter()
            .find(|label| label.galley.text() == "DNS sorgusu")
            .unwrap();
        let row: Vec<_> = labels
            .iter()
            .filter(|label| (label.pos.y - dns.pos.y).abs() < 3.0)
            .map(|label| label.galley.text())
            .collect();
        assert_eq!(row, ["DNS sorgusu", "1", "0", "-1"]);
    }
}
