use std::path::Path;

use eframe::egui::{self, RichText, Vec2};

use crate::{
    EventKind, Report,
    comparison::{Identity, identity},
};

use super::{Comparison, Palette, elapsed_label, event_label, process_image};

pub(super) struct EventReview {
    kind: EventKind,
    selected: [Option<usize>; 2],
}

pub(super) fn show(
    ui: &mut egui::Ui,
    base: &Report,
    base_path: Option<&Path>,
    comparison: &mut Comparison,
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
    let mut focus_events = false;
    palette.panel(palette.surface, 12, 10).show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.strong("Olay ve kapsam farkları");
        ui.label(
            RichText::new("Sayım farkları kaydedilen olayları gösterir. Gözlem aralığı ve Sysmon ayarları sonuçları etkileyebilir.")
                .color(palette.muted),
        );
        ui.checkbox(&mut comparison.changed_only, "Yalnızca sayısı değişen satırlar");
        if comparison.changed_only
            && comparison.event_review.as_ref().is_some_and(|review| {
                let key = review.kind.key();
                base.coverage.observed_kind_counts[key] == other.coverage.observed_kind_counts[key]
            })
        {
            comparison.event_review = None;
        }
        let summaries = [
            ("Süreç", base.processes.len(), other.processes.len()),
            ("Süreci belirsiz olay", base.unattributed_event_count, other.unattributed_event_count),
            ("Başlangıcı görünmeyen süreç", base.coverage.processes_without_start, other.coverage.processes_without_start),
            ("Üst süreci kayıtta yok", base.coverage.processes_with_unseen_parent, other.coverage.processes_with_unseen_parent),
        ];
        let event_rows = EventKind::ALL
            .into_iter()
            .map(|kind| {
                let key = kind.key();
                (kind, base.coverage.observed_kind_counts[key], other.coverage.observed_kind_counts[key])
            })
            .filter(|(_, left, right)| !comparison.changed_only || left != right)
            .collect::<Vec<_>>();
        let summaries = summaries
            .into_iter()
            .filter(|(_, left, right)| !comparison.changed_only || left != right)
            .collect::<Vec<_>>();
        if comparison.changed_only && event_rows.is_empty() && summaries.is_empty() {
            ui.label("Bu kayıtlardaki olay ve süreç sayıları aynı.");
            return;
        }
        egui::Grid::new("comparison-counts")
            .min_col_width(46.0)
            .spacing(Vec2::new(16.0, 6.0))
            .striped(true)
            .show(ui, |ui| {
                for label in ["Ölçüm", "1. kayıt", "2. kayıt", "Fark"] {
                    ui.strong(label);
                }
                ui.end_row();
                if !comparison.changed_only || base.events.len() != other.events.len() {
                    count_row(ui, "Toplam olay", base.events.len(), other.events.len(), palette);
                }
                for (kind, left, right) in event_rows {
                    let active = comparison.event_review.as_ref().is_some_and(|review| review.kind == kind);
                    if ui
                        .selectable_label(active, event_label(kind))
                        .on_hover_text("Bu türdeki olayları iki kayıtta incele")
                        .clicked()
                    {
                        comparison.event_review = (!active).then_some(EventReview {
                            kind,
                            selected: [None; 2],
                        });
                        focus_events = !active;
                    }
                    count_values(
                        ui,
                        left,
                        right,
                        palette,
                    );
                }
                for (label, left, right) in summaries {
                    count_row(ui, label, left, right, palette);
                }
            });
    });
    if let Some(review) = &mut comparison.event_review {
        ui.add_space(8.0);
        let heading = ui.heading(format!("Olaylar · {}", event_label(review.kind)));
        if focus_events {
            heading.scroll_to_me(Some(egui::Align::Min));
        }
        ui.columns(2, |columns| {
            for (side, (column, report)) in
                columns.iter_mut().zip([base, other.as_ref()]).enumerate()
            {
                column.push_id((side, review.kind.key()), |ui| {
                    event_list(
                        ui,
                        report,
                        side,
                        review.kind,
                        &mut review.selected[side],
                        palette,
                    );
                });
            }
        });
    }
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
    count_values(ui, base, other, palette);
}

fn count_values(ui: &mut egui::Ui, base: usize, other: usize, palette: Palette) {
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

fn event_list(
    ui: &mut egui::Ui,
    report: &Report,
    side: usize,
    kind: EventKind,
    selected: &mut Option<usize>,
    palette: Palette,
) {
    let events: Vec<_> = report
        .events
        .iter()
        .enumerate()
        .filter(|(_, event)| event.kind == kind)
        .collect();
    palette.panel(palette.surface, 10, 8).show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.strong(format!("{}. kayıt · {} olay", side + 1, events.len()));
        if events.is_empty() {
            ui.label(RichText::new("Bu türde kayıtlı olay yok.").color(palette.muted));
            return;
        }
        egui::ScrollArea::vertical()
            .id_salt("comparison-event-list")
            .max_height(180.0)
            .show_rows(ui, 28.0, events.len(), |ui, rows| {
                for (index, event) in events[rows].iter().copied() {
                    let label = format!("{}  {}", elapsed_label(event.elapsed), event.detail);
                    let button = egui::Button::new(label)
                        .selected(*selected == Some(index))
                        .min_size(Vec2::new(ui.available_width(), 28.0))
                        .truncate();
                    if ui.add(button).on_hover_text(&event.detail).clicked() {
                        *selected = Some(index);
                    }
                }
            });
        if let Some(event) = selected.and_then(|index| report.events.get(index)) {
            ui.separator();
            ui.add(egui::Label::new(&event.timestamp).wrap().selectable(true));
            if let Some(guid) = &event.process_guid {
                let image = process_image(report, guid).unwrap_or(guid);
                ui.add(egui::Label::new(image).wrap().selectable(true));
            }
            ui.add(egui::Label::new(&event.detail).wrap().selectable(true));
        }
    });
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
    fn comparison_explains_the_recorded_dns_difference_with_events() {
        let base = demo_report().unwrap();
        let mut capture: serde_json::Value =
            serde_json::from_str(include_str!("../../examples/capture.json")).unwrap();
        capture["events"]
            .as_array_mut()
            .unwrap()
            .retain(|event| event["kind"] != "dns-query");
        let mut comparison = Comparison {
            path: "second.json".into(),
            report: Box::new(crate::analyze(serde_json::from_value(capture).unwrap()).unwrap()),
            event_review: None,
            changed_only: false,
        };
        let ctx = egui::Context::default();
        let draw = |comparison: &mut Comparison, events| {
            ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        Vec2::new(550.0, 820.0),
                    )),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        show(
                            ui,
                            &base,
                            None,
                            comparison,
                            crate::gui::Theme::Dark.palette(),
                        );
                    });
                },
            )
        };
        let frame = draw(&mut comparison, vec![]);
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

        let pos = dns.pos + dns.galley.rect.center().to_vec2();
        let mut frame = draw(&mut comparison, vec![]);
        for pressed in [true, false] {
            frame = draw(
                &mut comparison,
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
        let review = comparison.event_review.as_ref().unwrap();
        assert!(review.kind == EventKind::DnsQuery);
        let text: Vec<_> = frame
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::epaint::Shape::Text(label) => Some(label.galley.text()),
                _ => None,
            })
            .collect();
        assert!(text.iter().any(|text| text.contains("example.org")));
        assert!(text.contains(&"Bu türde kayıtlı olay yok."));
        assert!(!text.iter().any(|text| text.contains("demo-output.txt")));

        comparison.changed_only = true;
        let frame = draw(&mut comparison, vec![]);
        let includes = |caption| {
            frame.shapes.iter().any(|shape|
            matches!(&shape.shape, egui::epaint::Shape::Text(text) if text.galley.text() == caption)
        )
        };
        assert!(includes("DNS sorgusu"));
        assert!(!includes("Dosya yazma"));
        assert!(!includes("Süreci belirsiz olay"));

        comparison.report = Box::new(demo_report().unwrap());
        let frame = draw(&mut comparison, vec![]);
        assert!(frame.shapes.iter().any(|shape|
            matches!(&shape.shape, egui::epaint::Shape::Text(text) if text.galley.text() == "Bu kayıtlardaki olay ve süreç sayıları aynı.")
        ));
        assert!(comparison.event_review.is_none());
    }
}
