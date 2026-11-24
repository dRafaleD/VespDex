use crate::{Event, Report, save_report_bytes};

use super::{Language, process_image};

pub(super) fn export<'a>(
    report: &Report,
    events: impl Iterator<Item = &'a Event>,
    lang: Language,
) -> Option<(bool, String)> {
    let path = rfd::FileDialog::new()
        .add_filter("CSV", &["csv"])
        .set_file_name("events.csv")
        .save_file()?;
    let bytes = encode(report, events);
    Some(match save_report_bytes(bytes.as_bytes(), &path) {
        Ok(()) => (
            false,
            format!(
                "{}: {}",
                lang.text("CSV kaydedildi", "CSV saved"),
                path.display()
            ),
        ),
        Err(error) => (
            true,
            format!(
                "{}: {error:#}",
                lang.text("CSV kaydedilemedi", "Could not save the CSV")
            ),
        ),
    })
}

fn encode<'a>(report: &Report, events: impl Iterator<Item = &'a Event>) -> String {
    let mut csv =
        String::from("timestamp,kind,process_guid,parent_process_guid,process_image,detail\r\n");
    for event in events {
        let guid = event.process_guid.as_deref().unwrap_or_default();
        let image = process_image(report, guid).unwrap_or_default();
        let fields = [
            &event.timestamp,
            event.kind.key(),
            guid,
            event.parent_process_guid.as_deref().unwrap_or_default(),
            image,
            &event.detail,
        ];
        for (column, field) in fields.iter().enumerate() {
            if column != 0 {
                csv.push(',');
            }
            push_field(&mut csv, field);
        }
        csv.push_str("\r\n");
    }
    csv
}

fn push_field(csv: &mut String, field: &str) {
    csv.push('"');
    // These prefixes can be interpreted as formulas when a CSV opens in a spreadsheet.
    if field
        .trim_start()
        .starts_with(['=', '+', '-', '@', '＝', '＋', '－', '＠'])
        || field.starts_with(['\t', '\r', '\n'])
    {
        csv.push('\'');
    }
    for character in field.chars() {
        if character == '"' {
            csv.push('"');
        }
        csv.push(character);
    }
    csv.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EventKind;
    use crate::demo_report;
    use crate::gui::{ElapsedRange, Timeline, visible_timeline_events};

    #[test]
    fn exports_only_events_matching_the_timeline_filters() {
        let report = demo_report().unwrap();
        let timeline = Timeline {
            kind: Some(EventKind::FileWrite),
            process: Some("22222222-2222-2222-2222-222222222222".into()),
            query: "demo-worker.exe".into(),
            ..Timeline::default()
        };
        let range = ElapsedRange::parse("0,5", "1", Language::Turkish).unwrap();
        let visible = visible_timeline_events(&report, &timeline, &range);
        let csv = encode(&report, visible.into_iter().map(|(_, event)| event));
        assert_eq!(csv.lines().count(), 2);
        assert!(csv.contains(r#""file-write""#));
        assert!(csv.contains(r#""demo-worker.exe","demo-output.txt""#));
        assert!(!csv.contains("example.org"));

        let marked = Timeline {
            marked: [2].into_iter().collect(),
            only_marked: true,
            ..Timeline::default()
        };
        let all_time = ElapsedRange::parse("", "", Language::Turkish).unwrap();
        let visible = visible_timeline_events(&report, &marked, &all_time);
        assert_eq!(
            encode(&report, visible.into_iter().map(|(_, event)| event)),
            csv
        );

        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("events.csv");
        save_report_bytes(csv.as_bytes(), &path).unwrap();
        assert!(save_report_bytes(b"replacement", &path).is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), csv);
    }

    #[test]
    fn quotes_delimiters_and_protects_formula_prefixes() {
        let mut cell = String::new();
        push_field(&mut cell, "file,\"sample\".txt");
        assert_eq!(cell, "\"file,\"\"sample\"\".txt\"");
        for text in ["=1+1", "  +2", "-2", "@name", "＝1", "\ttext"] {
            cell.clear();
            push_field(&mut cell, text);
            assert_eq!(cell, format!("\"'{text}\""));
        }
    }
}
