use std::path::Path;

use super::preferences;
use anyhow::{Context, Result};
use eframe::egui::{self, Color32, Stroke};

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum Theme {
    #[default]
    Dark,
    Graphite,
    Midnight,
    Contrast,
}

#[derive(Clone, Copy)]
pub(super) struct Palette {
    pub bg: Color32,
    pub surface: Color32,
    pub active: Color32,
    pub line: Color32,
    pub line_hot: Color32,
    pub accent: Color32,
    pub accent_soft: Color32,
    pub text: Color32,
    pub muted: Color32,
    pub error: Color32,
}

impl Theme {
    pub const ALL: [Self; 4] = [Self::Dark, Self::Graphite, Self::Midnight, Self::Contrast];

    pub fn label(self) -> &'static str {
        match self {
            Self::Dark => "Dark",
            Self::Graphite => "Graphite",
            Self::Midnight => "Midnight",
            Self::Contrast => "High Contrast",
        }
    }

    fn key(self) -> &'static str {
        match self {
            Self::Dark => "dark",
            Self::Graphite => "graphite",
            Self::Midnight => "midnight",
            Self::Contrast => "contrast",
        }
    }

    pub fn load() -> Self {
        preferences::path("theme")
            .map(|path| Self::read(&path))
            .unwrap_or_default()
    }

    pub fn save(self) -> Result<()> {
        self.write(&preferences::path("theme").context("LOCALAPPDATA is unavailable")?)
    }

    fn read(path: &Path) -> Self {
        let Some(value) = preferences::read(path) else {
            return Self::default();
        };
        Self::ALL
            .into_iter()
            .find(|theme| theme.key() == value.trim())
            .unwrap_or_default()
    }

    fn write(self, path: &Path) -> Result<()> {
        preferences::write(path, self.key())
    }

    pub fn palette(self) -> Palette {
        // Same palette values as AsphDex's appearance settings.
        let [
            bg,
            surface,
            active,
            line,
            line_hot,
            accent,
            accent_soft,
            text,
            muted,
            error,
        ] = match self {
            Self::Dark => [
                0x050806, 0x09100c, 0x0d1611, 0x1b3324, 0x2e6b40, 0x28ff73, 0x9effbb, 0xe5f4e9,
                0x82998a, 0xff748a,
            ],
            Self::Graphite => [
                0x111315, 0x17191c, 0x1c1f22, 0x30353a, 0x62696e, 0xc9ccc5, 0xe0e2dc, 0xe4e6e8,
                0xa3a9ae, 0xe18d88,
            ],
            Self::Midnight => [
                0x050711, 0x090d1b, 0x0d1325, 0x202d4d, 0x315d90, 0x54c7ff, 0xa9e5ff, 0xedf7ff,
                0x8ca2bb, 0xff748a,
            ],
            Self::Contrast => [
                0x000000, 0x050505, 0x0b0b0b, 0x6d6d6d, 0xffffff, 0x7dff00, 0xd5ffad, 0xffffff,
                0xdddddd, 0xff9ea6,
            ],
        }
        .map(|color: u32| Color32::from_rgb((color >> 16) as u8, (color >> 8) as u8, color as u8));
        Palette {
            bg,
            surface,
            active,
            line,
            line_hot,
            accent,
            accent_soft,
            text,
            muted,
            error,
        }
    }
}

impl Palette {
    pub fn apply(self, ctx: &egui::Context) {
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = self.bg;
        visuals.window_fill = self.surface;
        visuals.window_stroke = Stroke::new(1.0_f32, self.line);
        visuals.override_text_color = Some(self.text);
        visuals.extreme_bg_color = self.bg;
        visuals.faint_bg_color = self.surface;
        visuals.selection.bg_fill = self.active;
        visuals.selection.stroke = Stroke::new(1.0_f32, self.line_hot);
        for widgets in [
            &mut visuals.widgets.inactive,
            &mut visuals.widgets.hovered,
            &mut visuals.widgets.active,
        ] {
            widgets.bg_fill = self.surface;
            widgets.weak_bg_fill = self.active;
            widgets.corner_radius = egui::CornerRadius::same(2);
            widgets.bg_stroke = Stroke::new(1.0_f32, self.line);
            widgets.fg_stroke = Stroke::new(1.0_f32, self.text);
        }
        visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, self.line_hot);
        visuals.widgets.active.bg_stroke = Stroke::new(1.0_f32, self.accent);
        ctx.set_visuals(visuals);
    }

    pub fn panel(self, fill: Color32, x: i8, y: i8) -> egui::Frame {
        egui::Frame::new()
            .fill(fill)
            .stroke(Stroke::new(1.0_f32, self.line))
            .inner_margin(egui::Margin::symmetric(x, y))
            .corner_radius(2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn replaces_an_existing_preference_and_defaults_on_invalid_input() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("nested").join("theme");
        assert!(Theme::read(&path) == Theme::Dark);
        for theme in Theme::ALL {
            theme.write(&path).unwrap();
            assert!(Theme::read(&path) == theme);
        }
        fs::write(&path, b"unknown").unwrap();
        assert!(Theme::read(&path) == Theme::Dark);
        fs::write(&path, "contrast".to_owned() + &" ".repeat(64)).unwrap();
        assert!(Theme::read(&path) == Theme::Dark);
    }
}
