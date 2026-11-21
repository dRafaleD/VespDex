// Ported from AsphDex's cli/terminal-screen.js. See NOTICE.
use std::time::Duration;

use crossterm::style::Color;
use unicode_width::UnicodeWidthChar;

pub(super) const DURATION: Duration = Duration::from_millis(3400);
pub(super) const INTERVAL: Duration = Duration::from_millis(40);

const SCRAMBLE: [char; 7] = ['▒', '░', '0', '1', ':', '·', '+'];
const BAR_PARTS: [char; 8] = [' ', '▏', '▎', '▍', '▌', '▋', '▊', '▉'];
const ROTOR: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

fn hash(column: usize, row: usize, step: usize) -> usize {
    (column as u32 + 1).wrapping_mul(2_654_435_761) as usize
        ^ ((row + 7) * 40_503)
        ^ ((step + 13) * 97)
}

#[derive(Clone, Copy)]
pub(super) struct Frame {
    pub width: usize,
    pub height: usize,
    pub progress: f64,
    pub english: bool,
}

impl Frame {
    pub(super) fn row(self, y: u16, text: &str, color: Color) -> (String, Color) {
        let y = usize::from(y);
        let p = self.progress;
        let width = self.width;
        let first = 3;
        let last = self.height - 6;
        let span = last - first;
        let decode_rows = 5;
        let travel = (p / 0.8).min(1.0);
        let eased = if travel < 0.5 {
            2.0 * travel * travel
        } else {
            1.0 - (-2.0 * travel + 2.0).powi(2) / 2.0
        };
        let beam = first + (eased * (span + decode_rows + 1) as f64) as usize;
        let flash = Color::Rgb {
            r: 225,
            g: 255,
            b: 205,
        };
        let head_color = Color::Rgb {
            r: 155,
            g: 255,
            b: 92,
        };
        let glow = Color::Rgb {
            r: 90,
            g: 235,
            b: 25,
        };
        let trail = Color::Rgb {
            r: 38,
            g: 125,
            b: 0,
        };

        let (line, tone) = if (first..=last).contains(&y) {
            if beam < y {
                let dust = (0..width)
                    .map(|column| {
                        if column < 3 || column >= width - 3 {
                            return ' ';
                        }
                        match hash(column, y, (p * 14.0) as usize) % 173 {
                            0 => '◇',
                            1..=3 => '·',
                            _ => ' ',
                        }
                    })
                    .collect();
                (dust, trail)
            } else if beam == y {
                let head = ((p * 3.2).fract() * (width - 6) as f64) as usize;
                let rail: String = (0..width - 4)
                    .map(|column| {
                        if column == head {
                            '◆'
                        } else if column.abs_diff(head) < 5 {
                            '━'
                        } else if column % 2 == 1 {
                            '─'
                        } else {
                            '╌'
                        }
                    })
                    .collect();
                (format!("  {rail}"), head_color)
            } else {
                let behind = beam - y;
                let reveal = (behind as f64 / decode_rows as f64).min(1.0);
                let step = (p * 60.0) as usize;
                let mut column = 0;
                let mut has_portrait = false;
                let decoded = text
                    .chars()
                    .map(|ch| {
                        let at = column;
                        let cells = ch.width().unwrap_or(0);
                        column += cells;
                        let code = u32::from(ch);
                        if (0x2800..=0x28ff).contains(&code) {
                            has_portrait = true;
                            if reveal >= 1.0 {
                                return ch;
                            }
                            let mut dots = 0;
                            for bit in 0..8 {
                                let mask = 1 << bit;
                                if (code - 0x2800) & mask != 0
                                    && ((hash(at, y, bit) % 100) as f64 / 100.0) < reveal
                                {
                                    dots |= mask;
                                }
                            }
                            return if dots == 0 {
                                ' '
                            } else {
                                char::from_u32(0x2800 + dots).unwrap_or(ch)
                            };
                        }
                        if reveal < 1.0
                            && !ch.is_whitespace()
                            && cells == 1
                            && at as f64 >= reveal * width as f64 * 0.9
                            && hash(at, y, step) % 100 < 75
                        {
                            return SCRAMBLE[hash(at, y, step + 3) % SCRAMBLE.len()];
                        }
                        ch
                    })
                    .collect();
                let mut tone = if behind <= 1 {
                    flash
                } else if behind < decode_rows {
                    glow
                } else {
                    color
                };
                if reveal >= 1.0 && !(has_portrait && behind < decode_rows * 2) {
                    tone = color;
                }
                if p >= 0.8 {
                    let wave = first + (((p - 0.8) / 0.2) * (span + 2) as f64) as usize;
                    if y.abs_diff(wave) <= 1 {
                        tone = if y == wave { flash } else { glow };
                    }
                }
                (decoded, tone)
            }
        } else if p < 0.96 && (y == 2 || y == self.height - 5) {
            let shimmer = (p / 0.96 * (width - 3) as f64) as usize;
            let mirror = width - 3 - shimmer;
            let rail: String = (0..width - 2)
                .map(|column| {
                    if column == shimmer || column == mirror {
                        '◆'
                    } else if column.abs_diff(shimmer) < 4 || column.abs_diff(mirror) < 4 {
                        '━'
                    } else {
                        '─'
                    }
                })
                .collect();
            if y == 2 {
                (format!("╭{rail}╮"), head_color)
            } else {
                (format!("╰{rail}╯"), glow)
            }
        } else if y == self.height - 4 {
            let phase = match (self.english, p) {
                (false, p) if p < 0.32 => "arayüz başlatılıyor",
                (true, p) if p < 0.32 => "initializing interface",
                (false, p) if p < 0.78 => "çalışma alanı hazırlanıyor",
                (true, p) if p < 0.78 => "preparing workspace",
                (false, _) => "terminal hazır",
                (true, _) => "terminal ready",
            };
            let size = width.saturating_sub(42).clamp(6, 30);
            let units = (p * (size * 8) as f64) as usize;
            let full = units / 8;
            let mut bar = "█".repeat(full);
            if full < size {
                bar.push(BAR_PARTS[units % 8]);
                bar.push_str(&" ".repeat(size - full - 1));
            }
            let rotor = ROTOR[(p * 45.0) as usize % ROTOR.len()];
            (
                format!("  {rotor} ▕{bar}▏{:>3}%  {phase}", (p * 100.0) as u8),
                glow,
            )
        } else {
            (text.to_owned(), color)
        };
        (line, fade(tone, p))
    }
}

fn fade(color: Color, progress: f64) -> Color {
    let (r, g, b) = match color {
        Color::Rgb { r, g, b } => (r, g, b),
        Color::Green => (68, 210, 0),
        Color::White => (220, 225, 232),
        Color::Grey => (131, 143, 158),
        Color::DarkGrey => (65, 80, 92),
        _ => return color,
    };
    let brightness = 0.2 + 0.8 * (1.0 - (1.0 - progress).powi(3));
    let scale = |value: u8| (f64::from(value) * brightness).round() as u8;
    Color::Rgb {
        r: scale(r),
        g: scale(g),
        b: scale(b),
    }
}
