use ratatui::style::Color;

/// Volume thresholds for visual effects
const LOW_THRESHOLD: f32 = 0.3;
const HIGH_THRESHOLD: f32 = 0.6;

/// Compute the border character set based on volume level.
/// - 0.0-0.3: standard thin borders
/// - 0.3-0.6: medium thick borders
/// - 0.6-1.0: double borders
pub fn border_chars(volume: f32) -> (&'static str, &'static str) {
    let v = volume.clamp(0.0, 1.0);
    if v < LOW_THRESHOLD {
        ("\u{2502}", "\u{2500}")
    } else if v < HIGH_THRESHOLD {
        ("\u{2503}", "\u{2501}")
    } else {
        ("\u{2551}", "\u{2550}")
    }
}

/// Compute the border color based on volume level.
/// - 0.0-0.3: Gray
/// - 0.3-0.6: interpolated from Gray to Cyan
/// - 0.6-1.0: Cyan
pub fn border_color(volume: f32) -> Color {
    let v = volume.clamp(0.0, 1.0);
    if v < LOW_THRESHOLD {
        Color::DarkGray
    } else if v < HIGH_THRESHOLD {
        // Interpolate from gray to cyan
        let t = (v - LOW_THRESHOLD) / (HIGH_THRESHOLD - LOW_THRESHOLD);
        let r = lerp(128, 0, t);
        let g = lerp(128, 255, t);
        let b = lerp(128, 255, t);
        Color::Rgb(r, g, b)
    } else {
        Color::Cyan
    }
}

/// Compute jitter offset for border vibration at high volume.
/// Returns a value in {-1, 0, 1} for cell-level position jitter.
pub fn border_jitter(volume: f32, tick: u64) -> i16 {
    let v = volume.clamp(0.0, 1.0);
    if v < HIGH_THRESHOLD {
        0
    } else {
        // Alternate between -1, 0, 1 based on tick counter
        match tick % 3 {
            0 => -1,
            1 => 1,
            _ => 0,
        }
    }
}

fn lerp(a: u8, b: u8, t: f32) -> u8 {
    let result = a as f32 + (b as f32 - a as f32) * t;
    result.clamp(0.0, 255.0) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn border_chars_low_volume() {
        let (v, h) = border_chars(0.0);
        assert_eq!(v, "\u{2502}");
        assert_eq!(h, "\u{2500}");
    }

    #[test]
    fn border_chars_medium_volume() {
        let (v, h) = border_chars(0.5);
        assert_eq!(v, "\u{2503}");
        assert_eq!(h, "\u{2501}");
    }

    #[test]
    fn border_chars_high_volume() {
        let (v, h) = border_chars(0.8);
        assert_eq!(v, "\u{2551}");
        assert_eq!(h, "\u{2550}");
    }

    #[test]
    fn border_chars_clamped() {
        let (v, h) = border_chars(1.5);
        assert_eq!(v, "\u{2551}");
        assert_eq!(h, "\u{2550}");
    }

    #[test]
    fn border_color_low_is_gray() {
        assert_eq!(border_color(0.1), Color::DarkGray);
    }

    #[test]
    fn border_color_high_is_cyan() {
        assert_eq!(border_color(0.9), Color::Cyan);
    }

    #[test]
    fn border_color_mid_is_interpolated() {
        match border_color(0.45) {
            Color::Rgb(r, g, b) => {
                assert!(r < 128, "red should decrease");
                assert!(g > 128, "green should increase");
                assert!(b > 128, "blue should increase");
            }
            _ => panic!("Expected RGB color"),
        }
    }

    #[test]
    fn jitter_zero_at_low_volume() {
        assert_eq!(border_jitter(0.2, 0), 0);
        assert_eq!(border_jitter(0.2, 1), 0);
    }

    #[test]
    fn jitter_nonzero_at_high_volume() {
        let j0 = border_jitter(0.9, 0);
        let j1 = border_jitter(0.9, 1);
        let j2 = border_jitter(0.9, 2);
        assert_eq!(j0, -1);
        assert_eq!(j1, 1);
        assert_eq!(j2, 0);
    }

    #[test]
    fn lerp_boundaries() {
        assert_eq!(lerp(0, 255, 0.0), 0);
        assert_eq!(lerp(0, 255, 1.0), 255);
        assert_eq!(lerp(0, 255, 0.5), 127);
    }
}
