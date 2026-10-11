use ratatui::style::Color;

/// Volume thresholds for visual effects
const LOW_THRESHOLD: f32 = 0.3;
const HIGH_THRESHOLD: f32 = 0.6;

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

fn lerp(a: u8, b: u8, t: f32) -> u8 {
    let result = a as f32 + (b as f32 - a as f32) * t;
    result.clamp(0.0, 255.0) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn lerp_boundaries() {
        assert_eq!(lerp(0, 255, 0.0), 0);
        assert_eq!(lerp(0, 255, 1.0), 255);
        assert_eq!(lerp(0, 255, 0.5), 127);
    }
}
