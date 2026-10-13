//! Regenerate assets/terminal/unicode-width-0.1.14.json with:
//! cargo run --offline --quiet --example terminal-unicode > assets/terminal/unicode-width-0.1.14.json
use unicode_width::UnicodeWidthChar;

fn main() {
    let mut ranges = Vec::new();
    let mut start = 0;
    let mut previous = 0;
    for scalar in 0..=0x110000 {
        let width = if scalar == 0x110000 {
            1
        } else {
            char::from_u32(scalar).and_then(|c| c.width()).unwrap_or(0)
        };
        if width != previous {
            if previous != 1 {
                ranges.push([start, scalar - 1, previous as u32]);
            }
            start = scalar;
            previous = width;
        }
    }
    println!("{}", serde_json::to_string(&ranges).unwrap());
}
