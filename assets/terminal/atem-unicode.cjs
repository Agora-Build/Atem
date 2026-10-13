// xterm 6.0.0 provider matching vt100 0.15.2 / unicode-width 0.1.14.
// Load with allowProposedApi: true, before applying any terminal-v1 frames.
const ranges = require('./unicode-width-0.1.14.json');

class AtemUnicode {
  version = 'atem-unicode-width-0.1.14';

  wcwidth(codepoint) {
    let low = 0;
    let high = ranges.length - 1;
    while (low <= high) {
      const middle = (low + high) >>> 1;
      const [start, end, width] = ranges[middle];
      if (codepoint < start) high = middle - 1;
      else if (codepoint > end) low = middle + 1;
      else return width;
    }
    return 1;
  }

  charProperties(codepoint, preceding) {
    let width = this.wcwidth(codepoint);
    const previousWidth = (preceding >>> 1) & 3;
    const join = width === 0 && previousWidth > 0;
    if (join) width = previousWidth;
    // xterm 6 UnicodeCharProperties: kind << 3 | width << 1 | join.
    return (width << 1) | Number(join);
  }
}

module.exports = { AtemUnicode };
