# terminal-v1 renderer support

`atem-unicode.cjs` is the width provider for an Astation xterm renderer. Bundle
it and `unicode-width-0.1.14.json` locally with `@xterm/xterm` 6.0.0. This is a
renderer support asset, not an Astation UI or a standalone remote access server.

```js
const { AtemUnicode } = require('./atem-unicode.cjs');
const term = new Terminal({ allowProposedApi: true, scrollback: 0 });
term.unicode.register(new AtemUnicode());
term.unicode.activeVersion = 'atem-unicode-width-0.1.14';
```

The default xterm Unicode table misaligns emoji. Unicode11 also differs from
the host for recent emoji. Do not enable grapheme clustering independently:
the host currently measures individual scalars with `unicode-width` 0.1.14
(Unicode 15.1). The provider matches that behavior, including combining marks.
It uses xterm 6's proposed Unicode API; retest it when upgrading xterm.

The JSON consists of sorted inclusive `[start, end, width]` ranges. Unlisted
scalars have width 1. It is generated from `unicode-width` 0.1.14 by:

```sh
cargo run --offline --quiet --example terminal-unicode > assets/terminal/unicode-width-0.1.14.json
```

The Rust tests verify the generated table against every valid Unicode scalar.
Generation source: [unicode-width](https://github.com/unicode-rs/unicode-width),
licensed under MIT or Apache-2.0; the upstream package includes the Unicode
data license. These assets contain no fonts or downloaded executable scripts.

See `designs/terminal-v1-implementation.md` for framing, acknowledgement,
input handling, renderer limits and the Astation integration contract.
