# Bundled Markdown libraries

These upstream distributions are bundled locally; the extension downloads no
JavaScript at runtime. Licenses are included alongside the distributions.

- marked 18.1.1: https://github.com/markedjs/marked/tree/v18.1.1
  `lib/marked.umd.js` from the npm `marked-18.1.1.tgz` archive.
  Archive SHA-256: `c05b3cff890d35e1208805a01fd0501571d09a81e725de0559b10bdfae90adad`.
- DOMPurify 3.4.17: https://github.com/cure53/DOMPurify/tree/3.4.17
  `dist/purify.js` from the npm `dompurify-3.4.17.tgz` archive.
  Archive SHA-256: `056cbdae276897208b88c21d1d779adfa09ad7be488a2f510a28e900d3bbffe7`.

Parsed Markdown is sanitized before insertion. Note images and media are disabled
so opening a note cannot automatically contact tracking URLs. Only HTTP(S) and
mailto links remain clickable, and links open without an opener or referrer.
