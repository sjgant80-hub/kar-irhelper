// kar-irhelper · tools/inline.mjs — put the gated ir.mjs into index.html byte for byte, between the markers.
//   node tools/inline.mjs           write it
//   node tools/inline.mjs --check   fail unless the page already holds it
import { readFileSync, writeFileSync } from 'node:fs';
const NL = String.fromCharCode(10);
const pageUrl = new URL('../index.html', import.meta.url);
const src = readFileSync(new URL('../ir.mjs', import.meta.url), 'utf8').replace(/\r\n/g, NL);
const page = readFileSync(pageUrl, 'utf8').replace(/\r\n/g, NL);
const a = src.indexOf('export const VERSION'), b = src.indexOf('export default');
if (a < 0 || b < a) { console.error('ir.mjs has no export const VERSION … export default span'); process.exit(1); }
const body = src.slice(a, b).replace(/\bexport /g, '').trimEnd();
if (/<\/script/i.test(body) || body.includes('<!--')) { console.error('ir.mjs holds text that would end the page script early'); process.exit(1); }
const BEGIN = '/*IR:BEGIN*/', END = '/*IR:END*/';
const i = page.indexOf(BEGIN), j = page.indexOf(END);
if (i < 0 || j < i) { console.error('index.html has no IR markers'); process.exit(1); }
const next = page.slice(0, i + BEGIN.length) + NL + body + NL + page.slice(j);
if (process.argv.includes('--check')) {
  if (next !== page) { console.error('index.html does not hold the current ir.mjs. Run: node tools/inline.mjs'); process.exit(1); }
  console.log('index.html holds the gated ir.mjs byte for byte');
} else { writeFileSync(pageUrl, next); console.log('ir.mjs inlined into index.html'); }
