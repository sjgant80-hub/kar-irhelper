// kar-irhelper · page-parity.test.mjs — the page runs the gated kernel, and what it says the tool does is what it does.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import IR from './ir.mjs';

const NL = String.fromCharCode(10);
const read = (p) => readFileSync(new URL('./' + p, import.meta.url), 'utf8').replace(/\r\n/g, NL);
const page = read('index.html');
const src = read('ir.mjs');
const body = src.slice(src.indexOf('export const VERSION'), src.indexOf('export default')).replace(/\bexport /g, '').trimEnd();
const text = page.replace(/<script[\s\S]*?<\/script>/g, ' ').replace(/<style[\s\S]*?<\/style>/g, ' ').replace(/<[^>]+>/g, ' ').replace(/&gt;/g, '>').replace(/&lt;/g, '<').replace(/&amp;/g, '&').replace(/\s+/g, ' ');
const linux = JSON.parse(read('data/demo-linux.json')), windows = JSON.parse(read('data/demo-windows.json')), scope = JSON.parse(read('data/demo-scope.json'));

test('the page runs ir.mjs byte for byte, and nothing in it can end the page script early', () => {
  assert.ok(body.length > 10000);
  assert.ok(page.includes('/*IR:BEGIN*/' + NL + body + NL + '/*IR:END*/'));
  assert.ok(!/<\/script/i.test(body) && !body.includes('<!--'));
  const ctx = { TextEncoder }; // a browser has it; a bare VM context does not
  vm.runInNewContext(body + NL + ';globalThis.__ir = { analyse, checkScope, verifyLog, append, commandLine };', ctx);
  for (const ev of [linux, windows]) {
    assert.equal(JSON.stringify(ctx.__ir.analyse(ev)), JSON.stringify(IR.analyse(ev)), 'the inlined kernel agrees with the module on ' + ev.host);
    assert.equal(JSON.stringify(ctx.__ir.checkScope(scope, ev.host, ev.collectedAt)), JSON.stringify(IR.checkScope(scope, ev.host, ev.collectedAt)));
  }
  const log = IR.append(IR.append([], 'scope', 1, 't'), 'collect', 2, 't');
  assert.equal(JSON.stringify(ctx.__ir.verifyLog(log, log[1].hash)), JSON.stringify(IR.verifyLog(log, log[1].hash)));
});

test('the demo: synthetic, authorized for both demo hosts, and every refusal button is refused for its own reason', () => {
  for (const ev of [linux, windows]) {
    assert.ok(ev.synthetic.startsWith('SYNTHETIC'), ev.host + ' is marked synthetic');
    assert.equal(IR.checkScope(scope, ev.host, ev.collectedAt).ok, true, ev.host + ' is authorized at collection time');
    assert.ok(text.includes('(16 Nov 2026, 12:00 UTC)') && ev.collectedAt === '2026-11-16T12:00:00Z');
    const addrs = JSON.stringify(ev).match(/\b\d{1,3}(\.\d{1,3}){3}\b/g) || [];
    for (const a of addrs) assert.ok(/^(203\.0\.113|198\.51\.100|192\.0\.2|10\.|0\.0\.0\.0|127\.)/.test(a), 'only documentation or private addresses in the demo: ' + a);
  }
  assert.ok(text.includes('The evidence here is synthetic'));
  const at = linux.collectedAt;
  assert.deepEqual(IR.checkScope({ ...scope, expires: '2026-11-16T11:00:00Z' }, 'web1', at).why, ['this authorization has expired']);
  assert.deepEqual(IR.checkScope({ ...scope, hosts: ['db1'] }, 'web1', at).why, ['host "web1" is not in this authorization\'s hosts']);
  assert.deepEqual(IR.checkScope({ ...scope, authorizedBy: '' }, 'web1', at).why, ['authorizedBy is required: the person who authorized this response']);
  for (const want of ["s.expires = '2026-11-16T11:00:00Z'", "s.hosts = ['db1']", "s.authorizedBy = ''"]) assert.ok(page.includes(want), 'the button does ' + want);
  const l = IR.analyse(linux), w = IR.analyse(windows);
  assert.deepEqual([...new Set(l.facts.map((f) => f.rule))], ['proc-temp', 'shell-socket', 'uid0', 'brute-then-success', 'cron-suspicious', 'keys-recent'], 'the Linux demo shows all six Linux rules');
  assert.deepEqual([...new Set(w.facts.map((f) => f.rule))], ['proc-temp', 'task-suspicious', 'service-temp', 'brute-then-success'], 'the Windows demo shows all four Windows rules');
  for (const p of [...l.proposals, ...w.proposals]) for (const a of [...(p.run || []), ...(p.undo || [])]) assert.ok(!a.includes('"'), 'demo commands quote exactly: ' + a);
});

test('what the page says the tool does is what the kernel does', () => {
  assert.equal((src.match(/\bfact\('/g) || []).length, 10, 'ten rules in the kernel');
  assert.ok(text.includes('ten fixed rules'));
  const lists = page.slice(page.indexOf('id="rules"'), page.indexOf('id="blueprint"'));
  const items = (h) => { const s = lists.slice(lists.indexOf('<h3>' + h + '</h3>')); return (s.slice(0, s.indexOf('</ul>')).match(/<li>/g) || []).length; };
  assert.equal(items('Linux'), 6); assert.equal(items('Windows'), 4);
  assert.equal(IR.BRUTE_FAILURES, 5); assert.ok(text.includes('five or more failed SSH logins') && text.includes('five or more failed logons (4625)'));
  assert.ok(/<= 7 \* DAY/.test(src) && text.includes('changed in the last 7 days'));
  assert.equal(IR.MAX_SCOPE_DAYS, 30); assert.ok(text.includes('(30 days at most)'));
  for (const [rule, os] of [['proc-temp', 'linux'], ['uid0', 'linux'], ['brute-then-success', 'linux'], ['task-suspicious', 'windows'], ['service-temp', 'windows'], ['brute-then-success', 'windows']]) {
    const d = { pid: '5', user: 'a', ip: '1.2.3.4', task: '\\T', service: 'S', startMode: 'Auto', state: 'Running', path: 'C:\\Users\\Public\\a.exe' };
    for (const p of IR.propose(os, { id: 'F1', rule, detail: d }).filter((x) => x.kind === 'contain')) assert.ok(p.undo !== null, 'every contain step has its undo: ' + rule);
  }
  assert.ok(text.includes('Each comes with its exact undo'));
  assert.ok(IR.propose('linux', { id: 'F1', rule: 'proc-temp', detail: { pid: '5' } }).find((p) => p.kind === 'eradicate').reversible === false && text.includes('These are marked as not reversible'));
  for (const verb of ['kill', 'rm', 'usermod', 'iptables', 'sc config']) assert.ok(text.includes(verb), 'the page names the banned verb ' + verb);
  assert.ok(text.includes('cannot start with a dash') && text.includes('Someone with the file could still rewrite every hash after the entry they changed'), 'the limits of the safe-form check and of the chain are stated');
  assert.ok(!/\.(exec|spawn)\w*\(/.test(src) && !/child_process/.test(src), 'the kernel cannot run anything');
  const cli = read('bin/ir.mjs');
  assert.equal((cli.match(/execFileSync\(/g) || []).length, 1, 'the command line runs one thing: the collection loop');
  assert.ok(/for \(const c of plan\.commands\) \{\s*try \{ outputs\[c\.id\] = execFileSync\(c\.argv\[0\]/.test(cli), 'and only over the fixed allow-list');
  assert.ok(/log\('collect', \{[^}]*sha256: IR\.sha256\(text\)/.test(cli) && /writeFileSync\(out, text\)/.test(cli) && text.includes('records the SHA-256 of the evidence file it wrote'), 'the collect entry hashes exactly the file written');
  assert.ok(/scope: s\.summary/.test(cli) && /log\('scope', \{ host, summary: s\.summary \}\)/.test(cli) && text.includes('kept in the log and in each evidence file'), 'the authorization summary is in the log and the evidence');
  assert.ok(/log\('refused'/.test(cli) && /process\.exit\(2\)/.test(cli), 'a refusal is logged and exits without collecting');
  const at = '2026-11-16T12:00:00Z', ok = { authorizedBy: 'a', purpose: 'p', authorizedAt: '2026-11-16T09:00:00Z', expires: '2026-11-17T09:00:00Z', hosts: ['h'] };
  for (const bad of [{ authorizedBy: '' }, { purpose: '' }, { expires: '2026-11-16T11:00:00Z' }, { authorizedAt: '2026-11-16T13:00:00Z' }, { expires: '2026-12-30T09:00:00Z' }, { hosts: ['other'] }]) {
    assert.equal(IR.checkScope({ ...ok, ...bad }, 'h', at).ok, false, 'refused: ' + JSON.stringify(bad));
  }
  assert.ok(text.includes('has no named person or purpose, has expired, starts in the future, lasts more than 30 days, or does not list this host'));
});

test('the brochure, supplier, licence and no prices', () => {
  for (const h of ['IT manager or on-call engineer', 'CISO', 'Managed service provider', 'Finance', 'Legal and compliance', 'The board', 'Security and data protection', 'Deployment', 'Ownership, support and exit']) assert.ok(text.includes(h), h);
  for (const id of ['what', 'start-here', 'try', 'how', 'rules', 'blueprint', 'business', 'limits']) assert.ok(page.includes('id="' + id + '"'), '#' + id);
  assert.ok(page.includes('href="https://www.ai-nativesolutions.com/">AI Native Solutions</a>') && text.includes('MIT, © Simon Gant'));
  assert.ok(!/[£€$]\s?\d/.test(text), 'a price on the page');
  assert.ok(!new RegExp(['karma', 'didy'].join('-'), 'i').test(page) && !/[κφ◊]/.test(page));
});

test('the page builds its output with text nodes, and loads nothing from elsewhere', () => {
  const ui = page.slice(page.indexOf('/*IR:END*/'));
  assert.ok(!/\.innerHTML\s*=|insertAdjacentHTML|document\.write/.test(ui.slice(0, ui.indexOf('</script>'))));
  assert.ok(!/<script[^>]+src=/.test(page) && !/<link[^>]+stylesheet/.test(page));
  assert.ok(/connect-src 'self'/.test(page) && /default-src 'none'/.test(page));
});
