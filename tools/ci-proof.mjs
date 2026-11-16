// kar-irhelper · tools/ci-proof.mjs — CI ONLY, on a throwaway GitHub runner. Never run it on a host you care about.
//   node tools/ci-proof.mjs scope <file> [host]           an authorization for this runner (or for another host)
//   node tools/ci-proof.mjs prove <evidence> <canary>     the proof, after the workflow planted the canaries
// The workflow plants real signs of compromise on the runner (a program running from a temp folder, a shell holding a
// socket, a second uid-0 account, a new SSH key, a cron job or scheduled task or service that runs from a temp folder),
// then collects evidence with bin/ir.mjs. This script checks that analyse finds every planted sign, then RUNS each
// proposed command and its undo, as the person approving it would, and checks that each did what it says.
// The tool itself never runs a proposal: this script stands in for the person, on a machine that is thrown away.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { hostname } from 'node:os';
import IR from '../ir.mjs';

const [mode, a, b] = process.argv.slice(2);
const json = (p) => JSON.parse(readFileSync(p, 'utf8').replace(/^﻿/, ''));
const sha = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');
const run = (argv) => { try { return { ok: true, out: execFileSync(argv[0], argv.slice(1), { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true }) }; } catch (e) { return { ok: false, out: String(e.stdout || '') + String(e.stderr || '') }; } };
const wait = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
const until = (test, tries = 60) => { for (let i = 0; i < tries; i++) { if (test()) return true; wait(500); } return false; };
const ps = (cmd) => run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', cmd]);

if (mode === 'scope') {
  const now = Date.now();
  const scope = { authorizedBy: 'GitHub Actions run ' + (process.env.GITHUB_RUN_ID || 'local') + ' (a throwaway runner)', purpose: 'CI proof: signs planted on purpose on a throwaway runner', authorizedAt: new Date(now - 60000).toISOString(), expires: new Date(now + 3600000).toISOString(), hosts: [b || hostname()] };
  writeFileSync(a, JSON.stringify(scope, null, 1) + '\n');
  console.log('scope written for ' + scope.hosts[0]);
  process.exit(0);
}
if (mode !== 'prove') { console.error('usage: ci-proof.mjs scope <file> [host] | prove <evidence> <canary>'); process.exit(1); }

const evidence = json(a), canary = json(b);
const r = IR.analyse(evidence);
const fails = [], done = [], skipped = [];
const fail = (msg) => { fails.push(msg); console.log('FAIL  ' + msg); };
const pass = (msg) => { done.push(msg); console.log('ok    ' + msg); };
if (!r.ok) { console.error('analyse refused the evidence: ' + r.why); process.exit(1); }
console.log('host ' + r.host + ' · ' + r.facts.length + ' fact(s) · ' + r.proposals.length + ' proposal(s)');
for (const f of r.facts) console.log('  ' + f.id + ' ' + f.rule + ' ' + JSON.stringify(f.detail));

const find = (rule, match) => { const f = r.facts.find((x) => x.rule === rule && match(x.detail)); if (f === undefined) fail('the planted ' + rule + ' was not found'); else pass('found the planted ' + rule + ' (' + f.id + ', ' + f.source + (f.line ? ' line ' + f.line : '') + ')'); return f; };
const steps = (f) => (f === undefined ? [] : r.proposals.filter((p) => p.fact === f.id));
const synthetic = (rule, detail) => IR.propose(evidence.os, { id: 'S-' + rule, rule, detail });
// do(p, after, undone): run the step, check its effect; then its undo, check that the effect is gone
function act(p, after, undone) {
  if (p === undefined) { fail('a proposal is missing'); return; }
  const did = run(p.run);
  if (!did.ok) { fail(p.id + ' ' + p.kind + ' failed to run: ' + IR.commandLine(p.run) + ' · ' + did.out.trim().slice(0, 300)); return; }
  if (!until(after)) { fail(p.id + ' ran but did not do what it says: ' + p.does); return; }
  pass(p.id + ' ' + p.kind.padEnd(9) + ' ' + p.does + ' · ran ' + IR.commandLine(p.run));
  if (p.undo === null) return;
  const back = run(p.undo);
  if (!back.ok || !until(undone)) { fail(p.id + ' undo did not undo it: ' + IR.commandLine(p.undo) + ' · ' + back.out.trim().slice(0, 300)); return; }
  pass(p.id + ' undo      ' + IR.commandLine(p.undo));
}

if (evidence.os === 'linux') {
  const stat = (pid) => run(['ps', '-o', 'stat=', '-p', pid]).out.trim();
  const gone = (pid) => () => { const s = stat(pid); return s === '' || s.startsWith('Z'); };
  const locked = (user) => run(['passwd', '-S', user]).out.split(/\s+/)[1];
  const procSteps = (f, exe) => {
    const [keep, pause, end] = steps(f);
    act(keep, () => existsSync(keep.run[2]) && sha(keep.run[2]) === sha(exe));
    act(pause, () => stat(f.detail.pid).startsWith('T'), () => !stat(f.detail.pid).startsWith('T'));
    act(end, gone(f.detail.pid));
  };
  const proc = find('proc-temp', (d) => d.pid === canary.proc);
  if (proc) procSteps(proc, '/tmp/ir-canary');
  const shell = find('shell-socket', (d) => d.pid === canary.shell && d.program === 'bash');
  if (shell) procSteps(shell, '/proc/' + canary.shell + '/exe');
  const uid0 = find('uid0', (d) => d.user === canary.user);
  if (uid0) act(steps(uid0)[0], () => locked(canary.user) === 'L', () => locked(canary.user) === 'P');
  for (const [rule, path] of [['keys-recent', canary.key], ['cron-suspicious', canary.cron]]) {
    if (!path) { skipped.push(rule + ': not planted on this runner'); continue; }
    const f = find(rule, (d) => d.path === path);
    if (f) { const [keep, hand] = steps(f); act(keep, () => existsSync(path + '.ir-evidence') && sha(path + '.ir-evidence') === sha(path)); if (hand && hand.run === null) pass(hand.id + ' check     ' + hand.does + ' (by hand: no command)'); else fail(rule + ': the by-hand step is missing'); }
  }
  // the brute-force detection is proven by the unit tests; here its proposed commands are run for real
  const [block, lock] = synthetic('brute-then-success', { ip: '203.0.113.77', user: canary.user });
  const blocked = () => run(['iptables', '-C', 'INPUT', '-s', '203.0.113.77', '-j', 'DROP']).ok;
  act(block, blocked, () => !blocked());
  act(lock, () => locked(canary.user) === 'L', () => locked(canary.user) === 'P');
} else {
  const alive = (pid) => ps('Get-Process -Id ' + pid + ' -ErrorAction Stop | Out-Null').ok;
  const proc = find('proc-temp', (d) => d.pid === canary.proc);
  if (proc) {
    const [hash, end] = steps(proc);
    const want = sha(proc.detail.path);
    const h = run(hash.run);
    if (h.ok && h.out.replace(/\s/g, '').toLowerCase().includes(want)) pass(hash.id + ' preserve  ' + hash.does + ' · ran ' + IR.commandLine(hash.run) + ' · ' + want.slice(0, 16) + '…'); else fail(hash.id + ' did not record the file\'s hash: ' + h.out.trim().slice(0, 300));
    act(end, () => !alive(proc.detail.pid));
  }
  const status = (task) => run(['schtasks.exe', '/query', '/tn', task, '/fo', 'csv', '/nh']).out;
  const task = find('task-suspicious', (d) => d.task === canary.task);
  if (task) act(steps(task)[0], () => status(canary.task).includes('"Disabled"'), () => !status(canary.task).includes('"Disabled"'));
  const qc = (svc) => run(['sc.exe', 'qc', svc]).out;
  const svc = find('service-temp', (d) => d.service === canary.service);
  if (svc) {
    const s = steps(svc);
    if (s.length !== 1) fail('a stopped service should get one step (disable), not ' + s.length);
    act(s[0], () => qc(canary.service).includes('DISABLED'), () => qc(canary.service).includes('DEMAND_START'));
  }
  // stopping a running service: proven on the runner's own print spooler, if it is running, then restored
  if (run(['sc.exe', 'query', 'Spooler']).out.includes('RUNNING')) {
    const [off, stop] = synthetic('service-temp', { service: 'Spooler', startMode: 'Auto', state: 'Running' });
    const state = () => run(['sc.exe', 'query', 'Spooler']).out;
    act(off, () => qc('Spooler').includes('DISABLED'), () => qc('Spooler').includes('AUTO_START'));
    act(stop, () => state().includes('STOPPED'), () => state().includes('RUNNING'));
  } else skipped.push('stopping a running service: the Spooler service is not running on this runner');
  const [block, disable] = synthetic('brute-then-success', { ip: '203.0.113.77', user: canary.user });
  const rule = () => ps("Get-NetFirewallRule -DisplayName 'IR block 203.0.113.77' -ErrorAction Stop | Out-Null").ok;
  act(block, rule, () => !rule());
  const enabled = () => ps("(Get-LocalUser -Name '" + canary.user + "').Enabled").out.trim();
  act(disable, () => enabled() === 'False', () => enabled() === 'True');
}

for (const s of skipped) console.log('skip  ' + s);
console.log(done.length + ' checks passed, ' + fails.length + ' failed, ' + skipped.length + ' skipped');
writeFileSync('proof.json', JSON.stringify({ os: evidence.os, host: r.host, facts: r.facts.length, passed: done, failed: fails, skipped }, null, 1) + '\n');
process.exit(fails.length === 0 ? 0 : 1);
