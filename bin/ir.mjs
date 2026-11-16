#!/usr/bin/env node
// kar-irhelper · bin/ir.mjs — run ON the host you are examining, as a user who may read its processes and logs.
//   node bin/ir.mjs scope-template > scope.json            then fill in who authorized it, why, and until when
//   node bin/ir.mjs collect --scope scope.json [--dry-run]  read-only evidence → evidence.json, logged to ir-log.json
//   node bin/ir.mjs analyse evidence.json                   facts, each with where it was found, and proposals
//   node bin/ir.mjs approve <id> --evidence evidence.json --by "Name"   records the approval and PRINTS the command;
//                                                           it never runs it — the person who approved it does
//   node bin/ir.mjs verify-log [ir-log.json] [--anchor <hash>]   checks the hash chain, and that a hash you recorded
//                                                           elsewhere is still in it
// Options: --out evidence.json · --log ir-log.json
// After every entry it prints the log's latest hash. Record it somewhere else (the ticket, an email): the chain alone
// cannot catch someone who rewrites every hash after the entry they changed, but the recorded hash can.
import { readFileSync, writeFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { hostname } from 'node:os';
import { join, dirname, basename } from 'node:path';
import IR from '../ir.mjs';

const [cmd, ...rest] = process.argv.slice(2);
const opt = (name, d) => { const i = rest.indexOf('--' + name); return i < 0 ? d : rest[i + 1]; };
const positional = rest.filter((a, i) => !a.startsWith('--') && !(i > 0 && rest[i - 1].startsWith('--')));
const logPath = opt('log', 'ir-log.json');
const readJson = (p) => { try { return JSON.parse(readFileSync(p, 'utf8')); } catch (e) { console.error('cannot read ' + p + ': ' + e.message); process.exit(1); } };
const readLog = () => (existsSync(logPath) ? readJson(logPath) : []);
const log = (kind, data) => {
  const next = IR.append(readLog(), kind, data, new Date().toISOString());
  writeFileSync(logPath, JSON.stringify(next, null, 1) + '\n');
  const e = next[next.length - 1];
  console.error('[log ' + logPath + ' entry ' + e.seq + ' · latest hash ' + e.hash + ' · record it in the ticket]');
  return e;
};
const osName = () => (process.platform === 'linux' ? 'linux' : process.platform === 'win32' ? 'windows' : null);
const show = IR.commandLine;

// expand a path with * segments (e.g. /home/*/.ssh/authorized_keys) by reading directories, never a shell
function expand(pattern) {
  const parts = pattern.split('/').filter((p, i) => p !== '' || i === 0);
  let paths = [parts[0] === '' ? '/' : parts[0]];
  for (const part of parts.slice(1)) {
    const next = [];
    for (const base of paths) {
      if (part === '*') { try { for (const n of readdirSync(base)) next.push(join(base, n)); } catch { /* unreadable: skipped */ } }
      else next.push(join(base, part));
    }
    paths = next;
  }
  return paths.filter((p) => { try { return statSync(p).isFile(); } catch { return false; } });
}

if (cmd === 'scope-template') {
  const now = new Date();
  console.log(JSON.stringify({ authorizedBy: '', purpose: '', authorizedAt: now.toISOString(), expires: new Date(now.getTime() + 86400000).toISOString(), hosts: [hostname()] }, null, 2));
} else if (cmd === 'collect') {
  const os = osName();
  if (os === null) { console.error('this host\'s OS is not supported (Linux and Windows are)'); process.exit(1); }
  const scopePath = opt('scope', null);
  if (!scopePath) { console.error('collect needs --scope scope.json (make one with: node bin/ir.mjs scope-template)'); process.exit(1); }
  const scope = readJson(scopePath);
  const host = hostname(), now = new Date().toISOString();
  const s = IR.checkScope(scope, host, now);
  if (!s.ok) { log('refused', { host, why: s.why }); console.error('Refused: nothing was collected.'); for (const w of s.why) console.error('  - ' + w); process.exit(2); }
  const plan = IR.collectionPlan(os);
  if (rest.includes('--dry-run')) {
    console.log('Authorized: ' + s.summary + '\nWould run (read-only, no shell):');
    for (const c of plan.commands) console.log('  ' + c.id.padEnd(10) + show(c.argv) + '   (' + c.shows + ')');
    for (const f of plan.files) console.log('  ' + f.id.padEnd(10) + 'read ' + f.paths.join(', ') + '   (' + f.shows + ')');
    process.exit(0);
  }
  log('scope', { host, summary: s.summary });
  const outputs = {}, errors = {};
  for (const c of plan.commands) {
    try { outputs[c.id] = execFileSync(c.argv[0], c.argv.slice(1), { encoding: 'utf8', timeout: 60000, maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true }); }
    catch (e) { outputs[c.id] = typeof e.stdout === 'string' ? e.stdout : ''; errors[c.id] = String(e.message).split('\n')[0]; }
  }
  const files = [];
  for (const f of plan.files) for (const pattern of f.paths) for (const p of expand(pattern)) {
    try { const st = statSync(p); files.push({ id: f.id, path: p, mtime: st.mtime.toISOString(), text: readFileSync(p, 'utf8').slice(0, 1024 * 1024) }); }
    catch (e) { errors['file:' + p] = String(e.message).split('\n')[0]; }
  }
  const evidence = { tool: IR.VERSION, os, host, collectedAt: now, scope: s.summary, outputs, files, errors };
  const out = opt('out', 'evidence.json');
  const text = JSON.stringify(evidence, null, 1) + '\n';
  writeFileSync(out, text);
  const e = log('collect', { host, evidence: basename(out), sha256: IR.sha256(text), commands: Object.keys(outputs).length, files: files.length, errors: Object.keys(errors) });
  console.log('Collected from ' + host + ': ' + Object.keys(outputs).length + ' commands, ' + files.length + ' files' + (Object.keys(errors).length ? ', ' + Object.keys(errors).length + ' could not be read (see evidence.errors)' : '') + '.\nEvidence: ' + out + ' (sha256 ' + IR.sha256(text).slice(0, 16) + '…) · log entry ' + e.seq);
} else if (cmd === 'analyse' || cmd === 'analyze') {
  const path = positional[0] || 'evidence.json';
  const text = readFileSync(path, 'utf8');
  const r = IR.analyse(JSON.parse(text));
  if (!r.ok) { console.error(r.why); process.exit(1); }
  log('analyse', { evidence: basename(path), sha256: IR.sha256(text), facts: r.facts.length, proposals: r.proposals.length });
  console.log(r.facts.length + ' fact(s) on ' + r.host + '\n');
  for (const f of r.facts) {
    console.log(f.id + '  [' + f.severity + '] ' + f.title + '\n     found in ' + f.source + (f.line ? ', line ' + f.line : '') + ': ' + JSON.stringify(f.detail));
    const after = (p) => (p.undo ? 'undo: ' + show(p.undo) : p.kind === 'preserve' ? '(keeps evidence; changes nothing else)' : '(cannot be undone)');
    for (const p of r.proposals.filter((x) => x.fact === f.id)) console.log('     ' + p.id.padEnd(6) + p.kind.padEnd(10) + p.does + (p.run ? '\n' + ' '.repeat(22) + 'run:  ' + show(p.run) + '\n' + ' '.repeat(22) + after(p) : ''));
  }
  if (r.facts.length > 0) console.log('\nNothing has been changed. To act on a proposal: node bin/ir.mjs approve <id> --evidence ' + path + ' --by "Your name"');
} else if (cmd === 'approve') {
  const id = positional[0], by = opt('by', ''), path = opt('evidence', 'evidence.json');
  if (!id || by.trim() === '') { console.error('approve needs a proposal id and --by "Your name"'); process.exit(1); }
  const r = IR.analyse(readJson(path));
  const p = r.ok ? r.proposals.find((x) => x.id === id) : undefined;
  if (p === undefined) { console.error('no proposal ' + id + ' in ' + path); process.exit(1); }
  const e = log('approve', { proposal: id, by: by.trim(), kind: p.kind, does: p.does, run: p.run, undo: p.undo });
  console.log('Approved by ' + by.trim() + ' (log entry ' + e.seq + '). This tool does not run it. To carry it out, run:\n\n  ' + (p.run ? show(p.run) : '(a check by hand: ' + p.does + ')') + (p.undo ? '\n\nTo undo it later:\n\n  ' + show(p.undo) : p.run && p.kind !== 'preserve' ? '\n\nThis step cannot be undone.' : ''));
} else if (cmd === 'verify-log') {
  const path = positional[0] || logPath, anchor = opt('anchor', '');
  const v = IR.verifyLog(readJson(path), anchor);
  if (v.brokenAt !== null) console.log('The log does NOT verify: entry ' + v.brokenAt + ' of ' + v.entries + ' has been changed, removed or reordered.');
  else if (!v.ok) console.log('The log does NOT verify: its chain holds together, but the hash you recorded is not in it. It was rewritten after you recorded that hash.');
  else console.log('The log is intact: ' + v.entries + ' entries, each chained to the one before' + (v.anchoredAt !== null ? '; the hash you recorded is entry ' + v.anchoredAt + ', so every entry up to it is as it was.' : '. Give --anchor <hash> with a hash recorded elsewhere to also rule out a rewrite of the whole chain.'));
  process.exit(v.ok ? 0 : 3);
} else {
  console.error('usage: node bin/ir.mjs scope-template | collect --scope scope.json [--dry-run] | analyse evidence.json | approve <id> --evidence evidence.json --by "Name" | verify-log [ir-log.json] [--anchor <hash>]');
  process.exit(1);
}
