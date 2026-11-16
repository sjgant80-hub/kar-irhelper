// kar-irhelper · ir.mjs — an incident-response helper for hosts you own. It gathers evidence, finds facts, and
// PROPOSES containment. It never contains anything itself: a person reads each proposal, approves it, and runs the
// exact command shown. Every step is written to a hash-chained log, so any later edit to the record is detectable.
// Pure and deterministic; garbage never throws. The command line (bin/ir.mjs) does the reading; this file decides.
//
//   checkScope   no recorded authorization for THIS host, no run: who authorized, when, why, which hosts, until when
//   COLLECT      the fixed, read-only allow-list of commands and files per OS (nothing else is ever run or read)
//   analyse      evidence → facts (each with the rule, the command or file, and the line it came from) → proposals
//   PLAYBOOKS    each fact's proposals: preserve, contain or eradicate, with the exact command and its undo
//   append       the hash-chained log; verifyLog finds the first entry that does not match

export const VERSION = 'kar-irhelper/1';
export const MAX_SCOPE_DAYS = 30;
const DAY = 86400000;

const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
const str = (x) => (typeof x === 'string' ? x.trim() : '');
const lines = (x) => (typeof x === 'string' ? x.split(/\r?\n/) : []);
const ms = (x) => { const t = typeof x === 'string' ? Date.parse(x) : NaN; return Number.isFinite(t) ? t : NaN; };

// ── sha256 (pure, so the browser and the command line compute the same chain) ─────────────────────────────────────
const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
export function sha256(text) {
  const bytes = new TextEncoder().encode(typeof text === 'string' ? text : '');
  const bitLen = bytes.length * 8;
  const padded = new Uint8Array(((bytes.length + 9 + 63) >> 6) << 6);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 4, bitLen >>> 0);
  dv.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000));
  const h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  // a plain array sized by its own loops: an off-by-one in either loop changes the hash, so the test vectors catch it
  const w = [];
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < padded.length; off += 64) {
    w.length = 0;
    for (let i = 0; i < 16; i++) w.push(dv.getUint32(off + i * 4));
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3), s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w.push((w[i - 16] + s0 + w[i - 7] + s1) >>> 0);
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < w.length; i++) {
      const t1 = (hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i]) >>> 0;
      const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
  }
  return h.map((x) => x.toString(16).padStart(8, '0')).join('');
}

// ── scope: no recorded authorization, no run ─────────────────────────────────────────────────────────────────────
// checkScope(scope, host, nowIso) → { ok, why[], summary } — why lists every reason it is refused
export function checkScope(scope, host, nowIso) {
  const why = [];
  if (!isObj(scope)) return { ok: false, why: ['the scope must be a JSON object (run: node bin/ir.mjs scope-template)'], summary: '' };
  const by = str(scope.authorizedBy), purpose = str(scope.purpose), at = ms(scope.authorizedAt), until = ms(scope.expires), now = ms(nowIso);
  const hosts = Array.isArray(scope.hosts) ? scope.hosts.map(str).filter((h) => h !== '') : [];
  if (by === '') why.push('authorizedBy is required: the person who authorized this response');
  if (purpose === '') why.push('purpose is required: why this response is authorized');
  if (!Number.isFinite(at)) why.push('authorizedAt must be a date and time (ISO 8601)');
  if (!Number.isFinite(until)) why.push('expires must be a date and time (ISO 8601)');
  if (!Number.isFinite(now)) why.push('the current time could not be read');
  if (hosts.length === 0) why.push('hosts must list the hosts this authorization covers');
  if (Number.isFinite(at) && Number.isFinite(until) && until <= at) why.push('expires must be after authorizedAt');
  if (Number.isFinite(at) && Number.isFinite(until) && until - at > MAX_SCOPE_DAYS * DAY) why.push('an authorization may last at most ' + MAX_SCOPE_DAYS + ' days');
  if (Number.isFinite(at) && Number.isFinite(now) && at > now) why.push('authorizedAt is in the future');
  if (Number.isFinite(until) && Number.isFinite(now) && now >= until) why.push('this authorization has expired');
  const h = str(host).toLowerCase();
  if (h === '') why.push('the host being examined has no name');
  else if (hosts.length > 0 && !hosts.some((x) => x.toLowerCase() === h)) why.push('host "' + str(host) + '" is not in this authorization\'s hosts');
  const summary = why.length === 0 ? 'authorized by ' + by + ' at ' + new Date(at).toISOString() + ' for: ' + purpose + ' · hosts: ' + hosts.join(', ') + ' · until ' + new Date(until).toISOString() : '';
  return { ok: why.length === 0, why, summary };
}

// ── the read-only allow-list ─────────────────────────────────────────────────────────────────────────────────────
// Commands run with no shell (argv as given). Files are read, never written. Nothing outside this list is ever run.
const PS = (cmd) => Object.freeze(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', cmd]);
export const COLLECT = Object.freeze({
  linux: Object.freeze({
    commands: Object.freeze([
      Object.freeze({ id: 'processes', argv: Object.freeze(['ps', '-eo', 'pid,user,lstart,args', '--no-headers']), shows: 'running processes, their owner, start time and command line' }),
      Object.freeze({ id: 'sockets', argv: Object.freeze(['ss', '-tunap']), shows: 'network sockets and the process holding each' }),
      Object.freeze({ id: 'accounts', argv: Object.freeze(['getent', 'passwd']), shows: 'local accounts and their user ids' }),
      Object.freeze({ id: 'ssh-log', argv: Object.freeze(['journalctl', '-u', 'ssh', '-u', 'sshd', '--since', '-24h', '--no-pager', '-o', 'short-iso']), shows: 'the last day of SSH logins, failed and accepted' }),
    ]),
    files: Object.freeze([
      Object.freeze({ id: 'cron', paths: Object.freeze(['/etc/crontab', '/etc/cron.d/*', '/var/spool/cron/crontabs/*']), shows: 'scheduled jobs' }),
      Object.freeze({ id: 'ssh-keys', paths: Object.freeze(['/root/.ssh/authorized_keys', '/home/*/.ssh/authorized_keys']), shows: 'keys that can log in, and when each file last changed' }),
    ]),
  }),
  windows: Object.freeze({
    commands: Object.freeze([
      Object.freeze({ id: 'processes', argv: PS('Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Csv -NoTypeInformation'), shows: 'running processes, their file and command line' }),
      Object.freeze({ id: 'tasks', argv: Object.freeze(['schtasks.exe', '/query', '/fo', 'csv', '/v']), shows: 'scheduled tasks and what each runs' }),
      Object.freeze({ id: 'services', argv: PS('Get-CimInstance Win32_Service | Select-Object Name,State,StartMode,PathName | ConvertTo-Csv -NoTypeInformation'), shows: 'services, their state and file' }),
      Object.freeze({ id: 'logons', argv: PS("Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4625;StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue | ForEach-Object { $x=[xml]$_.ToXml(); $d=@{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name]=$_.'#text' }; [pscustomobject]@{Time=$_.TimeCreated.ToUniversalTime().ToString('o');Id=$_.Id;User=$d['TargetUserName'];Ip=$d['IpAddress']} } | ConvertTo-Csv -NoTypeInformation"), shows: 'the last day of successful and failed logons' }),
    ]),
    files: Object.freeze([]),
  }),
});

// collectionPlan(os) → the commands and files for that OS, or null for an OS it does not know
export function collectionPlan(os) {
  return typeof os === 'string' && Object.prototype.hasOwnProperty.call(COLLECT, os) ? COLLECT[os] : null;
}

// ── parsing helpers ──────────────────────────────────────────────────────────────────────────────────────────────
export function parseCsv(text) {
  const rows = [];
  let row = [], field = '', q = false;
  const s = typeof text === 'string' ? text : '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) { if (c === '"' && s[i + 1] === '"') { field += '"'; i++; } else if (c === '"') q = false; else field += c; continue; }
    if (c === '"') q = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n' || c === '\r') { row.push(field); rows.push(row); row = []; field = ''; } // a CRLF leaves an empty row, dropped below
    else field += c;
  }
  row.push(field); rows.push(row);
  const head = (rows.shift() || []).map((h) => h.trim());
  return rows.filter((r) => r.some((x) => x.trim() !== '')).map((r) => Object.fromEntries(head.map((h, i) => [h, r[i] === undefined ? '' : r[i]])));
}

const TEMP_LINUX = /^(\/tmp\/|\/var\/tmp\/|\/dev\/shm\/)/;
const TEMP_WIN = /\\(appdata\\local\\temp|windows\\temp|users\\public)\\/i;
const SHELLS = new Set(['bash', 'sh', 'dash', 'zsh', 'ksh', 'nc', 'ncat', 'netcat', 'socat']);
const CRON_BAD = /(\/tmp\/|\/var\/tmp\/|\/dev\/shm\/|(curl|wget)\b[^|]*\|\s*(ba)?sh\b|base64\s+(-d|--decode))/;
// -e/-ec/-enc/-encodedcommand only counts after powershell or pwsh: plenty of programs take a harmless -e
const TASK_BAD = /(\\(appdata\\local\\temp|windows\\temp|users\\public)\\|(powershell|pwsh)(\.exe)?\b.*\s-(e|ec|enc|encodedcommand)\s|mshta(\.exe)?\s+https?:|rundll32(\.exe)?\s+.*https?:|(powershell|pwsh)(\.exe)?\b.*\b(iwr|invoke-webrequest|downloadstring)\b)/i;
const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
export const BRUTE_FAILURES = 5;

// ── analyse: evidence → facts → proposals ────────────────────────────────────────────────────────────────────────
// evidence: { os, host, collectedAt, outputs: { <command id>: text }, files: [{ id, path, mtime, text }] }
export function analyse(evidence) {
  if (!isObj(evidence)) return { ok: false, why: 'give an evidence bundle (from: node bin/ir.mjs collect)' };
  const os = evidence.os;
  if (collectionPlan(os) === null) return { ok: false, why: 'unknown os: use "linux" or "windows"' };
  const out = isObj(evidence.outputs) ? evidence.outputs : {};
  const files = Array.isArray(evidence.files) ? evidence.files.filter(isObj) : [];
  const at = ms(evidence.collectedAt);
  const facts = [];
  const fact = (rule, title, severity, source, line, detail) => facts.push({ id: 'F' + (facts.length + 1), rule, title, severity, source, line, detail });

  if (os === 'linux') {
    lines(out.processes).forEach((l, i) => {
      const m = l.trim().match(/^(\d+)\s+(\S+)\s+\w{3}\s+\w{3}\s+\d+\s+[\d:]+\s+\d{4}\s+(.+)$/);
      if (m !== null && TEMP_LINUX.test(m[3])) fact('proc-temp', 'A process is running from a temporary folder', 'high', 'command: processes', i + 1, { pid: m[1], user: m[2], command: m[3] });
    });
    lines(out.sockets).forEach((l, i) => {
      const m = l.match(/^(\S+)\s+(\S+)\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s+users:\(\("([^"]+)",pid=(\d+)/);
      if (m !== null && SHELLS.has(m[5]) && (m[2] === 'ESTAB' || m[2] === 'LISTEN')) fact('shell-socket', 'A shell or netcat is holding a network connection', 'high', 'command: sockets', i + 1, { pid: m[6], program: m[5], state: m[2], local: m[3], peer: m[4] });
    });
    lines(out.accounts).forEach((l, i) => {
      const p = l.split(':');
      if (p.length >= 7 && p[2] === '0' && p[0] !== 'root') fact('uid0', 'An account other than root has user id 0 (full control)', 'high', 'command: accounts', i + 1, { user: p[0] });
    });
    const tries = new Map();
    lines(out['ssh-log']).forEach((l, i) => {
      const f = l.match(/Failed password for (?:invalid user )?(\S+) from (\S+)/), a = l.match(/Accepted (?:password|publickey|keyboard-interactive\/pam) for (\S+) from (\S+)/);
      if (f !== null) { const t = tries.get(f[2]) || { fails: 0, users: new Set(), success: null }; t.fails = t.fails + 1; t.users.add(f[1]); tries.set(f[2], t); }
      if (a !== null) { const t = tries.get(a[2]); if (t !== undefined && t.fails >= BRUTE_FAILURES && t.success === null) t.success = { user: a[1], line: i + 1 }; }
    });
    for (const [ip, t] of tries) if (t.success !== null) fact('brute-then-success', 'Repeated failed logins, then a successful one, from the same address', 'high', 'command: ssh-log', t.success.line, { ip, user: t.success.user, failures: t.fails });
    for (const f of files) {
      if (f.id === 'cron') lines(f.text).forEach((l, i) => { const s = l.trim(); if (s !== '' && !s.startsWith('#') && CRON_BAD.test(s)) fact('cron-suspicious', 'A scheduled job runs from a temporary folder, or downloads and runs code', 'high', 'file: ' + str(f.path), i + 1, { path: str(f.path), line: s }); });
      if (f.id === 'ssh-keys') { const age = at - ms(f.mtime); if (Number.isFinite(age) && age >= 0 && age <= 7 * DAY) fact('keys-recent', 'An SSH authorized_keys file changed in the last 7 days', 'medium', 'file: ' + str(f.path), 0, { path: str(f.path), changed: str(f.mtime) }); }
    }
  } else {
    parseCsv(out.processes).forEach((r, i) => { if (TEMP_WIN.test(str(r.ExecutablePath))) fact('proc-temp', 'A process is running from a temporary or public folder', 'high', 'command: processes', i + 2, { pid: str(r.ProcessId), name: str(r.Name), path: str(r.ExecutablePath) }); });
    parseCsv(out.tasks).forEach((r, i) => { const run = str(r['Task To Run']); if (TASK_BAD.test(' ' + run + ' ')) fact('task-suspicious', 'A scheduled task runs from a temporary folder, runs encoded PowerShell, or fetches code', 'high', 'command: tasks', i + 2, { task: str(r.TaskName), runs: run }); });
    parseCsv(out.services).forEach((r, i) => { if (TEMP_WIN.test(str(r.PathName)) || /\\appdata\\/i.test(str(r.PathName))) fact('service-temp', 'A service runs from a temporary folder or a user\'s AppData folder', 'high', 'command: services', i + 2, { service: str(r.Name), path: str(r.PathName), startMode: str(r.StartMode), state: str(r.State) }); });
    const tries = new Map();
    parseCsv(out.logons).sort((a, b) => ms(a.Time) - ms(b.Time)).forEach((r, i) => {
      const ip = str(r.Ip), user = str(r.User);
      if (ip === '' || ip === '-') return;
      const t = tries.get(ip) || { fails: 0, success: null };
      if (str(r.Id) === '4625') t.fails = t.fails + 1;
      if (str(r.Id) === '4624' && t.fails >= BRUTE_FAILURES && t.success === null) t.success = { user, line: i + 2 };
      tries.set(ip, t);
    });
    for (const [ip, t] of tries) if (t.success !== null) fact('brute-then-success', 'Repeated failed logons, then a successful one, from the same address', 'high', 'command: logons', t.success.line, { ip, user: t.success.user, failures: t.fails });
  }
  return { ok: true, os, host: str(evidence.host), facts, proposals: facts.flatMap((f) => propose(os, f)) };
}

// ── proposals: what a person could do, with the exact command and its undo ─────────────────────────────────────────
// A value only goes into a command if it is safe there: a pid of digits, an IPv4 address, a plain account or task
// name, a path without quotes or shell metacharacters. Anything else becomes a "check by hand" step with no command.
// A name may not start with "-" (it would be read as an option) and holds no "$" (a shell would expand it). A path holds
// nothing a shell or cmd.exe would act on inside double quotes; a Linux path must be absolute. PowerShell values go in
// single quotes, where nothing is expanded, and no safe value holds a quote.
const safePid = (x) => /^\d{1,10}$/.test(x);
export function safeIp(x) { const m = typeof x === 'string' ? x.match(IPV4) : null; return m !== null && m.slice(1).every((o) => Number(o) <= 255); }
const safeName = (x) => typeof x === 'string' && /^[A-Za-z0-9_][A-Za-z0-9._\-]{0,63}$/.test(x);
const safePath = (x) => typeof x === 'string' && x !== '' && !/["'`$;&|<>\n\r!%]/.test(x);
const safeLinuxPath = (x) => safePath(x) && x.startsWith('/') && !x.includes('\\');
const safeTask = (x) => typeof x === 'string' && /^\\?[A-Za-z0-9 ._\-\\]{1,200}$/.test(x);

// commandLine(argv) → the line a person types to run it. A plain argument is left as it is; any other is wrapped in
// double quotes (no argument a proposal builds holds a double quote, so the quoting is exact).
export function commandLine(argv) {
  return Array.isArray(argv) ? argv.map((a) => (/^[A-Za-z0-9._\-\/:=@,+]+$/.test(String(a)) ? String(a) : '"' + String(a) + '"')).join(' ') : '';
}

function step(f, n, kind, does, run, undo) {
  return { id: f.id + '.' + n, fact: f.id, kind, does, run: run === null ? null : Object.freeze(run), undo: undo === null ? null : Object.freeze(undo), reversible: undo !== null };
}
function byHand(f, n, does) { return { id: f.id + '.' + n, fact: f.id, kind: 'check', does, run: null, undo: null, reversible: true }; }

export function propose(os, f) {
  if (!isObj(f) || !isObj(f.detail)) return [];
  const d = f.detail;
  if (os === 'linux') {
    if (f.rule === 'proc-temp' || f.rule === 'shell-socket') {
      if (!safePid(d.pid)) return [byHand(f, 1, 'Check this process by hand: its id is not in the expected form')];
      return [
        step(f, 1, 'preserve', 'Save a copy of the running program for analysis', ['cp', '/proc/' + d.pid + '/exe', '/var/tmp/ir-evidence-' + d.pid + '.bin'], null),
        step(f, 2, 'contain', 'Pause the process (it keeps its memory, and can be resumed)', ['kill', '-STOP', d.pid], ['kill', '-CONT', d.pid]),
        step(f, 3, 'eradicate', 'End the process (cannot be undone)', ['kill', '-KILL', d.pid], null),
      ];
    }
    if (f.rule === 'uid0') return safeName(d.user) ? [step(f, 1, 'contain', 'Lock the account', ['usermod', '-L', d.user], ['usermod', '-U', d.user])] : [byHand(f, 1, 'Check this account by hand: its name is not in the expected form')];
    if (f.rule === 'brute-then-success') {
      const p = [];
      if (safeIp(d.ip)) p.push(step(f, p.length + 1, 'contain', 'Block the address', ['iptables', '-I', 'INPUT', '-s', d.ip, '-j', 'DROP'], ['iptables', '-D', 'INPUT', '-s', d.ip, '-j', 'DROP']));
      if (safeName(d.user)) p.push(step(f, p.length + 1, 'contain', 'Lock the account that was logged into', ['usermod', '-L', d.user], ['usermod', '-U', d.user]));
      return p.length > 0 ? p : [byHand(f, 1, 'Check this login by hand: the address or account is not in the expected form')];
    }
    if (f.rule === 'cron-suspicious' || f.rule === 'keys-recent') {
      if (!safeLinuxPath(d.path)) return [byHand(f, 1, 'Check this file by hand: its path is not in the expected form')];
      return [step(f, 1, 'preserve', 'Save a copy of the file', ['cp', '-p', d.path, d.path + '.ir-evidence'], null),
        byHand(f, 2, f.rule === 'cron-suspicious' ? 'Remove or comment out the job after reviewing it' : 'Review each key, and remove any you do not recognise')];
    }
    return [];
  }
  if (f.rule === 'proc-temp') {
    const p = [];
    if (safePath(d.path)) p.push(step(f, 1, 'preserve', 'Record the file\'s hash for analysis', ['powershell.exe', '-NoProfile', '-Command', 'Get-FileHash -LiteralPath \'' + d.path + '\' | Format-List'], null));
    if (safePid(d.pid)) p.push(step(f, p.length + 1, 'eradicate', 'End the process (cannot be undone)', ['taskkill.exe', '/PID', d.pid, '/F'], null));
    return p.length > 0 ? p : [byHand(f, 1, 'Check this process by hand: its id or path is not in the expected form')];
  }
  if (f.rule === 'task-suspicious') return safeTask(d.task) ? [step(f, 1, 'contain', 'Disable the scheduled task', ['schtasks.exe', '/change', '/tn', d.task, '/disable'], ['schtasks.exe', '/change', '/tn', d.task, '/enable'])] : [byHand(f, 1, 'Check this task by hand: its name is not in the expected form')];
  if (f.rule === 'service-temp') {
    if (!safeName(d.service)) return [byHand(f, 1, 'Check this service by hand: its name is not in the expected form')];
    const back = { Auto: 'auto', Manual: 'demand', Disabled: 'disabled' }[str(d.startMode)] || 'demand';
    const p = [step(f, 1, 'contain', 'Stop the service starting again (it stays disabled until undone)', ['sc.exe', 'config', d.service, 'start=', 'disabled'], ['sc.exe', 'config', d.service, 'start=', back])];
    if (str(d.state) === 'Running') p.push(step(f, 2, 'contain', 'Stop the running service', ['sc.exe', 'stop', d.service], ['sc.exe', 'start', d.service]));
    return p;
  }
  if (f.rule === 'brute-then-success') {
    const p = [];
    if (safeIp(d.ip)) p.push(step(f, 1, 'contain', 'Block the address in Windows Firewall', ['powershell.exe', '-NoProfile', '-Command', 'New-NetFirewallRule -DisplayName \'IR block ' + d.ip + '\' -Direction Inbound -RemoteAddress ' + d.ip + ' -Action Block'], ['powershell.exe', '-NoProfile', '-Command', 'Remove-NetFirewallRule -DisplayName \'IR block ' + d.ip + '\'']));
    if (safeName(d.user)) p.push(step(f, p.length + 1, 'contain', 'Disable the local account that was logged into', ['powershell.exe', '-NoProfile', '-Command', 'Disable-LocalUser -Name \'' + d.user + '\''], ['powershell.exe', '-NoProfile', '-Command', 'Enable-LocalUser -Name \'' + d.user + '\'']));
    return p.length > 0 ? p : [byHand(f, 1, 'Check this logon by hand: the address or account is not in the expected form')];
  }
  return [];
}

// ── the log: every collection, analysis, approval and refusal, chained by hash ────────────────────────────────────
// entry = { seq, at, kind, data, prev, hash }, hash = sha256(seq|at|kind|JSON(data)|prev)
const entryHash = (e) => sha256(e.seq + '|' + e.at + '|' + e.kind + '|' + JSON.stringify(e.data) + '|' + e.prev);
export function append(log, kind, data, at) {
  const list = Array.isArray(log) ? log : [];
  const last = list[list.length - 1];
  const prev = isObj(last) ? str(last.hash) : 'genesis';
  const e = { seq: list.length + 1, at: str(at), kind: str(kind), data: data === undefined ? null : data, prev };
  return list.concat([{ ...e, hash: entryHash(e) }]);
}
// verifyLog(log, anchor?) → { ok, entries, brokenAt, anchoredAt } — brokenAt is the seq of the first entry that does
// not match. The chain alone catches an edit, a removal or a reordering, but not someone who rewrites every hash after
// the entry they changed. So record the latest hash somewhere else (the ticket, an email): given as anchor, it must
// still be in the chain, which fixes every entry up to it.
export function verifyLog(log, anchor) {
  if (!Array.isArray(log)) return { ok: false, entries: 0, brokenAt: 0, anchoredAt: null };
  const want = str(anchor);
  let prev = 'genesis', at = null;
  for (let i = 0; i < log.length; i++) {
    const e = log[i];
    if (!isObj(e) || e.seq !== i + 1 || e.prev !== prev || e.hash !== entryHash(e)) return { ok: false, entries: log.length, brokenAt: i + 1, anchoredAt: null };
    if (e.hash === want) at = e.seq;
    prev = e.hash;
  }
  return { ok: want === '' || at !== null, entries: log.length, brokenAt: null, anchoredAt: at };
}

export default { VERSION, MAX_SCOPE_DAYS, BRUTE_FAILURES, sha256, checkScope, COLLECT, collectionPlan, parseCsv, analyse, propose, safeIp, commandLine, append, verifyLog };
