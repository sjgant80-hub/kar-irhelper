# Kar IR Helper

**Live: https://sjgant80-hub.github.io/kar-irhelper/**

An incident-response helper for hosts you own. It reads evidence with a fixed list of read-only commands, finds the tell-tale facts, and proposes what to do, with the exact command and how to undo it. **It never acts on its own.** A person approves each step and runs it, and every step goes into a hash-chained log. It will not start without a written authorization naming that host. Part of [Sovereign AI-Security](https://sjgant80-hub.github.io/sovereign-ai-security/). Built by Kar for [AI Native Solutions](https://www.ai-nativesolutions.com/).

```bash
node bin/ir.mjs scope-template > scope.json      # fill in who authorized it, why, until when (30 days at most)
node bin/ir.mjs collect --scope scope.json --dry-run   # exactly what it would run
node bin/ir.mjs collect --scope scope.json       # read-only evidence → evidence.json
node bin/ir.mjs analyse evidence.json            # facts, each with where it was found, and proposals
node bin/ir.mjs approve F1.2 --evidence evidence.json --by "Your name"   # records it, prints the command; you run it
node bin/ir.mjs verify-log --anchor <hash>       # the chain, and a hash you recorded in the ticket
```

Node 18 or later, no install, Linux or Windows. Run it as a user who can read the host's processes and logs (root or an administrator).

## What it looks for

| Linux | Windows |
|---|---|
| a process running from `/tmp`, `/var/tmp` or `/dev/shm` | a process running from a Temp or Public folder |
| a shell or netcat holding a network connection | a scheduled task that runs from a temp folder, runs encoded PowerShell, or fetches code |
| an account other than root with user id 0 | a service running from a temp folder or a user's AppData |
| 5+ failed SSH logins, then a success, from one address | 5+ failed logons (4625), then a success (4624), from one address |
| a cron job that runs from a temp folder or downloads and runs code | |
| an SSH `authorized_keys` file changed in the last 7 days | |

Each fact cites the command or file and the line it came from. Each proposal is **preserve** (copy the program or file, or record its hash), **contain** (pause, lock, block, disable; each with its exact undo), or **eradicate** (end a process; marked as not reversible).

## Why it is safe to point at a compromised host

- **No authorization, no run.** `collect` refuses unless the scope names this host, a person, a purpose, and an expiry no more than 30 days after it was granted. The refusal is logged.
- **Read-only by construction.** The collection commands are a fixed, frozen list run with no shell. A test fails if any of them uses a command that changes things.
- **Crafted evidence cannot inject a command.** A value only reaches a proposed command in a safe form: no leading dash, no quotes, `$`, `%`, `!` or shell operators. Anything else becomes a "check by hand" step with no command.
- **It cannot act.** The kernel (`ir.mjs`) cannot run anything. The command line runs exactly one thing, the collection loop over the allow-list.
- **The log shows edits.** Each entry is chained by SHA-256 to the one before it. Someone could still rewrite every hash after the entry they changed. So each step prints the latest hash: record it in the ticket, and `verify-log --anchor` proves every entry up to it is as it was.

## Proven on real hosts

On every change, CI ([`irhelper.yml`](.github/workflows/irhelper.yml)) runs on a throwaway GitHub Linux runner and a throwaway Windows runner. On each one it:

1. plants real signs of compromise (a program running from a temp folder, a bash holding a socket, a second uid-0 account, a new SSH key, a cron job, a scheduled task and a service running from Temp);
2. checks that `collect` refuses without an authorization for that host;
3. collects and analyses;
4. checks that every planted sign is found;
5. then **runs each proposed command and its undo** ([`tools/ci-proof.mjs`](tools/ci-proof.mjs) stands in for the person approving it), and checks that each did what it says.

The log must verify, and must fail when an entry is edited. The kernel's tests are themselves tested: [witness](https://github.com/sjgant80-hub/witness) v0.6 breaks `ir.mjs` one operator at a time, and every break must be caught.

## Limits

Ten rules are not an EDR: its silence is not an all-clear. A fact is a lead, not a verdict: on a fresh GitHub runner it also flags the runner's own provisioning agent (it runs from a temp folder) and the SSH keys provisioning has just written, both real matches and both harmless. It covers Linux and Windows only, and some evidence needs administrator rights. The scheduled-task rule reads English column names. The Linux block steps use `iptables`, and the account steps cover local accounts only. Linux SSH logins are read from the systemd journal. It proposes and does not remediate, and a proposal is not legal or forensic advice. For a serious incident, bring in responders and hand them the evidence file and the log.

## Files

`ir.mjs` the kernel (scope check, allow-list, rules, proposals, hash chain) · `ir.test.mjs` · `bin/ir.mjs` the command line · `index.html` the live page (runs `ir.mjs` byte for byte, via `tools/inline.mjs`) · `page-parity.test.mjs` · `data/` synthetic demo evidence (`tools/make-demo.mjs`) · `tools/ci-proof.mjs` the CI proof.

MIT © Simon Gant. Supplier: AI Native Solutions.
