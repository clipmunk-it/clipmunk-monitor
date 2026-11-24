# clipmunk-monitor

A tiny public watchdog for the private clipmunk bot repos.

It runs hourly and enforces **exactly one active bot account**:

1. Reads `ACCOUNTS_JSON` (repo secret) — the account tokens.
2. Finds which bot repo has Actions enabled (the real active account).
3. Estimates that account's monthly Actions minutes and looks for the
   "job never started" exhaustion signature.
4. If the active account is exhausted, it:
   - disables the old account's Actions and cancels its runs,
   - waits for its final state commit,
   - clones code + state,
   - force-copies `main` to the least-recently-used standby,
   - sets `CONFIG_ENV_B64` on the standby from the secret,
   - enables the standby and dispatches a read-only preflight,
   - alerts Telegram.

Because this repository is **public**, its Actions minutes are free and do
not consume the private bot repos' 2,000-minute allowance. No tokens or
config are stored in the code; only repo secrets.

## Secrets

- `ACCOUNTS_JSON` — the same JSON kept at `~/.clipmunk/accounts.json`
  (tokens with `repo` + `workflow`).
- `CONFIG_ENV_B64` — base64 of the bot's `config.env`.

## Commands

Manual run: **Actions → clipmunk-monitor → Run workflow**.

Local equivalents live in `~/.clipmunk/switch_account.py`.
