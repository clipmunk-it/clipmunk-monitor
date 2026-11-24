#!/usr/bin/env python3
"""Cold-standby switch + automatic minute monitor for clipmunk accounts.

Commands:
    switch_account.py --list
    switch_account.py --status
    switch_account.py --auto
    switch_account.py <target-account-name>

`--auto` is what the launchd monitor calls. It:
  * estimates the active account's Actions minutes this month (run_started_at
    -> updated_at, rounded up);
  * detects the "job never started" exhaustion signature (completed failure,
    <=20s, no runner/steps) repeated twice;
  * defers while a run is queued/in progress;
  * switches to the least-recently-used standby, one active at a time;
  * notifies Telegram before/after, and never prints tokens.

Tokens live in ~/.clipmunk/accounts.json (mode 600).
"""
import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

ACCOUNTS = os.path.expanduser("~/.clipmunk/accounts.json")
DEFAULT_CONFIG = "/Users/mac/Downloads/clipmunk/config.env"
LOCAL_REPO = os.environ.get("CLIPMUNK_REPO", "/Users/mac/Downloads/clipmunk")
API = "https://api.github.com"

NEAR_LIMIT_MINUTES = 1800     # 90% of the 2,000 free minutes
INFRA_FAILURE_SECONDS = 20    # a blocked job dies in ~3s, no steps
MAX_SWITCH_PER_HOUR = 1
MONTHLY_INCLUDED_MINUTES = 2000
CLOUD = bool(os.environ.get("CLIPMUNK_CLOUD"))


# --------------------------------------------------------------------------- #
# state + API
# --------------------------------------------------------------------------- #
def load_accounts():
    with open(ACCOUNTS, encoding="utf-8") as fh:
        return json.load(fh)


def save_accounts(data):
    tmp = ACCOUNTS + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1)
    os.replace(tmp, ACCOUNTS)


def find(data, name):
    for a in data.get("accounts", []):
        if a.get("name") == name:
            return a
    raise SystemExit("unknown account: {}".format(name))


def api(token, method, path, body=None, allow=()):
    req = urllib.request.Request(
        API + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": "Bearer " + token,
                 "Accept": "application/vnd.github+json",
                 "User-Agent": "clipmunk-switch",
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=90) as fh:
            raw = fh.read()
            return json.loads(raw) if raw.strip() else None
    except urllib.error.HTTPError as exc:
        if exc.code in allow:
            return None
        raise RuntimeError("GitHub {} {} -> {}: {}".format(
            method, path, exc.code, exc.read().decode()[:200]))


def login(token):
    return api(token, "GET", "/user")["login"]


def ensure_repo(token, user, repo):
    r = api(token, "GET", "/repos/{}/{}".format(user, repo), allow=(404,))
    if r is None:
        api(token, "POST", "/user/repos", {"name": repo, "private": True,
            "description": "clipmunk posting engine (cold standby)",
            "has_issues": False, "has_wiki": False, "has_projects": False})
        print("  created private repo {}/{}".format(user, repo))


def actions_enabled(token, user, repo):
    return bool(api(token, "GET",
                    "/repos/{}/{}/actions/permissions".format(user, repo))
                .get("enabled"))


def set_actions(token, user, repo, enabled):
    api(token, "PUT", "/repos/{}/{}/actions/permissions".format(user, repo),
        {"enabled": bool(enabled)})


def last_run_epoch(token, user, repo):
    """When this repo last finished a run (0 when it never has)."""
    try:
        runs = api(token, "GET",
                   "/repos/{}/{}/actions/runs?per_page=1".format(
                       user, repo)).get("workflow_runs") or []
        if not runs:
            return 0.0
        d = _parse(runs[0].get("updated_at"))
        return d.timestamp() if d else 0.0
    except Exception:  # noqa: BLE001 - unknown age just sorts first
        return 0.0


def enabled_accounts(data):
    """Accounts with Actions ON, newest run first.

    The enabled flag is the real source of truth: a cloud monitor may not be
    able to persist an `active` field (the tokens live in a secret), but it
    can always see which repos are allowed to run.
    """
    out = []
    for a in data.get("accounts", []):
        try:
            if not a.get("user"):
                a["user"] = login(a["token"])
            if actions_enabled(a["token"], a["user"], a["repo"]):
                out.append(a)
        except Exception:  # noqa: BLE001 - a bad token is not the active one
            continue
    out.sort(key=lambda a: last_run_epoch(a["token"], a["user"], a["repo"]),
             reverse=True)
    return out


def cancel_runs(token, user, repo):
    for status in ("queued", "in_progress"):
        runs = api(token, "GET",
                   "/repos/{}/{}/actions/runs?status={}&per_page=20".format(
                       user, repo, status)).get("workflow_runs") or []
        for run in runs:
            api(token, "POST",
                "/repos/{}/{}/actions/runs/{}/cancel".format(
                    user, repo, run["id"]), allow=(409,))
            print("  cancelled run", run["id"])


def set_secret(token, user, repo, config_path):
    from nacl import encoding, public
    pub = api(token, "GET",
              "/repos/{}/{}/actions/secrets/public-key".format(user, repo))
    box = public.SealedBox(
        public.PublicKey(pub["key"].encode(), encoding.Base64Encoder()))
    payload = base64.b64encode(open(config_path, "rb").read())
    api(token, "PUT",
        "/repos/{}/{}/actions/secrets/CONFIG_ENV_B64".format(user, repo),
        {"encrypted_value": base64.b64encode(box.encrypt(payload)).decode(),
         "key_id": pub["key_id"]})


# --------------------------------------------------------------------------- #
# health
# --------------------------------------------------------------------------- #
def _parse(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def account_health(token, user, repo):
    runs = api(token, "GET",
               "/repos/{}/{}/actions/runs?per_page=40".format(user, repo)
               ).get("workflow_runs") or []
    now = datetime.now(timezone.utc)
    month_start = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
    minutes = 0.0
    for r in runs:
        started = _parse(r.get("run_started_at") or r.get("created_at"))
        ended = _parse(r.get("updated_at"))
        if not started or not ended or started < month_start:
            continue
        minutes += max(0.0, (ended - started).total_seconds() / 60.0)
    busy = any(r.get("status") in ("queued", "in_progress") for r in runs)
    recent = [r for r in runs if r.get("status") == "completed"][:4]
    infra_failures = 0
    for r in recent:
        if r.get("conclusion") != "failure":
            break
        started = _parse(r.get("run_started_at") or r.get("created_at"))
        ended = _parse(r.get("updated_at"))
        if started and ended and (ended - started).total_seconds() > \
                INFRA_FAILURE_SECONDS:
            break
        try:
            jobs = api(token, "GET",
                       "/repos/{}/{}/actions/runs/{}/jobs".format(
                           user, repo, r["id"])).get("jobs") or []
        except Exception:  # noqa: BLE001 - unknown, don't count it
            break
        if any((j.get("steps") or []) for j in jobs):
            break  # real job ran: a code failure, not an account block
        infra_failures += 1
    quota_pct = int(min(100.0, minutes / MONTHLY_INCLUDED_MINUTES * 100.0))
    exhausted = infra_failures >= 2
    near = minutes >= NEAR_LIMIT_MINUTES
    return {"minutes": round(minutes), "quota_pct": quota_pct,
            "busy": busy, "infra_failures": infra_failures,
            "exhausted": exhausted, "near_limit": near,
            "healthy": not (exhausted or near), "runs": len(runs)}


# --------------------------------------------------------------------------- #
# notifications
# --------------------------------------------------------------------------- #
def notify(text):
    try:
        cfg = {}
        with open(DEFAULT_CONFIG, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    cfg[k.strip()] = v.split("#", 1)[0].strip()
        token = cfg.get("TELEGRAM_BOT_TOKEN")
        chat = cfg.get("TELEGRAM_CHAT_ID")
        if not token or not chat:
            return
        data = urllib.parse.urlencode({"chat_id": chat,
                                       "text": text[:3900]}).encode()
        req = urllib.request.Request(
            "https://api.telegram.org/bot{}/sendMessage".format(token),
            data=data)
        urllib.request.urlopen(req, timeout=30).read()
    except Exception:  # noqa: BLE001 - a failed alert never blocks a switch
        pass


def alert_once(data, key, text, cooldown_h=6):
    """Do not repeat the same account alert every 20 minutes."""
    last = float(data.get(key) or 0)
    if time.time() - last < cooldown_h * 3600:
        return
    notify(text)
    data[key] = time.time()
    save_accounts(data)


# --------------------------------------------------------------------------- #
# switching
# --------------------------------------------------------------------------- #
def clone_active(account, workdir):
    url = "https://x-access-token:{}@github.com/{}/{}.git".format(
        account["token"], account["user"], account["repo"])
    target = os.path.join(workdir, "active")
    subprocess.run(["git", "clone", "--quiet", url, target],
                   check=True, capture_output=True, timeout=600)
    return target


def push_to(clone, target):
    url = "https://x-access-token:{}@github.com/{}/{}.git".format(
        target["token"], target["user"], target["repo"])
    subprocess.run(["git", "-C", clone, "push", "--force", url,
                    "main:main"], check=True, capture_output=True, timeout=600)


def dispatch_preflight(token, user, repo):
    api(token, "POST",
        "/repos/{}/{}/actions/workflows/clipmunk.yml/dispatches".format(
            user, repo), {"ref": "main", "inputs": {"preflight_only": True}})


def switch_to(data, target_name, config_path, reason=""):
    active = find(data, data.get("active"))
    target = find(data, target_name)
    for acct in (active, target):
        acct["user"] = login(acct["token"])
        print("  {} -> {}".format(acct["name"], acct["user"]))
    old_enabled = actions_enabled(active["token"], active["user"], active["repo"])
    target_enabled = False
    try:
        print("1/6 disabling + cancelling {}...".format(active["name"]))
        set_actions(active["token"], active["user"], active["repo"], False)
        cancel_runs(active["token"], active["user"], active["repo"])
        time.sleep(12)  # let the workflow's always() state commit land

        print("2/6 cloning {}...".format(active["name"]))
        with tempfile.TemporaryDirectory(prefix="clipmunk-switch-") as tmp:
            clone = clone_active(active, tmp)
            head = subprocess.run(["git", "-C", clone, "log", "-1",
                                   "--format=%h %s"], capture_output=True,
                                  text=True).stdout.strip()
            print("  head:", head)

            print("3/6 preparing {}...".format(target["name"]))
            ensure_repo(target["token"], target["user"], target["repo"])
            set_actions(target["token"], target["user"], target["repo"], False)

            print("4/6 copying code + state...")
            push_to(clone, target)

        print("5/6 setting secret + enabling {}...".format(target["name"]))
        set_secret(target["token"], target["user"], target["repo"], config_path)
        set_actions(target["token"], target["user"], target["repo"], True)
        target_enabled = True

        # Point this checkout at the live account. Credentials stay in the
        # login keychain; the token is only written to the helper's stdin.
        if os.path.isdir(LOCAL_REPO):
            subprocess.run(["git", "-C", LOCAL_REPO, "remote", "set-url",
                            "origin", "https://github.com/{}/{}.git".format(
                                target["user"], target["repo"])],
                           capture_output=True, timeout=60)
            subprocess.run(["git", "-C", LOCAL_REPO, "config",
                            "credential.username", target["user"]],
                           capture_output=True, timeout=60)
            payload = ("protocol=https\nhost=github.com\nusername={}\n"
                       "password={}\n\n".format(target["user"], target["token"]))
            subprocess.run(["git", "credential-osxkeychain", "store"],
                           input=payload, text=True, capture_output=True,
                           timeout=60)
            print("  local origin -> {}/{}".format(target["user"], target["repo"]))

        now = time.time()
        data["active"] = target_name
        data["last_switch_at"] = now
        data["last_switch_reason"] = reason
        target["last_active"] = now
        save_accounts(data)

        print("6/6 preflight on {}...".format(target["name"]))
        dispatch_preflight(target["token"], target["user"], target["repo"])
        time.sleep(15)
        runs = api(target["token"], "GET",
                   "/repos/{}/{}/actions/runs?per_page=3".format(
                       target["user"], target["repo"])).get("workflow_runs") or []
        if runs:
            r = runs[0]
            print("  run {} {} {}".format(r["id"], r["status"],
                                          r["conclusion"] or "-"))
        print("active is now {}".format(target_name))
        return True
    except Exception:
        # A half-finished switch must never leave two accounts live.
        try:
            if target_enabled:
                set_actions(target["token"], target["user"], target["repo"],
                            False)
            if old_enabled:
                set_actions(active["token"], active["user"], active["repo"],
                            True)
        except Exception:  # noqa: BLE001 - best effort restore
            pass
        data["active"] = active["name"]
        save_accounts(data)
        if os.path.isdir(LOCAL_REPO):
            subprocess.run(["git", "-C", LOCAL_REPO, "remote", "set-url",
                            "origin", "https://github.com/{}/{}.git".format(
                                active["user"], active["repo"])],
                           capture_output=True, timeout=60)
        raise


# --------------------------------------------------------------------------- #
# auto mode
# --------------------------------------------------------------------------- #
def auto_mode(data, config_path):
    enabled = enabled_accounts(data)
    if len(enabled) > 1:
        # Enforce one poller: keep the one that ran most recently, turn the
        # others off. A half-finished manual switch is the usual cause.
        keep = enabled[0]
        for extra in enabled[1:]:
            try:
                set_actions(extra["token"], extra["user"], extra["repo"], False)
                print("disabled duplicate active:", extra["name"])
            except Exception as exc:  # noqa: BLE001
                print("could not disable {}: {}".format(extra["name"],
                                                        str(exc)[:100]))
        notify("⚠️ clipmunk: multiple GitHub accounts had Actions on; kept {} "
               "and disabled the rest.".format(keep["name"]))
        data["active"] = keep["name"]

    active = enabled[0] if enabled else None
    if active is None:
        # Nothing is allowed to run: recover the recorded account (or the
        # least-recently-used one) so the bot is not silently dead.
        if data.get("active"):
            active = find(data, data["active"])
        else:
            active = min(data.get("accounts", []),
                         key=lambda a: last_run_epoch(
                             a["token"], a.get("user") or "", a["repo"]))
        active["user"] = active.get("user") or login(active["token"])
        print("no enabled account; restoring", active["name"])
        set_actions(active["token"], active["user"], active["repo"], True)
        set_secret(active["token"], active["user"], active["repo"], config_path)
        dispatch_preflight(active["token"], active["user"], active["repo"])
        data["active"] = active["name"]
        save_accounts(data)
        notify("⚠️ clipmunk: no account had Actions enabled; restored {} and "
               "dispatched a preflight.".format(active["name"]))
        return 0

    active["user"] = active.get("user") or login(active["token"])
    data["active"] = active["name"]
    h = account_health(active["token"], active["user"], active["repo"])
    print("active {}: {}".format(active["name"], h))
    if h["busy"]:
        print("a run is active — deferring")
        return 0
    if h["healthy"]:
        save_accounts(data)
        return 0

    # The local monitor persists last_switch_at; the cloud one relies on the
    # enabled flags, which already change atomically with each switch.
    if not CLOUD:
        last = float(data.get("last_switch_at") or 0)
        if time.time() - last < MAX_SWITCH_PER_HOUR * 3600:
            print("switched within the last hour — refusing to chain switches")
            return 0

    candidates = [a for a in data.get("accounts", [])
                  if a.get("name") != active["name"]]
    if not candidates:
        if CLOUD:
            print("no standby accounts configured")
        else:
            alert_once(data, "last_no_standby_alert",
                       "⚠️ clipmunk: {} looks exhausted ({}) and there is no "
                       "standby account configured.".format(active["name"], h))
        return 1
    for a in candidates:
        if not a.get("user"):
            try:
                a["user"] = login(a["token"])
            except Exception:  # noqa: BLE001 - invalid token sorts last
                a["user"] = ""
    candidates.sort(key=lambda a: last_run_epoch(a["token"], a["user"],
                                                 a["repo"]))
    target = candidates[0]
    why = ("Actions minutes near the monthly limit (~{} min)".format(
        h["minutes"]) if h["near_limit"] else
        "run failures with no runner/steps (account block)")
    notify("🔁 clipmunk: switching GitHub account {} → {} — {}.".format(
        active["name"], target["name"], why))
    try:
        switch_to(data, target["name"], config_path, reason=why)
    except Exception as exc:  # noqa: BLE001 - the old account is restored
        if CLOUD:
            notify("⚠️ clipmunk: switch {} → {} failed: {}".format(
                active["name"], target["name"], str(exc)[:180]))
        else:
            alert_once(data, "last_switch_fail_alert",
                       "⚠️ clipmunk: switch {} → {} failed: {}".format(
                           active["name"], target["name"], str(exc)[:180]))
        print("switch failed:", str(exc)[:180])
        return 1
    notify("✅ clipmunk is live on {} — one poller active.".format(
        target["name"]))
    return 0


def status(data):
    for a in data.get("accounts", []):
        try:
            a["user"] = login(a["token"])
            h = account_health(a["token"], a["user"], a["repo"])
            print("{:<10} {:<18} {}".format(a["name"], a["user"], h))
        except Exception as exc:  # noqa: BLE001
            print("{:<10} ERROR {}".format(a["name"], str(exc)[:120]))
    print("active:", data.get("active"))


# --------------------------------------------------------------------------- #
# entry
# --------------------------------------------------------------------------- #
def main():
    data = load_accounts()
    config_path = os.environ.get("CLIPMUNK_CONFIG", DEFAULT_CONFIG)
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print("usage: switch_account.py --list|--status|--auto|<account>")
        return 1
    cmd = args[0]
    if cmd == "--list":
        print("active:", data.get("active"))
        for a in data.get("accounts", []):
            print(" ", a["name"], a.get("user"), a.get("repo"))
        return 0
    if cmd == "--status":
        status(data)
        return 0
    if cmd == "--auto":
        return auto_mode(data, config_path)
    if cmd.startswith("-"):
        print("unknown option", cmd)
        return 1
    if cmd == data.get("active"):
        print("{} is already active".format(cmd))
        return 1
    if not os.path.exists(config_path):
        raise SystemExit("config not found: " + config_path)
    switch_to(data, cmd, config_path, reason="manual switch")
    return 0


if __name__ == "__main__":
    sys.exit(main())
