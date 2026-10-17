"""Smoke test: public-mode UI against a password-protected FalkorDB server (Cloud stand-in)."""
import json, os, secrets, subprocess, sys, time, urllib.request, urllib.error

sys.path.insert(0, os.getcwd())
from reach.dbserver import free_port, start  # noqa: E402

scratch = os.environ["KIROCREW_SCRATCH"]
pw, dbport, webport = secrets.token_hex(12), free_port(), free_port()
db = start(dbport, os.path.join(scratch, "smoke-db"), password=pw)
env = {**os.environ, "FALKORDB_HOST": "127.0.0.1", "FALKORDB_PORT": str(dbport), "FALKORDB_PASSWORD": pw,
       "REACH_PUBLIC": "1", "REACH_RATE_PER_MIN": "30", "PORT": str(webport), "REACH_HOST": "127.0.0.1",
       "KIROCREW_SCRATCH": scratch}
web = subprocess.Popen([sys.executable, "-m", "reach.web"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
base = f"http://127.0.0.1:{webport}"


def get(path, body=None):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


try:
    for _ in range(50):
        try:
            urllib.request.urlopen(base + "/", timeout=1)
            break
        except Exception:
            time.sleep(0.2)
    print("config", get("/api/config"))
    s, p = get("/api/paths?estate=real")
    print("real paths", s, len(p.get("paths", [])))
    s, r = get("/api/redteam?estate=demo", {"scenario": "cross-agent", "llm": True})
    print("redteam", s, r.get("victim"), [x["exfiltrated"] for x in r.get("runs", [])])
    s, r = get("/api/gateway/run", {"scenario": "cross-agent", "llm": False})
    print("gateway", s, [(x["mode"], bool(x["exfiltrated"])) for x in r.get("runs", [])] if s == 200 else r)
    print("mine refused", get("/api/setup", {"which": "mine"}))
    codes = [get("/api/config")[0] for _ in range(30)]
    print("rate limit: 429 after", codes.index(429) if 429 in codes else "never")
finally:
    web.terminate(); db.terminate()
