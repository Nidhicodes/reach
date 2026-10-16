"""Run a real FalkorDB server locally, without Docker.

falkordblite already ships `redis-server` and the FalkorDB module (`falkordb.so`); this
starts them as a normal TCP server on 127.0.0.1 so several processes (two gateways, the
UI, a benchmark) share ONE graph -- the same thing `docker run falkordb/falkordb` gives.

  uv run python -m reach.dbserver [--port 6390] [--dir DATA_DIR]
  export FALKORDB_HOST=127.0.0.1 FALKORDB_PORT=6390

Bound to loopback only. For anything public use FalkorDB Cloud (TLS + auth).
"""

from __future__ import annotations

import argparse
import os
import pathlib
import socket
import subprocess
import time


def binaries() -> tuple[str, str]:
    import redislite

    b = pathlib.Path(redislite.__file__).parent / "bin"
    return str(b / "redis-server"), str(b / "falkordb.so")


def start(port: int, data_dir: str, password: str | None = None) -> subprocess.Popen:
    server, module = binaries()
    os.makedirs(data_dir, exist_ok=True)
    cmd = [server, "--port", str(port), "--bind", "127.0.0.1", "--protected-mode", "yes",
           "--dir", data_dir, "--save", "", "--appendonly", "no", "--loadmodule", module]
    if password:
        cmd += ["--requirepass", password]
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return p
        except OSError:
            if p.poll() is not None:
                raise RuntimeError(f"redis-server exited with {p.returncode}")
            time.sleep(0.05)
    p.kill()
    raise RuntimeError("FalkorDB server did not start")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=6390)
    ap.add_argument("--dir", default=".falkordb")
    a = ap.parse_args()
    p = start(a.port, a.dir)
    print(f"FalkorDB on 127.0.0.1:{a.port}\n  export FALKORDB_HOST=127.0.0.1 FALKORDB_PORT={a.port}")
    try:
        p.wait()
    except KeyboardInterrupt:
        p.terminate()


if __name__ == "__main__":
    main()
