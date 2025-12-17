#!/usr/bin/env python3
"""
Lightweight FastAPI backend that:
- Starts/stops ip_range_capture.py runs
- Parses completed captures into flowlet events via packet-analysis/parse_flowlets.py
- Persists capture metadata + flowlets (LLM-tagged) into SQLite
- Serves the front-end endpoints consumed by src/App.jsx
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import signal
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# --- Paths & constants

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
DB_PATH = DATA_DIR / "captures.db"
CAPTURE_DEFAULT_OUTDIR = ROOT / "captures"
PARSE_FLOWLETS_PATH = ROOT / "packet-analysis" / "parse_flowlets.py"
IP_RANGE_CAPTURE_PATH = ROOT / "ip_range_capture.py"
UPLOAD_DIR = DATA_DIR / "uploads"

DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# --- Dynamically load parse_flowlets (hyphenated directory)

import importlib.util


def _load_parse_flowlets():
    spec = importlib.util.spec_from_file_location(
        "parse_flowlets_module", PARSE_FLOWLETS_PATH
    )
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise RuntimeError("Could not load parse_flowlets.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["parse_flowlets_module"] = mod
    spec.loader.exec_module(mod)
    return mod


parse_flowlets = _load_parse_flowlets()

# --- FastAPI app

app = FastAPI(title="Networks Project API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- DB helpers


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db() -> None:
    with get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS captures (
                id TEXT PRIMARY KEY,
                name TEXT,
                status TEXT,
                ip_range TEXT,
                interface TEXT,
                outdir TEXT,
                snaplen INTEGER,
                extra_filter TEXT,
                timeout INTEGER,
                started_at TEXT,
                ended_at TEXT,
                capture_file TEXT,
                pid INTEGER,
                flowlet_count INTEGER DEFAULT 0,
                llm_flowlet_count INTEGER DEFAULT 0,
                analysis_json TEXT,
                analyzed INTEGER DEFAULT 0
            );
            """
        )
        # Backfill analyzed column if DB existed before
        try:
            conn.execute("ALTER TABLE captures ADD COLUMN analyzed INTEGER DEFAULT 0;")
        except sqlite3.OperationalError:
            pass

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS flowlets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                capture_id TEXT NOT NULL,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                bytes INTEGER,
                llm_usage INTEGER,
                llm_provider TEXT,
                llm_model TEXT,
                llm_confidence REAL,
                user_id TEXT,
                protocol TEXT,
                FOREIGN KEY (capture_id) REFERENCES captures(id) ON DELETE CASCADE
            );
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS flowlets_capture_idx ON flowlets(capture_id);"
        )


@app.on_event("startup")
def on_startup():
    init_db()


# --- Pydantic models


class StartCaptureRequest(BaseModel):
    ip_range: str = Field(..., description="CIDR or host (strict=False)")
    interface: Optional[str] = Field(None, description="Interface name (e.g., en0)")
    outdir: str = Field("captures", description="Directory for capture text output")
    timeout: Optional[int] = Field(None, description="Seconds to run before stop")
    snaplen: int = Field(96, description="tcpdump snap length")
    extra_filter: Optional[str] = Field(
        None, description='Extra BPF filter, e.g. "tcp port 443"'
    )


class CaptureResponse(BaseModel):
    id: str
    name: Optional[str] = None
    status: str
    startedAt: Optional[str] = None
    endedAt: Optional[str] = None
    flowletCount: int = 0
    llmFlowletCount: int = 0
    isMock: bool = False
    ipRange: Optional[str] = None
    interface: Optional[str] = None
    outdir: Optional[str] = None
    snaplen: Optional[int] = None
    extraFilter: Optional[str] = None
    analyzed: bool = False


class FlowletResponse(BaseModel):
    id: str
    timestamp: str
    userId: Optional[str]
    srcIp: str
    dstIp: str
    bytes: int
    protocol: Optional[str]
    llmUsage: bool
    llmProvider: Optional[str]
    llmModel: Optional[str]
    llmConfidence: Optional[float]


# --- Utility helpers


def now_iso() -> str:
    return dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc).isoformat()


def map_capture_row(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "status": row["status"],
        "startedAt": row["started_at"],
        "endedAt": row["ended_at"],
        "flowletCount": row["flowlet_count"] or 0,
        "llmFlowletCount": row["llm_flowlet_count"] or 0,
        "isMock": False,
        "ipRange": row["ip_range"],
        "interface": row["interface"],
        "outdir": row["outdir"],
        "snaplen": row["snaplen"],
        "extraFilter": row["extra_filter"],
        "analyzed": bool(row["analyzed"]) if "analyzed" in row.keys() else False,
    }


def map_flowlet_row(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": str(row["id"]),
        "timestamp": row["timestamp"],
        "userId": row["user_id"],
        "srcIp": row["src_ip"],
        "dstIp": row["dst_ip"],
        "bytes": row["bytes"],
        "protocol": row["protocol"],
        "llmUsage": bool(row["llm_usage"]),
        "llmProvider": row["llm_provider"],
        "llmModel": row["llm_model"],
        "llmConfidence": row["llm_confidence"],
    }


def capture_output_path(ip_range: str, outdir: Path) -> Path:
    network = ipaddress.ip_network(ip_range, strict=False)
    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = str(network.with_prefixlen).replace("/", "_").replace(":", "-")
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir / f"capture_{timestamp}_{safe_name}.txt"


def read_initial_output(proc: subprocess.Popen, timeout_s: float = 2.0) -> str:
    """Read a couple of lines to discover the capture path ('Writing to: ...')."""
    capture_path = ""
    if proc.stdout is None:
        return capture_path
    proc.stdout.flush()
    end = dt.datetime.now() + dt.timedelta(seconds=timeout_s)
    while dt.datetime.now() < end:
        line = proc.stdout.readline()
        if not line:
            continue
        if "Writing to:" in line:
            capture_path = line.split("Writing to:", 1)[1].strip()
            break
    return capture_path


def terminate_process(pid: int, timeout_s: float = 5.0) -> None:
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = dt.datetime.now() + dt.timedelta(seconds=timeout_s)
    while dt.datetime.now() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.1)
    # Force kill if still running
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def parse_and_store_capture(capture_id: str, capture_file: Path, started_at: str) -> None:
    packets = parse_flowlets.parse_capture_text(capture_file)
    flows = parse_flowlets.group_packets_into_flows(packets, bidirectional=True)
    summary = parse_flowlets.build_summary(flows, threshold=0.1, bidirectional=True)
    parse_flowlets.annotate_queries(summary)
    events = parse_flowlets.export_to_traffic_json(
        summary, base_timestamp=started_at or now_iso()
    )

    with get_conn() as conn:
        conn.execute("DELETE FROM flowlets WHERE capture_id = ?", (capture_id,))
        flowlet_count = 0
        llm_flowlet_count = 0
        for ev in events:
            flowlet_count += 1
            if ev.get("llmUsage"):
                llm_flowlet_count += 1
            conn.execute(
                """
                INSERT INTO flowlets (
                    capture_id, timestamp, src_ip, dst_ip, bytes, llm_usage,
                    llm_provider, llm_model, llm_confidence, user_id, protocol
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    capture_id,
                    ev.get("timestamp"),
                    ev.get("srcIp"),
                    ev.get("dstIp"),
                    ev.get("bytes") or 0,
                    1 if ev.get("llmUsage") else 0,
                    ev.get("llmProvider"),
                    ev.get("llmModel"),
                    ev.get("llmConfidence"),
                    ev.get("userId"),
                    ev.get("protocol"),
                ),
            )

        conn.execute(
            """
            UPDATE captures
            SET flowlet_count = ?, llm_flowlet_count = ?, analysis_json = ?, analyzed = 1
            WHERE id = ?;
            """,
            (
                flowlet_count,
                llm_flowlet_count,
                json.dumps(summary),
                capture_id,
            ),
        )


# --- API endpoints


@app.get("/api/health")
def health():
    return {"ok": True, "time": now_iso()}


@app.get("/api/captures", response_model=List[CaptureResponse])
def list_captures():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM captures ORDER BY started_at DESC;"
        ).fetchall()
    return [map_capture_row(r) for r in rows]


@app.get("/api/captures/{capture_id}/flowlets", response_model=List[FlowletResponse])
def get_flowlets(capture_id: str):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM flowlets WHERE capture_id = ? ORDER BY timestamp ASC;",
            (capture_id,),
        ).fetchall()
    return [map_flowlet_row(r) for r in rows]


@app.post("/api/captures/start", response_model=CaptureResponse)
def start_capture(payload: StartCaptureRequest):
    if not IP_RANGE_CAPTURE_PATH.exists():
        raise HTTPException(status_code=500, detail="ip_range_capture.py not found")

    capture_id = str(uuid.uuid4())
    started_at = now_iso()
    outdir = (ROOT / payload.outdir).resolve()

    # Predict output path (used if we can't parse stdout)
    predicted_capture_file = capture_output_path(payload.ip_range, outdir)

    cmd = [
        sys.executable,
        str(IP_RANGE_CAPTURE_PATH),
        payload.ip_range,
        "-o",
        str(outdir),
        "--snaplen",
        str(payload.snaplen),
    ]
    if payload.interface:
        cmd.extend(["-i", payload.interface])
    if payload.timeout:
        cmd.extend(["-t", str(payload.timeout)])
    if payload.extra_filter:
        cmd.extend(["--extra-filter", payload.extra_filter])

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    capture_file = read_initial_output(proc) or str(predicted_capture_file)

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO captures (
                id, name, status, ip_range, interface, outdir, snaplen,
                extra_filter, timeout, started_at, capture_file, pid, analyzed
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                capture_id,
                f"Capture {capture_id[:8]}",
                "running",
                payload.ip_range,
                payload.interface,
                str(outdir),
                payload.snaplen,
                payload.extra_filter,
                payload.timeout,
                started_at,
                capture_file,
                proc.pid,
                0,
            ),
        )

    return CaptureResponse(
        id=capture_id,
        name=f"Capture {capture_id[:8]}",
        status="running",
        startedAt=started_at,
        flowletCount=0,
        llmFlowletCount=0,
        ipRange=payload.ip_range,
        interface=payload.interface,
        outdir=str(outdir),
        snaplen=payload.snaplen,
        extraFilter=payload.extra_filter,
    )


@app.post("/api/captures/{capture_id}/stop", response_model=CaptureResponse)
def stop_capture(capture_id: str):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM captures WHERE id = ?;", (capture_id,)
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Capture not found")
    if row["status"] != "running":
        raise HTTPException(status_code=400, detail="Capture not running")

    pid = row["pid"]
    if pid:
        terminate_process(pid)

    ended_at = now_iso()
    capture_file = row["capture_file"]

    # Parse + persist flowlets in a worker thread to keep the API responsive
    def worker():
        try:
            parse_and_store_capture(capture_id, Path(capture_file), row["started_at"])
        except Exception as exc:  # pragma: no cover - best effort logging
            print(f"[parse] failed for {capture_file}: {exc}", file=sys.stderr)

    threading.Thread(target=worker, daemon=True).start()

    with get_conn() as conn:
        conn.execute(
            """
            UPDATE captures
            SET status = ?, ended_at = ?, pid = NULL
            WHERE id = ?;
            """,
            ("stopped", ended_at, capture_id),
        )
        row = conn.execute(
            "SELECT * FROM captures WHERE id = ?;", (capture_id,)
        ).fetchone()

    return CaptureResponse(**map_capture_row(row))


@app.post("/api/captures/{capture_id}/analyze", response_model=CaptureResponse)
def analyze_capture(capture_id: str):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM captures WHERE id = ?;", (capture_id,)
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Capture not found")
    capture_file = row["capture_file"]
    if not capture_file or not Path(capture_file).exists():
        raise HTTPException(status_code=400, detail="Capture file not found")

    parse_and_store_capture(capture_id, Path(capture_file), row["started_at"])

    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM captures WHERE id = ?;", (capture_id,)
        ).fetchone()
    return CaptureResponse(**map_capture_row(row))


# Convenience route to manually ingest an existing capture text file
@app.post("/api/captures/ingest", response_model=CaptureResponse)
def ingest_capture(file_path: str, ip_range: str):
    path = Path(file_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    capture_id = str(uuid.uuid4())
    started_at = now_iso()
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO captures (
                id, name, status, ip_range, started_at, ended_at, capture_file
            )
            VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            (
                capture_id,
                f"Ingested {capture_id[:8]}",
                "stopped",
                ip_range,
                started_at,
                started_at,
                str(path),
            ),
        )
    parse_and_store_capture(capture_id, path, started_at)
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM captures WHERE id = ?;", (capture_id,)
        ).fetchone()
    return CaptureResponse(**map_capture_row(row))


@app.post("/api/captures/upload", response_model=CaptureResponse)
async def upload_capture(file: UploadFile = File(...), ip_range: str = Form("unknown")):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    suffix = Path(file.filename).suffix or ".txt"
    dest_path = UPLOAD_DIR / f"{uuid.uuid4()}{suffix}"

    content = await file.read()
    with dest_path.open("wb") as f:
        f.write(content)

    capture_id = str(uuid.uuid4())
    started_at = now_iso()
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO captures (
                id, name, status, ip_range, interface, outdir, snaplen,
                extra_filter, timeout, started_at, ended_at, capture_file, pid, analyzed
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                capture_id,
                f"Uploaded {capture_id[:8]}",
                "stopped",
                ip_range,
                None,
                str(dest_path.parent),
                None,
                None,
                None,
                started_at,
                started_at,
                str(dest_path),
                None,
                0,
            ),
        )

    # Parse and store flowlets synchronously so the caller gets updated counts
    parse_and_store_capture(capture_id, dest_path, started_at)

    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM captures WHERE id = ?;", (capture_id,)
        ).fetchone()
    return CaptureResponse(**map_capture_row(row))


@app.delete("/api/captures/{capture_id}")
def delete_capture(capture_id: str):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT id FROM captures WHERE id = ?;", (capture_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Capture not found")
        conn.execute("DELETE FROM captures WHERE id = ?;", (capture_id,))
    return {"ok": True}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)

