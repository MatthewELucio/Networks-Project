#!/usr/bin/env python3
"""api_server.py

FastAPI/uvicorn webserver providing API endpoints for the front-end.
"""
import json
import subprocess
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

import sys
from pathlib import Path

# Add packet-analysis to path
sys.path.insert(0, str(Path(__file__).parent / "packet-analysis"))
from database import init_database, get_db, get_db_session, Capture, Flowlet

app = FastAPI(title="Networks Project API")

# CORS middleware for front-end
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],  # Vite default port
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Track running captures
_running_captures: Dict[int, subprocess.Popen] = {}

# SSL keys config file
SSL_CONFIG_FILE = Path("ssl_keys_config.json")


def load_ssl_config() -> Dict[str, Any]:
    """Load SSL keys configuration from file."""
    if SSL_CONFIG_FILE.exists():
        with SSL_CONFIG_FILE.open("r") as f:
            return json.load(f)
    return {"ssl_key_path": None}


def save_ssl_config(config: Dict[str, Any]) -> None:
    """Save SSL keys configuration to file."""
    with SSL_CONFIG_FILE.open("w") as f:
        json.dump(config, f, indent=2)


# Pydantic models for request/response
class CaptureCreate(BaseModel):
    file_path: str
    notes: Optional[str] = None


class CaptureStart(BaseModel):
    ip_range: str
    interface: Optional[str] = None
    outdir: Optional[str] = None
    timeout: Optional[int] = None
    snaplen: int = 96
    extra_filter: Optional[str] = None
    use_ssl_decrypt: bool = False  # Use decrypt script if True


class CaptureResponse(BaseModel):
    id: int
    file_path: str
    created_at: str
    status: str
    llm_ip_map: Dict[str, str]
    notes: Optional[str]
    flow_count: int
    llm_flow_count: Optional[int] = None

    class Config:
        from_attributes = True


class FlowletResponse(BaseModel):
    id: int
    capture_id: int
    flow_key: Dict[str, Any]
    flowlet_id: int
    traffic_class: Optional[str]
    llm_name: Optional[str]
    start_ts: float
    end_ts: float
    duration: float
    packet_count: int
    total_bytes: int
    model_llm_prediction: Optional[str] = None
    model_llm_confidence: Optional[float] = None
    ground_truth_llm: Optional[str] = None

    class Config:
        from_attributes = True


class SSLKeysConfig(BaseModel):
    ssl_key_path: Optional[str] = None


# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    db_path = Path("networks_project.db")
    init_database(str(db_path))
    print(f"Database initialized at {db_path}")


# API Endpoints
@app.get("/api/captures", response_model=List[CaptureResponse])
def list_captures(db: Session = Depends(get_db)):
    """List all captures with flow counts."""
    captures = db.query(Capture).order_by(Capture.created_at.desc()).all()
    result = []
    for capture in captures:
        flow_count = db.query(Flowlet).filter_by(capture_id=capture.id).count()
        llm_flow_count = db.query(Flowlet).filter_by(
            capture_id=capture.id, traffic_class="llm"
        ).count()
        
        # Check if classification has been run
        classified_count = db.query(Flowlet).filter_by(
            capture_id=capture.id
        ).filter(Flowlet.model_llm_prediction.isnot(None)).count()
        
        capture_dict = capture.to_dict()
        capture_dict["flow_count"] = flow_count
        if classified_count > 0:
            capture_dict["llm_flow_count"] = llm_flow_count
        result.append(capture_dict)
    
    return result


@app.get("/api/captures/{capture_id}", response_model=CaptureResponse)
def get_capture(capture_id: int, db: Session = Depends(get_db)):
    """Get a specific capture by ID."""
    capture = db.query(Capture).filter_by(id=capture_id).first()
    if not capture:
        raise HTTPException(status_code=404, detail="Capture not found")
    
    flow_count = db.query(Flowlet).filter_by(capture_id=capture_id).count()
    llm_flow_count = db.query(Flowlet).filter_by(
        capture_id=capture_id, traffic_class="llm"
    ).count()
    
    result = capture.to_dict()
    result["flow_count"] = flow_count
    result["llm_flow_count"] = llm_flow_count
    return result


@app.get("/api/captures/{capture_id}/flowlets", response_model=List[FlowletResponse])
def get_capture_flowlets(
    capture_id: int,
    skip: int = 0,
    limit: int = 1000,
    db: Session = Depends(get_db)
):
    """Get flowlets for a specific capture."""
    capture = db.query(Capture).filter_by(id=capture_id).first()
    if not capture:
        raise HTTPException(status_code=404, detail="Capture not found")
    
    flowlets = db.query(Flowlet).filter_by(capture_id=capture_id)\
        .order_by(Flowlet.start_ts)\
        .offset(skip)\
        .limit(limit)\
        .all()
    
    return [flowlet.to_dict() for flowlet in flowlets]


@app.get("/api/captures/{capture_id}/flowlets/chart")
def get_capture_flowlets_chart(capture_id: int, db: Session = Depends(get_db)):
    """Get flowlet data formatted for charting (time series)."""
    capture = db.query(Capture).filter_by(id=capture_id).first()
    if not capture:
        raise HTTPException(status_code=404, detail="Capture not found")
    
    flowlets = db.query(Flowlet).filter_by(capture_id=capture_id)\
        .order_by(Flowlet.start_ts)\
        .all()
    
    # Bucket flowlets by time (10 second intervals)
    buckets = {}
    for flowlet in flowlets:
        bucket_time = int(flowlet.start_ts / 10) * 10
        if bucket_time not in buckets:
            buckets[bucket_time] = {"total_bytes": 0, "llm_bytes": 0, "count": 0}
        
        buckets[bucket_time]["total_bytes"] += flowlet.total_bytes
        buckets[bucket_time]["count"] += 1
        if flowlet.traffic_class == "llm" or (flowlet.model_llm_prediction and flowlet.model_llm_prediction != "non_llm"):
            buckets[bucket_time]["llm_bytes"] += flowlet.total_bytes
    
    # Convert to list sorted by time
    chart_data = [
        {
            "time": bucket_time,
            "total_bytes": data["total_bytes"],
            "llm_bytes": data["llm_bytes"],
            "count": data["count"],
        }
        for bucket_time, data in sorted(buckets.items())
    ]
    
    return chart_data


@app.post("/api/captures/start")
def start_capture(capture_data: CaptureStart, background_tasks: BackgroundTasks):
    """Start a new packet capture. Uses decrypt script if use_ssl_decrypt is True."""
    # Determine which script to use
    if capture_data.use_ssl_decrypt:
        ssl_config = load_ssl_config()
        ssl_key_path = ssl_config.get("ssl_key_path")
        if not ssl_key_path or not Path(ssl_key_path).exists():
            raise HTTPException(
                status_code=400,
                detail="SSL key file not configured or not found. Please set SSL keys first."
            )
        
        # Use decrypt script
        cmd = ["python3", "ip_range_capture_tshark_decrypt_llm_only.py", capture_data.ip_range]
        cmd.extend(["--sniff"])  # Enable filtering/decryption mode
        cmd.extend(["-k", ssl_key_path])
    else:
        # Use regular capture script
        cmd = ["python3", "ip_range_capture.py", capture_data.ip_range]
        if capture_data.snaplen:
            cmd.extend(["--snaplen", str(capture_data.snaplen)])
        if capture_data.extra_filter:
            cmd.extend(["--extra-filter", capture_data.extra_filter])
    
    if capture_data.interface:
        cmd.extend(["-i", capture_data.interface])
    
    if capture_data.outdir:
        cmd.extend(["-o", capture_data.outdir])
    else:
        # Default to captures directory
        cmd.extend(["-o", "captures"])
    
    if capture_data.timeout:
        cmd.extend(["-t", str(capture_data.timeout)])
    
    # Start capture process
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        
        # Create capture record in database
        db = get_db_session()
        try:
            notes = f"IP: {capture_data.ip_range}, Interface: {capture_data.interface or 'default'}"
            if capture_data.use_ssl_decrypt:
                notes += " [SSL Decrypted]"
            capture = Capture(
                file_path="",  # Will be updated when capture completes
                status="running",
                notes=notes
            )
            db.add(capture)
            db.commit()
            db.refresh(capture)
            capture_id = capture.id
        finally:
            db.close()
        
        # Store process reference
        _running_captures[capture_id] = proc
        
        # Monitor process in background
        background_tasks.add_task(monitor_capture, capture_id, proc, capture_data.outdir or "captures")
        
        return {"id": capture_id, "status": "running", "message": "Capture started"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start capture: {str(e)}")


async def monitor_capture(capture_id: int, proc: subprocess.Popen, outdir: str):
    """Monitor a running capture and update database when it completes."""
    proc.wait()
    
    db = get_db_session()
    try:
        capture = db.query(Capture).filter_by(id=capture_id).first()
        if capture:
            # Find the output file (most recent in outdir)
            outdir_path = Path(outdir)
            if outdir_path.exists():
                # Check for both regular and hybrid captures
                capture_files = sorted(
                    list(outdir_path.glob("capture_*.txt")) + list(outdir_path.glob("hybrid_capture_*.txt")),
                    key=lambda p: p.stat().st_mtime
                )
                if capture_files:
                    capture.file_path = str(capture_files[-1])
            
            capture.status = "completed" if proc.returncode == 0 else "failed"
            db.commit()
    finally:
        db.close()
    
    # Remove from running captures
    if capture_id in _running_captures:
        del _running_captures[capture_id]


@app.post("/api/captures/{capture_id}/stop")
def stop_capture(capture_id: int):
    """Stop a running capture."""
    if capture_id not in _running_captures:
        raise HTTPException(status_code=404, detail="Capture not running")
    
    proc = _running_captures[capture_id]
    proc.terminate()
    
    db = get_db_session()
    try:
        capture = db.query(Capture).filter_by(id=capture_id).first()
        if capture:
            capture.status = "stopped"
            db.commit()
    finally:
        db.close()
    
    del _running_captures[capture_id]
    
    return {"message": "Capture stopped"}


@app.post("/api/captures/{capture_id}/parse")
def parse_capture(capture_id: int, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """Parse a capture file and extract flowlets."""
    capture = db.query(Capture).filter_by(id=capture_id).first()
    if not capture:
        raise HTTPException(status_code=404, detail="Capture not found")
    
    if not capture.file_path or not Path(capture.file_path).exists():
        raise HTTPException(status_code=400, detail="Capture file not found")
    
    # Check if already parsed
    existing_flowlets = db.query(Flowlet).filter_by(capture_id=capture_id).count()
    if existing_flowlets > 0:
        return {"message": f"Capture already parsed ({existing_flowlets} flowlets)"}
    
    # Run parsing in background
    background_tasks.add_task(run_parse, capture_id, capture.file_path)
    
    return {"message": "Parsing started in background"}


async def run_parse(capture_id: int, file_path: str):
    """Run parse_flowlets_v2.py on a single capture file."""
    import sys
    from pathlib import Path
    
    # Import parse function
    sys.path.insert(0, str(Path(__file__).parent / "packet-analysis"))
    from parse_flowlets_v2 import process_capture_file
    from database import get_db_session
    
    db = get_db_session()
    try:
        capture = db.query(Capture).get(capture_id)
        if not capture:
            return
        
        # Parse the file
        llm_ip_map = {}
        features, file_llm_map = process_capture_file(
            Path(file_path),
            threshold=0.1,
            bidirectional=False,
            llm_ip_map=llm_ip_map,
            db_session=db,
            capture_id=capture_id,
        )
        
        # Update capture LLM map
        capture.llm_ip_map = json.dumps(file_llm_map)
        db.commit()
        
        print(f"Parsed {len(features)} flowlets for capture {capture_id}")
    except Exception as e:
        print(f"Error parsing capture {capture_id}: {e}")
        if capture:
            capture.status = "failed"
            db.commit()
    finally:
        db.close()


@app.post("/api/captures/{capture_id}/classify")
def classify_capture(capture_id: int, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """Run classification on flowlets for a capture."""
    capture = db.query(Capture).filter_by(id=capture_id).first()
    if not capture:
        raise HTTPException(status_code=404, detail="Capture not found")
    
    flowlet_count = db.query(Flowlet).filter_by(capture_id=capture_id).count()
    if flowlet_count == 0:
        raise HTTPException(status_code=400, detail="No flowlets found. Parse the capture first.")
    
    # Run classification in background
    background_tasks.add_task(run_classify, capture_id)
    
    return {"message": "Classification started in background"}


@app.get("/api/ssl-keys")
def get_ssl_keys():
    """Get current SSL keys configuration."""
    config = load_ssl_config()
    return config


@app.post("/api/ssl-keys")
def set_ssl_keys(config: SSLKeysConfig):
    """Set SSL keys configuration."""
    ssl_key_path = config.ssl_key_path
    if ssl_key_path and not Path(ssl_key_path).exists():
        raise HTTPException(status_code=400, detail=f"SSL key file not found: {ssl_key_path}")
    
    save_ssl_config({"ssl_key_path": ssl_key_path})
    return {"message": "SSL keys configuration saved", "ssl_key_path": ssl_key_path}


async def run_classify(capture_id: int):
    """Run classify.py on flowlets for a capture."""
    import sys
    from pathlib import Path
    
    sys.path.insert(0, str(Path(__file__).parent / "packet-analysis"))
    from classify import annotate_flowlets, load_model_artifacts
    from database import get_db_session, Flowlet
    
    db = get_db_session()
    try:
        # Load model artifacts
        model_path = Path(__file__).parent / "packet-analysis" / "flowlet_model_weights.pkl"
        if not model_path.exists():
            print(f"Model weights not found at {model_path}")
            return
        
        artifacts = load_model_artifacts(model_path)
        
        # Load flowlets from database
        flowlets = db.query(Flowlet).filter_by(capture_id=capture_id).all()
        flowlet_dicts = [f.to_dict() for f in flowlets]
        
        # Run classification
        annotated = annotate_flowlets(flowlet_dicts, artifacts, threshold=0.5)
        
        # Update flowlets in database
        for flowlet_dict in annotated:
            flowlet = db.query(Flowlet).get(flowlet_dict["id"])
            if flowlet:
                flowlet.model_llm_prediction = flowlet_dict.get("model_llm_prediction")
                flowlet.model_llm_confidence = flowlet_dict.get("model_llm_confidence")
        
        db.commit()
        print(f"Classified {len(annotated)} flowlets for capture {capture_id}")
    except Exception as e:
        print(f"Error classifying capture {capture_id}: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

