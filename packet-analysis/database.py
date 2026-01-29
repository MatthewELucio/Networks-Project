#!/usr/bin/env python3
"""database.py

SQLite database models and utilities for storing captures and flowlets.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Generator

from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    DateTime,
    ForeignKey,
    Text,
    Boolean,
    create_engine,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker, Session

Base = declarative_base()


class Capture(Base):
    """Represents a packet capture file."""
    __tablename__ = "captures"

    id = Column(Integer, primary_key=True, autoincrement=True)
    file_path = Column(String, unique=True, nullable=True, index=True)  # Nullable to allow captures in progress
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    status = Column(String, default="completed")  # 'running', 'completed', 'failed'
    llm_ip_map = Column(Text)  # JSON string of {ip: llm_name} mappings
    notes = Column(Text, nullable=True)

    # Relationships
    flowlets = relationship("Flowlet", back_populates="capture", cascade="all, delete-orphan")

    def to_dict(self) -> Dict[str, Any]:
        """Convert capture to dictionary."""
        return {
            "id": self.id,
            "file_path": self.file_path,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "status": self.status,
            "llm_ip_map": json.loads(self.llm_ip_map) if self.llm_ip_map else {},
            "notes": self.notes,
        }


class Flowlet(Base):
    """Represents a flowlet extracted from a capture."""
    __tablename__ = "flowlets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    capture_id = Column(Integer, ForeignKey("captures.id"), nullable=False, index=True)
    
    # Flow key
    src_ip = Column(String, nullable=True)
    src_port = Column(Integer, nullable=True)
    dst_ip = Column(String, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True)
    
    # Flowlet metadata
    flowlet_id = Column(Integer, nullable=False)  # ID within the flow
    traffic_class = Column(String, nullable=True)  # 'llm' or 'non_llm'
    llm_name = Column(String, nullable=True)  # e.g., 'ChatGPT', 'Claude', etc.
    
    # Timing
    start_ts = Column(Float, nullable=False)
    end_ts = Column(Float, nullable=False)
    duration = Column(Float, nullable=False)
    
    # Packet/byte counts
    packet_count = Column(Integer, nullable=False)
    total_bytes = Column(Integer, nullable=False)
    
    # Statistics
    inter_packet_time_mean = Column(Float, nullable=True)
    inter_packet_time_std = Column(Float, nullable=True)
    packet_size_mean = Column(Float, nullable=True)
    packet_size_std = Column(Float, nullable=True)
    
    # Detailed arrays (stored as JSON)
    inter_packet_times = Column(Text, nullable=True)  # JSON array
    packet_sizes = Column(Text, nullable=True)  # JSON array
    
    # Classification results (added by classify.py)
    model_llm_prediction = Column(String, nullable=True)  # 'ChatGPT', 'non_llm', etc.
    model_llm_confidence = Column(Float, nullable=True)
    
    # Ground truth from decrypted captures (set when parsing decrypted captures)
    ground_truth_llm = Column(String, nullable=True)  # 'ChatGPT', 'Claude', 'Gemini', etc. or None
    
    # Relationships
    capture = relationship("Capture", back_populates="flowlets")

    def to_dict(self) -> Dict[str, Any]:
        """Convert flowlet to dictionary."""
        return {
            "id": self.id,
            "capture_id": self.capture_id,
            "flow_key": {
                "src_ip": self.src_ip,
                "src_port": self.src_port,
                "dst_ip": self.dst_ip,
                "dst_port": self.dst_port,
                "protocol": self.protocol,
            },
            "flowlet_id": self.flowlet_id,
            "traffic_class": self.traffic_class,
            "llm_name": self.llm_name,
            "start_ts": self.start_ts,
            "end_ts": self.end_ts,
            "duration": self.duration,
            "packet_count": self.packet_count,
            "total_bytes": self.total_bytes,
            "inter_packet_time_mean": self.inter_packet_time_mean,
            "inter_packet_time_std": self.inter_packet_time_std,
            "packet_size_mean": self.packet_size_mean,
            "packet_size_std": self.packet_size_std,
            "inter_packet_times": json.loads(self.inter_packet_times) if self.inter_packet_times else [],
            "packet_sizes": json.loads(self.packet_sizes) if self.packet_sizes else [],
            "model_llm_prediction": self.model_llm_prediction,
            "model_llm_confidence": self.model_llm_confidence,
            "ground_truth_llm": self.ground_truth_llm,
        }


# Database connection management
_engine = None
_SessionLocal = None


def init_database(db_path: str = "data/networks_project.db") -> None:
    """Initialize the database and create tables."""
    global _engine, _SessionLocal
    _engine = create_engine(f"sqlite:///{db_path}", echo=False)
    _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)
    Base.metadata.create_all(bind=_engine)


def get_db() -> Generator[Session, None, None]:
    """Get a database session generator for FastAPI dependency injection.
    
    Usage in FastAPI: db: Session = Depends(get_db)
    For direct usage, call get_db_session() instead.
    """
    if _SessionLocal is None:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    db = _SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_db_session() -> Session:
    """Get a database session directly (for background tasks, etc.).
    
    Remember to call db.close() when done!
    """
    if _SessionLocal is None:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    return _SessionLocal()


def close_db() -> None:
    """Close database connections."""
    global _engine
    if _engine:
        _engine.dispose()

