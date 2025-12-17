// src/App.jsx
import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

const REFRESH_INTERVAL_MS = 5000; // poll every 5s
const SSL_KEY_STORAGE_KEY = "sslKeyMaterial";
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

async function fetchJSON(url, options = {}) {
  const res = await fetch(url, options);
  if (!res.ok) {
    throw new Error(`HTTP ${res.status}`);
  }
  return res.json();
}

async function apiFetchJSON(path, options = {}) {
  const url =
    path.startsWith("http://") || path.startsWith("https://")
      ? path
      : `${API_BASE}${path}`;
  return fetchJSON(url, options);
}

async function apiFetchCaptures() {
  try {
    return await apiFetchJSON("/api/captures");
  } catch (err) {
    // Fall back to mock data so the UI stays usable without the backend
    console.warn("Falling back to mock capture list:", err);
    const mock = await fetchJSON("/mock_traffic.json");
    const now = new Date();
    return [
      {
        id: "mock",
        name: "Sample capture (mock)",
        status: "stopped",
        startedAt: new Date(now.getTime() - 15 * 60 * 1000).toISOString(),
        endedAt: now.toISOString(),
        flowletCount: mock.length,
        llmFlowletCount: mock.filter((m) => m.llmUsage).length,
        isMock: true,
      },
    ];
  }
}

async function apiFetchFlowlets(captureId) {
  if (captureId === "mock") {
    const mock = await fetchJSON("/mock_traffic.json");
    return mock;
  }
  return apiFetchJSON(`/api/captures/${captureId}/flowlets`);
}

async function apiStartCapture(payload) {
  // Backend should run ip_range_capture.py with these args.
  return apiFetchJSON("/api/captures/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function apiStopCapture(captureId) {
  return apiFetchJSON(`/api/captures/${captureId}/stop`, { method: "POST" });
}

async function apiDecryptCapture() {
  // Placeholder: wire to decrypt endpoint once ready.
  return Promise.resolve({ ok: true });
}

async function apiAnalyzeCapture(captureId) {
  return apiFetchJSON(`/api/captures/${captureId}/analyze`, { method: "POST" });
}

async function apiUploadCapture(file, ipRange) {
  const form = new FormData();
  form.append("file", file);
  form.append("ip_range", ipRange || "unknown");
  const res = await fetch(
    `${API_BASE}/api/captures/upload`,
    {
      method: "POST",
      body: form,
    }
  );
  if (!res.ok) {
    throw new Error(`HTTP ${res.status}`);
  }
  return res.json();
}

async function apiDeleteCapture(captureId) {
  const res = await fetch(`${API_BASE}/api/captures/${captureId}`, {
    method: "DELETE",
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

function formatTime(ts) {
  if (!ts) return "";
  const d = new Date(ts);
  return d.toLocaleString();
}

function shortTime(ts) {
  if (!ts) return "-";
  const d = new Date(ts);
  return d.toLocaleTimeString(undefined, { hour12: false });
}

function bytesToHuman(bytes) {
  if (bytes == null) return "-";
  if (bytes < 1024) return `${bytes} B`;
  const kb = bytes / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB`;
  const mb = kb / 1024;
  return `${mb.toFixed(1)} MB`;
}

function statusLabel(status) {
  if (!status) return "unknown";
  return status;
}

function useCaptures() {
  const [captures, setCaptures] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  const refresh = useCallback(async () => {
    setIsLoading(true);
    try {
      const data = await apiFetchCaptures();
      setCaptures(data);
      setError(null);
    } catch (err) {
      console.error("Failed to fetch captures", err);
      setError(err.message || String(err));
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, REFRESH_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [refresh]);

  return { captures, setCaptures, isLoading, error, refresh };
}

function useFlowlets(captureId) {
  const [flowlets, setFlowlets] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  const refresh = useCallback(
    async (id) => {
      if (!id) {
        setFlowlets([]);
        return;
      }
      setIsLoading(true);
      try {
        const data = await apiFetchFlowlets(id);
        const sorted = [...data].sort(
          (a, b) => new Date(a.timestamp) - new Date(b.timestamp)
        );
        setFlowlets(sorted);
        setError(null);
      } catch (err) {
        console.error("Failed to fetch flowlets", err);
        setFlowlets([]);
        setError(err.message || String(err));
      } finally {
        setIsLoading(false);
      }
    },
    []
  );

  useEffect(() => {
    refresh(captureId);
    const interval = captureId
      ? setInterval(() => refresh(captureId), REFRESH_INTERVAL_MS)
      : null;
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [captureId, refresh]);

  return { flowlets, isLoading, error, refresh };
}

function TrafficChart({ events }) {
  const chartData = useMemo(() => {
    const bucketMap = new Map();

    events.forEach((evt) => {
      const ts = new Date(evt.timestamp);
      const bucketKey = new Date(
        ts.getFullYear(),
        ts.getMonth(),
        ts.getDate(),
        ts.getHours(),
        ts.getMinutes(),
        Math.floor(ts.getSeconds() / 10) * 10
      ).toISOString();

      const existing = bucketMap.get(bucketKey) || {
        time: bucketKey,
        totalBytes: 0,
        llmBytes: 0,
      };

      existing.totalBytes += evt.bytes || 0;
      if (evt.llmUsage) {
        existing.llmBytes += evt.bytes || 0;
      }

      bucketMap.set(bucketKey, existing);
    });

    return Array.from(bucketMap.values()).sort(
      (a, b) => new Date(a.time) - new Date(b.time)
    );
  }, [events]);

  if (!chartData.length) {
    return <div className="card-body text-muted">No traffic yet.</div>;
  }

  return (
    <div className="card-body" style={{ height: 260 }}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart
          data={chartData}
          margin={{ top: 10, right: 20, left: 0, bottom: 0 }}
        >
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis
            dataKey="time"
            tickFormatter={(t) =>
              new Date(t).toLocaleTimeString(undefined, { hour12: false })
            }
          />
          <YAxis tickFormatter={bytesToHuman} />
          <Tooltip
            labelFormatter={(ts) =>
              new Date(ts).toLocaleTimeString(undefined, { hour12: false })
            }
            formatter={(value, name) => [bytesToHuman(value), name]}
          />
          <Line
            type="monotone"
            dataKey="totalBytes"
            name="Total bytes"
            strokeWidth={2}
            dot={false}
          />
          <Line
            type="monotone"
            dataKey="llmBytes"
            name="LLM bytes"
            strokeWidth={2}
            dot={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

function SummaryCards({ events }) {
  const now = Date.now();
  const fiveMinutesAgo = now - 5 * 60 * 1000;

  const totalBytes = events.reduce((acc, e) => acc + (e.bytes || 0), 0);
  const llmEvents = events.filter((e) => e.llmUsage);
  const llmBytes = llmEvents.reduce((acc, e) => acc + (e.bytes || 0), 0);
  const recentLLMs = llmEvents.filter(
    (e) => new Date(e.timestamp).getTime() >= fiveMinutesAgo
  );

  return (
    <div className="summary-grid">
      <div className="card">
        <div className="card-title">Total traffic (session)</div>
        <div className="card-value">{bytesToHuman(totalBytes)}</div>
      </div>
      <div className="card">
        <div className="card-title">LLM traffic (session)</div>
        <div className="card-value">{bytesToHuman(llmBytes)}</div>
      </div>
      <div className="card">
        <div className="card-title">Total LLM events</div>
        <div className="card-value">{llmEvents.length}</div>
      </div>
      <div className="card">
        <div className="card-title">LLM events (last 5 min)</div>
        <div className="card-value">{recentLLMs.length}</div>
      </div>
    </div>
  );
}

function LLMEventsTable({ events }) {
  const llmEvents = [...events]
    .filter((e) => e.llmUsage)
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

  if (!llmEvents.length) {
    return (
      <div className="card-body text-muted">No LLM usage detected yet.</div>
    );
  }

  return (
    <div className="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>User</th>
            <th>Src IP</th>
            <th>Dst IP</th>
            <th>Bytes</th>
            <th>Provider</th>
            <th>Model</th>
            <th>Conf.</th>
          </tr>
        </thead>
        <tbody>
          {llmEvents.map((e) => (
            <tr key={e.id || `${e.timestamp}-${e.srcIp}-${e.dstIp}`}>
              <td>{shortTime(e.timestamp)}</td>
              <td>{e.userId || "-"}</td>
              <td>{e.srcIp}</td>
              <td>{e.dstIp}</td>
              <td>{bytesToHuman(e.bytes)}</td>
              <td>{e.llmProvider || "-"}</td>
              <td>{e.llmModel || "-"}</td>
              <td>
                {typeof e.llmConfidence === "number"
                  ? `${(e.llmConfidence * 100).toFixed(0)}%`
                  : "-"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function CaptureList({ captures, onSelect, onOpenTab, onDelete, selectedId }) {
  if (!captures.length) {
    return <div className="card-body text-muted">No capture events yet.</div>;
  }

  return (
    <div className="capture-list">
      {captures.map((cap) => (
        <div
          key={cap.id}
          className={`capture-item ${selectedId === cap.id ? "capture-item-active" : ""}`}
        >
          <div className="capture-main">
            <div>
              <div className="capture-title">
                {cap.name || `Capture ${cap.id}`}
              </div>
              <div className="capture-meta">
                <span className={`status-pill status-${cap.status || "unknown"}`}>
                  {statusLabel(cap.status)}
                </span>
                {cap.analyzed && <span className="tag">Analyzed</span>}
                {cap.startedAt && (
                  <span className="tag">Start {shortTime(cap.startedAt)}</span>
                )}
                {cap.endedAt && (
                  <span className="tag">End {shortTime(cap.endedAt)}</span>
                )}
                <span className="tag">
                  Flowlets {cap.flowletCount ?? "?"} | LLM{" "}
                  {cap.llmFlowletCount ?? "?"}
                </span>
                {cap.isMock && <span className="tag">Mock data</span>}
              </div>
            </div>
          </div>
          <div className="capture-actions">
            <button className="btn btn-primary btn-sm" onClick={() => onSelect(cap.id)}>
              Load
            </button>
            <button className="btn btn-ghost btn-sm" onClick={() => onOpenTab(cap.id)}>
              Open in tab
            </button>
            <button
              className="btn btn-ghost btn-sm btn-danger"
              onClick={() => onDelete(cap.id)}
            >
              Delete
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}

function CaptureControls({
  onStartClick,
  onStopClick,
  onUploadClick,
  onDecryptClick,
  onAnalyzeClick,
  activeCaptureId,
  selectedCaptureId,
  isStarting,
  isStopping,
  isUploading,
  isDecrypting,
  isAnalyzing,
  lastAction,
}) {
  return (
    <div className="card">
      <div className="card-header">
        <h2>Capture controls</h2>
        <p className="card-subtitle">
          Start/stop tcpdump via ip_range_capture.py, then decrypt/analyze.
        </p>
      </div>
      <div className="card-body">
        <div className="control-row">
          <button
            className="btn btn-primary"
            onClick={onStartClick}
            disabled={isStarting}
          >
            {isStarting ? "Starting..." : "Start Log"}
          </button>
          <button
            className="btn btn-secondary"
            onClick={onUploadClick}
            disabled={isUploading}
          >
            {isUploading ? "Uploading..." : "Upload Capture"}
          </button>
          <button
            className="btn btn-danger"
            onClick={onStopClick}
            disabled={!activeCaptureId || isStopping}
          >
            {isStopping ? "Stopping..." : "Stop Log"}
          </button>
          <button
            className="btn btn-secondary"
            onClick={onDecryptClick}
            disabled={!selectedCaptureId || isDecrypting}
          >
            {isDecrypting ? "Saving..." : "Decrypt"}
          </button>
          <button
            className="btn btn-secondary"
            onClick={onAnalyzeClick}
            disabled={!selectedCaptureId || isAnalyzing}
          >
            {isAnalyzing ? "Analyzing..." : "Analyze"}
          </button>
        </div>
        <div className="text-muted">
          {activeCaptureId
            ? `Active capture: ${activeCaptureId}`
            : "No capture running."}
          {lastAction && <span className="tag tag-ghost"> {lastAction}</span>}
        </div>
      </div>
    </div>
  );
}

function Modal({
  isOpen,
  title,
  children,
  onClose,
  onSubmit,
  submitLabel = "Save",
  busyLabel = "Saving...",
  isBusy = false,
}) {
  if (!isOpen) return null;
  return (
    <div className="modal-backdrop">
      <div className="modal">
        <div className="modal-header">
          <h3>{title}</h3>
          <button className="btn btn-ghost btn-sm" onClick={onClose}>
            Close
          </button>
        </div>
        <div className="modal-body">{children}</div>
        <div className="modal-actions">
          <button className="btn btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn-primary"
            onClick={onSubmit}
            disabled={isBusy}
          >
            {isBusy ? busyLabel : submitLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

function CaptureDetail({ capture, flowlets, isLoading, error }) {
  return (
    <div className="card">
      <div className="card-header">
        <h2>{capture?.name || "Capture details"}</h2>
        <p className="card-subtitle">
          Flowlets saved to SQLite for this capture event. Analysis view mirrors
          the homepage layout.
        </p>
      </div>
      {error && (
        <div className="alert alert-error">Failed to load flowlets: {error}</div>
      )}
      {isLoading && (
        <div className="card-body text-muted">Loading flowlets...</div>
      )}
      {!isLoading && (
        <>
          <SummaryCards events={flowlets} />

          <div className="grid-2">
            <div className="card">
              <div className="card-header">
                <h2>Traffic over time</h2>
                <p className="card-subtitle">
                  Total vs LLM bytes (bucketed in ~10s intervals)
                </p>
              </div>
              <TrafficChart events={flowlets} />
            </div>

            <div className="card">
              <div className="card-header">
                <h2>LLM usage events</h2>
                <p className="card-subtitle">
                  Detected LLM calls (from classifier + decryption)
                </p>
              </div>
              <LLMEventsTable events={flowlets} />
            </div>
          </div>
        </>
      )}
    </div>
  );
}

const DEFAULT_CAPTURE_FORM = {
  ipRange: "",
  interface: "",
  outdir: "captures",
  timeout: 60,
  snaplen: 96,
  extraFilter: "",
};

export default function App() {
  const { captures, setCaptures, isLoading, error, refresh } = useCaptures();
  const [selectedCaptureId, setSelectedCaptureId] = useState(null);
  const { flowlets, isLoading: flowletsLoading, error: flowletsError } =
    useFlowlets(selectedCaptureId);

  const [showStartModal, setShowStartModal] = useState(false);
  const [showDecryptModal, setShowDecryptModal] = useState(false);
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [startForm, setStartForm] = useState(DEFAULT_CAPTURE_FORM);
  const [sslKey, setSslKey] = useState(
    () => localStorage.getItem(SSL_KEY_STORAGE_KEY) || ""
  );
  const [uploadFile, setUploadFile] = useState(null);
  const [uploadIpRange, setUploadIpRange] = useState("");

  const [isStarting, setIsStarting] = useState(false);
  const [isStopping, setIsStopping] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [lastAction, setLastAction] = useState("");

  const activeCaptureId = useMemo(
    () => captures.find((c) => c.status === "running")?.id || null,
    [captures]
  );
  const selectedCapture = useMemo(
    () => captures.find((c) => c.id === selectedCaptureId),
    [captures, selectedCaptureId]
  );

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const captureFromUrl = params.get("capture");
    if (captureFromUrl) {
      setSelectedCaptureId(captureFromUrl);
    }
  }, []);

  useEffect(() => {
    if (!selectedCaptureId && captures.length) {
      setSelectedCaptureId(captures[0].id);
    }
  }, [captures, selectedCaptureId]);

  useEffect(() => {
    const url = new URL(window.location.href);
    if (selectedCaptureId) {
      url.searchParams.set("capture", selectedCaptureId);
    } else {
      url.searchParams.delete("capture");
    }
    window.history.replaceState({}, "", url.toString());
  }, [selectedCaptureId]);

  const handleStartCapture = async () => {
    setIsStarting(true);
    setLastAction("");
    try {
      const payload = {
        ip_range: startForm.ipRange,
        interface: startForm.interface || undefined,
        outdir: startForm.outdir,
        timeout: startForm.timeout,
        snaplen: startForm.snaplen,
        extra_filter: startForm.extraFilter || undefined,
      };
      const started = await apiStartCapture(payload);
      setCaptures((prev) => [
        started,
        ...prev.filter((c) => c.id !== started.id),
      ]);
      setSelectedCaptureId(started.id);
      setLastAction("Capture started");
      setShowStartModal(false);
      setStartForm(DEFAULT_CAPTURE_FORM);
      await refresh();
    } catch (err) {
      console.error("Failed to start capture", err);
      setLastAction(err.message || "Failed to start capture");
    } finally {
      setIsStarting(false);
    }
  };

  const handleStopCapture = async () => {
    if (!activeCaptureId) return;
    setIsStopping(true);
    setLastAction("");
    try {
      await apiStopCapture(activeCaptureId);
      setLastAction("Capture stopped");
      await refresh();
    } catch (err) {
      console.error("Failed to stop capture", err);
      setLastAction(err.message || "Failed to stop capture");
    } finally {
      setIsStopping(false);
    }
  };

  const handleDecrypt = async () => {
    if (!selectedCaptureId) {
      setLastAction("Select a capture first");
      return;
    }
    setIsDecrypting(true);
    setLastAction("");
    try {
      localStorage.setItem(SSL_KEY_STORAGE_KEY, sslKey || "");
      await apiDecryptCapture(selectedCaptureId, sslKey);
      setLastAction("SSL key saved. Wire decrypt backend to use it.");
      setShowDecryptModal(false);
    } catch (err) {
      console.error("Failed to save key", err);
      setLastAction(err.message || "Failed to save key");
    } finally {
      setIsDecrypting(false);
    }
  };

  const handleAnalyze = async () => {
    if (!selectedCaptureId) {
      setLastAction("Select a capture first");
      return;
    }
    setIsAnalyzing(true);
    setLastAction("");
    try {
      await apiAnalyzeCapture(selectedCaptureId);
      setLastAction("Capture analyzed and saved");
      await refresh();
    } catch (err) {
      console.error("Failed to analyze", err);
      setLastAction(err.message || "Failed to analyze");
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleUpload = async () => {
    if (!uploadFile) {
      setLastAction("Select a capture file first");
      return;
    }
    setIsUploading(true);
    setLastAction("");
    try {
      const uploaded = await apiUploadCapture(uploadFile, uploadIpRange);
      setLastAction("Capture uploaded and parsed");
      setShowUploadModal(false);
      setUploadFile(null);
      setUploadIpRange("");
      setSelectedCaptureId(uploaded.id);
      await refresh();
    } catch (err) {
      console.error("Failed to upload", err);
      setLastAction(err.message || "Failed to upload");
    } finally {
      setIsUploading(false);
    }
  };

  const handleDelete = async (captureId) => {
    if (!window.confirm("Delete this capture and its flowlets?")) return;
    try {
      await apiDeleteCapture(captureId);
      setLastAction("Capture deleted");
      if (selectedCaptureId === captureId) {
        setSelectedCaptureId(null);
      }
      await refresh();
    } catch (err) {
      console.error("Failed to delete", err);
      setLastAction(err.message || "Failed to delete");
    }
  };

  const handleOpenTab = (captureId) => {
    const url = new URL(window.location.href);
    url.searchParams.set("capture", captureId);
    window.open(url.toString(), "_blank", "noopener");
  };

  return (
    <div className="app-root">
      <header className="app-header">
        <h1>LLM Traffic Monitor</h1>
        <div className="app-status">
          {isLoading && <span className="status-dot status-dot-loading" />}
          {!isLoading && <span className="status-dot status-dot-ok" />}
          <span className="status-text">
            {isLoading ? "Refreshing..." : "Live (5s polling)"}
          </span>
        </div>
      </header>

      {error && (
        <div className="alert alert-error">
          Failed to fetch capture list: {error}
        </div>
      )}

      <CaptureControls
        onStartClick={() => setShowStartModal(true)}
        onStopClick={handleStopCapture}
        onUploadClick={() => setShowUploadModal(true)}
        onDecryptClick={() => setShowDecryptModal(true)}
        onAnalyzeClick={handleAnalyze}
        activeCaptureId={activeCaptureId}
        selectedCaptureId={selectedCaptureId}
        isStarting={isStarting}
        isStopping={isStopping}
        isUploading={isUploading}
        isDecrypting={isDecrypting}
        isAnalyzing={isAnalyzing}
        lastAction={lastAction}
      />

      <div className="card">
        <div className="card-header">
          <h2>Capture events (SQLite-backed)</h2>
          <p className="card-subtitle">
            List of capture runs. Click to load, or open in a new tab to mirror
            the homepage view for that event.
          </p>
        </div>
        <CaptureList
          captures={captures}
          onSelect={setSelectedCaptureId}
          onOpenTab={handleOpenTab}
          onDelete={handleDelete}
          selectedId={selectedCaptureId}
        />
      </div>

      {selectedCapture ? (
        <CaptureDetail
          capture={selectedCapture}
          flowlets={flowlets}
          isLoading={flowletsLoading}
          error={flowletsError}
        />
      ) : (
        <div className="card">
          <div className="card-body text-muted">
            Select a capture to view its flowlets.
          </div>
        </div>
      )}

      <Modal
        isOpen={showStartModal}
        title="Start capture (ip_range_capture.py)"
        onClose={() => setShowStartModal(false)}
        onSubmit={handleStartCapture}
        submitLabel="Start"
        busyLabel="Starting..."
        isBusy={isStarting}
      >
        <div className="input-group">
          <label className="input-label">IP range (CIDR)</label>
          <input
            className="input"
            placeholder="192.168.1.0/24 or 2001:db8::/64"
            value={startForm.ipRange}
            onChange={(e) =>
              setStartForm((f) => ({ ...f, ipRange: e.target.value }))
            }
          />
        </div>
        <div className="input-grid">
          <div className="input-group">
            <label className="input-label">Interface</label>
            <input
              className="input"
              placeholder="eth0 / en0 (optional)"
              value={startForm.interface}
              onChange={(e) =>
                setStartForm((f) => ({ ...f, interface: e.target.value }))
              }
            />
          </div>
          <div className="input-group">
            <label className="input-label">Timeout (seconds)</label>
            <input
              className="input"
              type="number"
              min="0"
              value={startForm.timeout}
              onChange={(e) =>
                setStartForm((f) => ({ ...f, timeout: Number(e.target.value) }))
              }
            />
          </div>
          <div className="input-group">
            <label className="input-label">Snaplen</label>
            <input
              className="input"
              type="number"
              min="64"
              value={startForm.snaplen}
              onChange={(e) =>
                setStartForm((f) => ({ ...f, snaplen: Number(e.target.value) }))
              }
            />
          </div>
        </div>
        <div className="input-group">
          <label className="input-label">Output directory</label>
          <input
            className="input"
            value={startForm.outdir}
            onChange={(e) =>
              setStartForm((f) => ({ ...f, outdir: e.target.value }))
            }
          />
        </div>
        <div className="input-group">
          <label className="input-label">Extra filter (BPF)</label>
          <input
            className="input"
            placeholder='e.g. "tcp port 443"'
            value={startForm.extraFilter}
            onChange={(e) =>
              setStartForm((f) => ({ ...f, extraFilter: e.target.value }))
            }
          />
        </div>
        <p className="text-muted small-text">
          Start will call the backend to run ip_range_capture.py with these
          arguments. Flowlets should be stored to SQLite for this capture.
        </p>
      </Modal>

      <Modal
        isOpen={showDecryptModal}
        title="Provide SSL key (for future decrypt hook)"
        onClose={() => setShowDecryptModal(false)}
        onSubmit={handleDecrypt}
        submitLabel="Save key"
        busyLabel="Saving..."
        isBusy={isDecrypting}
      >
        <div className="input-group">
          <label className="input-label">SSL key / path</label>
          <textarea
            className="textarea"
            rows={4}
            placeholder="Paste PEM, or provide path"
            value={sslKey}
            onChange={(e) => setSslKey(e.target.value)}
          />
        </div>
        <p className="text-muted small-text">
          We remember this locally so the field is pre-filled next time. The
          decrypt function is left empty; connect it to your backend when ready.
        </p>
      </Modal>

      <Modal
        isOpen={showUploadModal}
        title="Upload existing capture (capture_*.txt)"
        onClose={() => setShowUploadModal(false)}
        onSubmit={handleUpload}
        submitLabel="Upload & parse"
        busyLabel="Uploading..."
        isBusy={isUploading}
      >
        <div className="input-group">
          <label className="input-label">Capture text file</label>
          <input
            className="input"
            type="file"
            accept=".txt"
            onChange={(e) => setUploadFile(e.target.files?.[0] || null)}
          />
        </div>
        <div className="input-group">
          <label className="input-label">IP range hint (optional)</label>
          <input
            className="input"
            placeholder="e.g. 0.0.0.0/0 or unknown"
            value={uploadIpRange}
            onChange={(e) => setUploadIpRange(e.target.value)}
          />
        </div>
        <p className="text-muted small-text">
          The file is uploaded to the backend, parsed by parse_flowlets.py, and
          its flowlets are saved to SQLite. Once parsed, the capture is marked
          analyzed.
        </p>
      </Modal>
    </div>
  );
}
