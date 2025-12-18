// src/App.jsx
import React, { useEffect, useState } from "react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ResponsiveContainer,
} from "recharts";

const API_BASE = "http://localhost:8000";

function useCaptures() {
  const [captures, setCaptures] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchCaptures = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/captures`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setCaptures(data);
    } catch (err) {
      console.error("Failed to fetch captures", err);
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchCaptures();
    const interval = setInterval(fetchCaptures, 5000); // Refresh every 5s
    return () => clearInterval(interval);
  }, []);

  return { captures, isLoading, error, refetch: fetchCaptures };
}

function formatDate(dateStr) {
  if (!dateStr) return "-";
  return new Date(dateStr).toLocaleString();
}

function CaptureTable({ captures, onCaptureClick, onParse, onClassify }) {
  if (captures.length === 0) {
    return <div className="card-body text-muted">No captures yet.</div>;
  }

  return (
    <div className="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>File Path</th>
            <th>Created</th>
            <th>Status</th>
            <th>Flows</th>
            <th>LLM Flows</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {captures.map((capture) => (
            <tr key={capture.id}>
              <td>{capture.id}</td>
              <td>
                <a
                  href="#"
                  onClick={(e) => {
                    e.preventDefault();
                    onCaptureClick(capture.id);
                  }}
                  style={{ color: "#007bff", cursor: "pointer" }}
                >
                  {capture.file_path.split("/").pop() || "-"}
                </a>
              </td>
              <td>{formatDate(capture.created_at)}</td>
              <td>
                <span
                  className={`status-badge ${
                    capture.status === "completed"
                      ? "status-completed"
                      : capture.status === "running"
                      ? "status-running"
                      : "status-failed"
                  }`}
                >
                  {capture.status}
                </span>
              </td>
              <td>{capture.flow_count || 0}</td>
              <td>{capture.llm_flow_count ?? "-"}</td>
              <td>
                <div style={{ display: "flex", gap: "8px" }}>
                  {capture.flow_count === 0 && capture.status === "completed" && (
                    <button
                      className="btn btn-sm"
                      onClick={() => onParse(capture.id)}
                    >
                      Parse
                    </button>
                  )}
                  {capture.flow_count > 0 && (
                    <button
                      className="btn btn-sm"
                      onClick={() => onClassify(capture.id)}
                    >
                      Classify
                    </button>
                  )}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function CaptureStartDialog({ isOpen, onClose, onStart }) {
  const [formData, setFormData] = useState({
    ip_range: "",
    interface: "",
    outdir: "captures",
    timeout: "",
    snaplen: "96",
    extra_filter: "",
    use_ssl_decrypt: false,
  });

  if (!isOpen) return null;

  const handleSubmit = (e) => {
    e.preventDefault();
    onStart({
      ip_range: formData.ip_range,
      interface: formData.interface || null,
      outdir: formData.outdir || null,
      timeout: formData.timeout ? parseInt(formData.timeout) : null,
      snaplen: parseInt(formData.snaplen) || 96,
      extra_filter: formData.extra_filter || null,
    });
    onClose();
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <h2>Start Capture</h2>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>
              IP Range (CIDR) <span style={{ color: "red" }}>*</span>
            </label>
            <input
              type="text"
              value={formData.ip_range}
              onChange={(e) =>
                setFormData({ ...formData, ip_range: e.target.value })
              }
              placeholder="e.g., 192.168.1.0/24"
              required
            />
          </div>
          <div className="form-group">
            <label>Interface</label>
            <input
              type="text"
              value={formData.interface}
              onChange={(e) =>
                setFormData({ ...formData, interface: e.target.value })
              }
              placeholder="e.g., eth0, en0"
            />
          </div>
          <div className="form-group">
            <label>Output Directory</label>
            <input
              type="text"
              value={formData.outdir}
              onChange={(e) =>
                setFormData({ ...formData, outdir: e.target.value })
              }
              placeholder="captures"
            />
          </div>
          <div className="form-group">
            <label>Timeout (seconds)</label>
            <input
              type="number"
              value={formData.timeout}
              onChange={(e) =>
                setFormData({ ...formData, timeout: e.target.value })
              }
              placeholder="Leave empty for indefinite"
            />
          </div>
          <div className="form-group">
            <label>Snap Length</label>
            <input
              type="number"
              value={formData.snaplen}
              onChange={(e) =>
                setFormData({ ...formData, snaplen: e.target.value })
              }
            />
          </div>
          <div className="form-group">
            <label>Extra Filter</label>
            <input
              type="text"
              value={formData.extra_filter}
              onChange={(e) =>
                setFormData({ ...formData, extra_filter: e.target.value })
              }
              placeholder="e.g., tcp port 443"
            />
          </div>
          <div className="form-group">
            <label style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <input
                type="checkbox"
                checked={formData.use_ssl_decrypt}
                onChange={(e) =>
                  setFormData({ ...formData, use_ssl_decrypt: e.target.checked })
                }
              />
              Use SSL Decryption (requires SSL keys to be configured)
            </label>
          </div>
          <div style={{ display: "flex", gap: "8px", justifyContent: "flex-end" }}>
            <button type="button" className="btn btn-secondary" onClick={onClose}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary">
              Start
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

function SSLKeysDialog({ isOpen, onClose }) {
  const [sslKeyPath, setSslKeyPath] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    if (isOpen) {
      fetch(`${API_BASE}/api/ssl-keys`)
        .then((res) => res.json())
        .then((data) => setSslKeyPath(data.ssl_key_path || ""))
        .catch((err) => console.error("Failed to load SSL keys", err));
    }
  }, [isOpen]);

  const handleSave = async () => {
    setIsLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/ssl-keys`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ssl_key_path: sslKeyPath || null }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      alert("SSL keys configuration saved");
      onClose();
    } catch (err) {
      alert(`Failed to save SSL keys: ${err.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <h2>SSL Keys Configuration</h2>
        <div className="form-group">
          <label>SSL Key Log File Path</label>
          <input
            type="text"
            value={sslKeyPath}
            onChange={(e) => setSslKeyPath(e.target.value)}
            placeholder="/path/to/sslkeylogfile.txt"
            style={{ width: "100%" }}
          />
          <small style={{ color: "var(--muted)", fontSize: "0.8rem" }}>
            Path to your SSLKEYLOGFILE (used for decrypting TLS traffic)
          </small>
        </div>
        <div style={{ display: "flex", gap: "8px", justifyContent: "flex-end" }}>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={handleSave}
            disabled={isLoading}
          >
            Save
          </button>
        </div>
      </div>
    </div>
  );
}

function CaptureDetailView({ captureId, onClose }) {
  const [chartData, setChartData] = useState([]);
  const [flowlets, setFlowlets] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      setIsLoading(true);
      setError(null);
      try {
        const [chartRes, flowletsRes] = await Promise.all([
          fetch(`${API_BASE}/api/captures/${captureId}/flowlets/chart`),
          fetch(`${API_BASE}/api/captures/${captureId}/flowlets?limit=1000`),
        ]);
        if (!chartRes.ok) throw new Error(`HTTP ${chartRes.status}`);
        if (!flowletsRes.ok) throw new Error(`HTTP ${flowletsRes.status}`);
        const chartData = await chartRes.json();
        const flowletsData = await flowletsRes.json();
        setChartData(chartData);
        setFlowlets(flowletsData);
      } catch (err) {
        console.error("Failed to fetch data", err);
        setError(err.message);
      } finally {
        setIsLoading(false);
      }
    };

    if (captureId) {
      fetchData();
      const interval = setInterval(fetchData, 5000);
      return () => clearInterval(interval);
    }
  }, [captureId]);

  if (!captureId) return null;

  const hasGroundTruth = flowlets.some((f) => f.ground_truth_llm);
  const hasPredictions = flowlets.some((f) => f.model_llm_prediction);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content modal-large" onClick={(e) => e.stopPropagation()}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px" }}>
          <h2>Capture {captureId} - Flow Patterns</h2>
          <button className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
        </div>
        {error && <div className="alert alert-error">{error}</div>}
        {isLoading && <div>Loading data...</div>}
        {!isLoading && chartData.length === 0 && (
          <div className="text-muted">No flowlet data available.</div>
        )}
        {!isLoading && chartData.length > 0 && (
          <>
            <div style={{ height: "400px", marginBottom: "20px" }}>
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={chartData} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis
                    dataKey="time"
                    tickFormatter={(t) => {
                      const hours = Math.floor(t / 3600);
                      const minutes = Math.floor((t % 3600) / 60);
                      const seconds = Math.floor(t % 60);
                      return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
                    }}
                  />
                  <YAxis
                    tickFormatter={(value) => {
                      if (value < 1024) return `${value} B`;
                      if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
                      return `${(value / (1024 * 1024)).toFixed(1)} MB`;
                    }}
                  />
                  <Tooltip
                    labelFormatter={(ts) => {
                      const hours = Math.floor(ts / 3600);
                      const minutes = Math.floor((ts % 3600) / 60);
                      const seconds = Math.floor(ts % 60);
                      return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
                    }}
                    formatter={(value, name) => {
                      if (value < 1024) return [`${value} B`, name];
                      if (value < 1024 * 1024) return [`${(value / 1024).toFixed(1)} KB`, name];
                      return [`${(value / (1024 * 1024)).toFixed(1)} MB`, name];
                    }}
                  />
                  <Line
                    type="monotone"
                    dataKey="total_bytes"
                    name="Total bytes"
                    stroke="#8884d8"
                    strokeWidth={2}
                    dot={false}
                  />
                  <Line
                    type="monotone"
                    dataKey="llm_bytes"
                    name="LLM bytes"
                    stroke="#82ca9d"
                    strokeWidth={2}
                    dot={false}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
            {(hasGroundTruth || hasPredictions) && (
              <div style={{ marginTop: "20px" }}>
                <h3>Predicted vs Actual (Sample Flowlets)</h3>
                <div className="table-wrapper" style={{ maxHeight: "300px", overflowY: "auto" }}>
                  <table>
                    <thead>
                      <tr>
                        <th>Flowlet ID</th>
                        <th>Ground Truth</th>
                        <th>Predicted</th>
                        <th>Confidence</th>
                        <th>Match</th>
                      </tr>
                    </thead>
                    <tbody>
                      {flowlets
                        .filter((f) => f.ground_truth_llm || f.model_llm_prediction)
                        .slice(0, 50)
                        .map((flowlet) => {
                          // Determine if prediction matches ground truth
                          let match = null;
                          if (flowlet.ground_truth_llm && flowlet.model_llm_prediction) {
                            const gt = flowlet.ground_truth_llm.toLowerCase();
                            const pred = flowlet.model_llm_prediction.toLowerCase();
                            // Match if they're the same, or if ground truth is an LLM and prediction is non_llm (mismatch)
                            match = gt === pred;
                          }
                          return (
                            <tr key={flowlet.id}>
                              <td>{flowlet.flowlet_id}</td>
                              <td>{flowlet.ground_truth_llm || "-"}</td>
                              <td>{flowlet.model_llm_prediction || "-"}</td>
                              <td>
                                {flowlet.model_llm_confidence
                                  ? `${(flowlet.model_llm_confidence * 100).toFixed(0)}%`
                                  : "-"}
                              </td>
                              <td>
                                {match !== null ? (
                                  <span
                                    className={`status-badge ${
                                      match ? "status-completed" : "status-failed"
                                    }`}
                                  >
                                    {match ? "✓" : "✗"}
                                  </span>
                                ) : (
                                  "-"
                                )}
                              </td>
                            </tr>
                          );
                        })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

export default function App() {
  const { captures, isLoading, error, refetch } = useCaptures();
  const [showStartDialog, setShowStartDialog] = useState(false);
  const [showSSLDialog, setShowSSLDialog] = useState(false);
  const [selectedCaptureId, setSelectedCaptureId] = useState(null);
  const [runningCaptures, setRunningCaptures] = useState(new Set());

  const handleStartCapture = async (data) => {
    try {
      const res = await fetch(`${API_BASE}/api/captures/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const result = await res.json();
      setRunningCaptures(new Set([...runningCaptures, result.id]));
      refetch();
    } catch (err) {
      alert(`Failed to start capture: ${err.message}`);
    }
  };

  const handleStopCapture = async (captureId) => {
    try {
      const res = await fetch(`${API_BASE}/api/captures/${captureId}/stop`, {
        method: "POST",
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setRunningCaptures(new Set([...runningCaptures].filter(id => id !== captureId)));
      refetch();
    } catch (err) {
      alert(`Failed to stop capture: ${err.message}`);
    }
  };

  const handleParse = async (captureId) => {
    try {
      const res = await fetch(`${API_BASE}/api/captures/${captureId}/parse`, {
        method: "POST",
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      alert("Parsing started in background");
      refetch();
    } catch (err) {
      alert(`Failed to start parsing: ${err.message}`);
    }
  };

  const handleClassify = async (captureId) => {
    try {
      const res = await fetch(`${API_BASE}/api/captures/${captureId}/classify`, {
        method: "POST",
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      alert("Classification started in background");
      refetch();
    } catch (err) {
      alert(`Failed to start classification: ${err.message}`);
    }
  };

  return (
    <div className="app-root">
      <header className="app-header">
        <h1>Network Capture Manager</h1>
        <div className="app-status">
          {isLoading && <span className="status-dot status-dot-loading" />}
          {!isLoading && <span className="status-dot status-dot-ok" />}
          <span className="status-text">
            {isLoading ? "Loading..." : "Live"}
          </span>
        </div>
      </header>

      {error && (
        <div className="alert alert-error">
          Failed to fetch captures: {error}
        </div>
      )}

      <div className="card">
        <div className="card-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <h2>Captures</h2>
          <div style={{ display: "flex", gap: "8px" }}>
            <button
              className="btn btn-secondary"
              onClick={() => setShowSSLDialog(true)}
            >
              SSL Keys
            </button>
            <button
              className="btn btn-primary"
              onClick={() => setShowStartDialog(true)}
            >
              Start Capture
            </button>
          </div>
        </div>
        <CaptureTable
          captures={captures}
          onCaptureClick={setSelectedCaptureId}
          onParse={handleParse}
          onClassify={handleClassify}
        />
      </div>

      <CaptureStartDialog
        isOpen={showStartDialog}
        onClose={() => setShowStartDialog(false)}
        onStart={handleStartCapture}
      />

      <SSLKeysDialog
        isOpen={showSSLDialog}
        onClose={() => setShowSSLDialog(false)}
      />

      {selectedCaptureId && (
        <CaptureDetailView
          captureId={selectedCaptureId}
          onClose={() => setSelectedCaptureId(null)}
        />
      )}
    </div>
  );
}
