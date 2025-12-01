// src/App.jsx
import React, { useEffect, useMemo, useState } from "react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ResponsiveContainer,
} from "recharts";

const REFRESH_INTERVAL_MS = 5000; // poll every 5s

function useTrafficData() {
  const [events, setEvents] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [lastError, setLastError] = useState(null);

  useEffect(() => {
    let cancelled = false;

    async function fetchTraffic() {
      setIsLoading(true);
      try {
        const res = await fetch("/mock_traffic.json"); // make sure this file is in /public
        if (!res.ok) {
          throw new Error(`HTTP ${res.status}`);
        }
        const data = await res.json();
        if (!cancelled) {
          const sorted = [...data].sort(
            (a, b) => new Date(a.timestamp) - new Date(b.timestamp)
          );
          setEvents(sorted);
          setLastError(null);
        }
      } catch (err) {
        if (!cancelled) {
          console.error("Failed to fetch traffic", err);
          setLastError(err.message || String(err));
        }
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    }

    fetchTraffic();

    return () => {
      cancelled = true;
    };
  }, []);

  return { events, isLoading, lastError };
}


function formatTime(ts) {
  if (!ts) return "";
  const d = new Date(ts);
  return d.toLocaleTimeString();
}

function bytesToHuman(bytes) {
  if (bytes == null) return "-";
  if (bytes < 1024) return `${bytes} B`;
  const kb = bytes / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB`;
  const mb = kb / 1024;
  return `${mb.toFixed(1)} MB`;
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
        <LineChart data={chartData} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
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
      <div className="card-body text-muted">
        No LLM usage detected yet.
      </div>
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
            <tr key={e.id}>
              <td>{formatTime(e.timestamp)}</td>
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

export default function App() {
  const { events, isLoading, lastError } = useTrafficData();

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

      {lastError && (
        <div className="alert alert-error">
          Failed to fetch traffic: {lastError}
        </div>
      )}

      <SummaryCards events={events} />

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <h2>Traffic over time</h2>
            <p className="card-subtitle">
              Total vs LLM bytes (bucketed in ~10s intervals)
            </p>
          </div>
          <TrafficChart events={events} />
        </div>

        <div className="card">
          <div className="card-header">
            <h2>LLM usage events</h2>
            <p className="card-subtitle">
              Detected LLM calls (from backend classifier)
            </p>
          </div>
          <LLMEventsTable events={events} />
        </div>
      </div>
    </div>
  );
}
