import { useEffect, useMemo, useRef, useState } from "react";

const API_BASE = "http://localhost:8000";

const colors = {
  bg: "#010409",
  cyan: "#4cc9f0",
  orange: "#ff6b35",
  green: "#30d158",
  red: "#ff2d55",
  yellow: "#ffd60a",
  purple: "#bf5af2",
  panel: "#0b111a",
  panelBorder: "#131b26",
  text: "#d6e2f0",
  muted: "#8fa3b8"
};

const severityColors = {
  Critical: colors.purple,
  High: colors.orange,
  Medium: colors.yellow,
  Low: colors.green
};

const attackSeverityMap = {
  "Command Injection": "Critical",
  "SQL Injection": "High",
  "Directory Traversal": "High",
  "Cross-Site Scripting": "Medium",
  Unknown: "Low"
};

function StatCard({ label, value, sub, color }) {
  return (
    <div
      style={{
        background: colors.panel,
        border: `1px solid ${colors.panelBorder}`,
        borderLeft: `4px solid ${color}`,
        borderRadius: 10,
        padding: 16,
        boxShadow: `0 0 18px ${color}22`,
        animation: "fadeIn 0.6s ease",
        minHeight: 88
      }}
    >
      <div style={{ color: colors.muted, fontSize: 12, letterSpacing: 1 }}>
        {label}
      </div>
      <div style={{ color: colors.text, fontSize: 26, marginTop: 6 }}>
        {value}
      </div>
      <div style={{ color: color, fontSize: 12, marginTop: 4 }}>{sub}</div>
    </div>
  );
}

function SeverityBadge({ level }) {
  const badgeColor = severityColors[level] || colors.muted;
  return (
    <span
      style={{
        padding: "4px 10px",
        borderRadius: 20,
        background: `${badgeColor}1a`,
        color: badgeColor,
        border: `1px solid ${badgeColor}55`,
        boxShadow: `0 0 12px ${badgeColor}33`,
        fontSize: 12,
        animation: "fadeIn 0.6s ease"
      }}
    >
      {level}
    </span>
  );
}

export default function App() {
  const [threats, setThreats] = useState([]);
  const [stats, setStats] = useState(null);
  const [selected, setSelected] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("ALL");
  const [uploading, setUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState(null);
  const fileInputRef = useRef(null);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [analyzeRes, statsRes] = await Promise.all([
        fetch(`${API_BASE}/analyze`),
        fetch(`${API_BASE}/stats`)
      ]);
      const analyzeData = await analyzeRes.json();
      const statsData = await statsRes.json();
      setThreats(analyzeData.results || []);
      setStats(statsData || null);
      setSelected(null);
    } catch (err) {
      setUploadResult({ type: "error", message: "Failed to load data." });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const timer = setInterval(fetchData, 30000);
    return () => clearInterval(timer);
  }, []);

  const filteredThreats = useMemo(() => {
    if (filter === "MALICIOUS") {
      return threats.filter((t) => t.ml_classification === "malicious");
    }
    if (filter === "NORMAL") {
      return threats.filter((t) => t.ml_classification === "normal");
    }
    return threats;
  }, [threats, filter]);

  const counts = useMemo(() => {
    const malicious = threats.filter((t) => t.ml_classification === "malicious").length;
    const normal = threats.filter((t) => t.ml_classification === "normal").length;
    return { all: threats.length, malicious, normal };
  }, [threats]);

  const handleUpload = async (event) => {
    const file = event.target.files && event.target.files[0];
    if (!file) return;
    setUploading(true);
    setUploadResult(null);
    try {
      const formData = new FormData();
      formData.append("file", file);
      const res = await fetch(`${API_BASE}/analyze-log`, {
        method: "POST",
        body: formData
      });
      const data = await res.json();
      if (data.error) {
        setUploadResult({ type: "error", message: data.error });
      } else {
        setThreats(data.results || []);
        setSelected(null);
        setUploadResult({ type: "success", message: "Log processed successfully." });
      }
    } catch (err) {
      setUploadResult({ type: "error", message: "Upload failed." });
    } finally {
      setUploading(false);
    }
  };

  const distribution = stats?.attack_distribution || {};

  return (
    <div
      style={{
        minHeight: "100vh",
        background: colors.bg,
        color: colors.text,
        fontFamily: "'JetBrains Mono', monospace",
        padding: 24,
        position: "relative",
        overflow: "hidden"
      }}
    >
      <style>
        {`
          @keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
          @keyframes pulse { 0% { opacity: 0.6; } 50% { opacity: 1; } 100% { opacity: 0.6; } }
          @keyframes shimmer { 0% { background-position: -200px 0; } 100% { background-position: 200px 0; } }
          .scanline { position: absolute; inset: 0; background: repeating-linear-gradient(180deg, rgba(255,255,255,0.03), rgba(255,255,255,0.03) 1px, transparent 1px, transparent 3px); pointer-events: none; }
        `}
      </style>

      <div className="scanline" />

      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
        <div style={{ animation: "fadeIn 0.6s ease" }}>
          <div style={{ fontSize: 28, display: "flex", alignItems: "center", gap: 12 }}>
            AI Threat Monitor
            <span
              style={{
                width: 10,
                height: 10,
                borderRadius: "50%",
                background: colors.green,
                boxShadow: `0 0 10px ${colors.green}`,
                animation: "pulse 1.6s ease infinite"
              }}
            />
          </div>
          <div style={{ color: colors.muted, fontSize: 12, marginTop: 4 }}>
            Web Threat Intelligence · ML Classification · OWASP Detection
          </div>
        </div>

        <div style={{ display: "flex", gap: 12, animation: "fadeIn 0.6s ease" }}>
          <button
            onClick={fetchData}
            style={{
              background: colors.cyan,
              color: "#00111a",
              border: "none",
              borderRadius: 6,
              padding: "10px 16px",
              cursor: "pointer",
              fontWeight: 700
            }}
          >
            REFRESH
          </button>
          <button
            onClick={() => fileInputRef.current?.click()}
            style={{
              background: colors.orange,
              color: "#1b0d00",
              border: "none",
              borderRadius: 6,
              padding: "10px 16px",
              cursor: "pointer",
              fontWeight: 700
            }}
          >
            {uploading ? "UPLOADING..." : "UPLOAD LOG"}
          </button>
          <input
            ref={fileInputRef}
            type="file"
            accept=".txt,.log"
            onChange={handleUpload}
            style={{ display: "none" }}
          />
        </div>
      </div>

      {uploadResult && (
        <div
          style={{
            background: uploadResult.type === "success" ? `${colors.green}1a` : `${colors.red}1a`,
            border: `1px solid ${uploadResult.type === "success" ? colors.green : colors.red}`,
            color: uploadResult.type === "success" ? colors.green : colors.red,
            padding: "10px 14px",
            borderRadius: 8,
            marginBottom: 18,
            animation: "fadeIn 0.6s ease"
          }}
        >
          {uploadResult.message}
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 280px", gap: 20 }}>
        <div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: 18 }}>
            <StatCard
              label="TOTAL REQUESTS"
              value={stats?.total_requests ?? "--"}
              sub="All inbound traffic"
              color={colors.cyan}
            />
            <StatCard
              label="THREATS DETECTED"
              value={stats?.malicious_detected ?? "--"}
              sub="ML flagged"
              color={colors.red}
            />
            <StatCard
              label="HIGH SEVERITY"
              value={stats?.high_severity ?? "--"}
              sub="High + Critical"
              color={colors.orange}
            />
            <StatCard
              label="NORMAL TRAFFIC"
              value={stats?.normal_traffic ?? "--"}
              sub="Classified normal"
              color={colors.green}
            />
          </div>

          <div style={{ display: "flex", gap: 10, marginBottom: 12, animation: "fadeIn 0.6s ease" }}>
            {[
              { label: `ALL (${counts.all})`, value: "ALL" },
              { label: `MALICIOUS (${counts.malicious})`, value: "MALICIOUS" },
              { label: `NORMAL (${counts.normal})`, value: "NORMAL" }
            ].map((tab) => (
              <button
                key={tab.value}
                onClick={() => setFilter(tab.value)}
                style={{
                  background: filter === tab.value ? colors.cyan : colors.panel,
                  color: filter === tab.value ? "#00111a" : colors.text,
                  border: `1px solid ${colors.panelBorder}`,
                  borderRadius: 20,
                  padding: "6px 14px",
                  cursor: "pointer",
                  fontSize: 12
                }}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <div
            style={{
              background: colors.panel,
              border: `1px solid ${colors.panelBorder}`,
              borderRadius: 12,
              padding: 12,
              animation: "fadeIn 0.6s ease"
            }}
          >
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                <thead>
                  <tr style={{ textAlign: "left", color: colors.muted }}>
                    <th style={{ padding: "10px 8px" }}>Time</th>
                    <th style={{ padding: "10px 8px" }}>Source IP</th>
                    <th style={{ padding: "10px 8px" }}>Endpoint</th>
                    <th style={{ padding: "10px 8px" }}>Attack Type</th>
                    <th style={{ padding: "10px 8px" }}>Severity</th>
                    <th style={{ padding: "10px 8px" }}>ML Class</th>
                    <th style={{ padding: "10px 8px" }}>Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {loading && (
                    <tr>
                      <td colSpan={7} style={{ padding: 20 }}>
                        <div
                          style={{
                            height: 12,
                            borderRadius: 6,
                            background: "linear-gradient(90deg, #0b111a, #172233, #0b111a)",
                            backgroundSize: "200px 100%",
                            animation: "shimmer 1.2s linear infinite"
                          }}
                        />
                      </td>
                    </tr>
                  )}
                  {!loading && filteredThreats.length === 0 && (
                    <tr>
                      <td colSpan={7} style={{ padding: 16, color: colors.muted }}>
                        No entries found.
                      </td>
                    </tr>
                  )}
                  {!loading &&
                    filteredThreats.map((row, idx) => (
                      <tr
                        key={idx}
                        onClick={() => setSelected(row)}
                        style={{
                          background: selected === row ? "#101a28" : "transparent",
                          cursor: "pointer"
                        }}
                      >
                        <td style={{ padding: "10px 8px", borderTop: `1px solid ${colors.panelBorder}` }}>
                          {row.timestamp}
                        </td>
                        <td style={{ padding: "10px 8px", borderTop: `1px solid ${colors.panelBorder}` }}>
                          {row.ip}
                        </td>
                        <td style={{ padding: "10px 8px", borderTop: `1px solid ${colors.panelBorder}` }}>
                          {row.endpoint}
                        </td>
                        <td style={{ padding: "10px 8px", borderTop: `1px solid ${colors.panelBorder}` }}>
                          {row.attack_type}
                        </td>
                        <td style={{ padding: "10px 8px", borderTop: `1px solid ${colors.panelBorder}` }}>
                          <SeverityBadge level={row.severity} />
                        </td>
                        <td style={{ padding: "10px 8px", borderTop: `1px solid ${colors.panelBorder}` }}>
                          {row.ml_classification}
                        </td>
                        <td style={{ padding: "10px 8px", borderTop: `1px solid ${colors.panelBorder}` }}>
                          {Math.round(row.confidence * 100)}%
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          </div>

          {selected && (
            <div
              style={{
                marginTop: 18,
                background: colors.panel,
                border: `1px solid ${colors.panelBorder}`,
                borderRadius: 12,
                padding: 18,
                animation: "fadeIn 0.6s ease"
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 14 }}>
                <div style={{ fontSize: 16 }}>Threat Detail</div>
                <button
                  onClick={() => setSelected(null)}
                  style={{
                    background: "transparent",
                    color: colors.muted,
                    border: `1px solid ${colors.panelBorder}`,
                    borderRadius: 6,
                    padding: "6px 10px",
                    cursor: "pointer"
                  }}
                >
                  CLOSE
                </button>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12 }}>
                {[
                  { label: "What Happened", value: selected.ai_summary?.what_happened },
                  { label: "Potential Impact", value: selected.ai_summary?.potential_impact },
                  { label: "Recommended Action", value: selected.ai_summary?.recommended_action },
                  { label: "OWASP Reference", value: selected.ai_summary?.owasp_reference }
                ].map((card, idx) => (
                  <div
                    key={idx}
                    style={{
                      background: "#0f1724",
                      border: `1px solid ${colors.panelBorder}`,
                      borderRadius: 10,
                      padding: 12,
                      animation: "fadeIn 0.6s ease"
                    }}
                  >
                    <div style={{ color: colors.muted, fontSize: 12, marginBottom: 6 }}>{card.label}</div>
                    <div style={{ fontSize: 13 }}>{card.value}</div>
                  </div>
                ))}
              </div>

              <div style={{ marginTop: 14 }}>
                <div style={{ color: colors.muted, fontSize: 12, marginBottom: 6 }}>Raw Payload</div>
                <div
                  style={{
                    background: "#0a0f16",
                    border: `1px solid ${colors.panelBorder}`,
                    borderRadius: 8,
                    padding: 10,
                    fontSize: 12
                  }}
                >
                  {selected.payload}
                </div>
              </div>
            </div>
          )}
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <div
            style={{
              background: colors.panel,
              border: `1px solid ${colors.panelBorder}`,
              borderRadius: 12,
              padding: 16,
              animation: "fadeIn 0.6s ease"
            }}
          >
            <div style={{ marginBottom: 12, fontSize: 13, color: colors.muted }}>Attack Distribution</div>
            {Object.keys(distribution).length === 0 && (
              <div style={{ color: colors.muted, fontSize: 12 }}>No data.</div>
            )}
            {Object.entries(distribution).map(([key, value]) => {
              const barColor = severityColors[attackSeverityMap[key] || "Low"] || colors.cyan;
              return (
                <div key={key} style={{ marginBottom: 10 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}>
                    <span>{key}</span>
                    <span style={{ color: colors.muted }}>{value}</span>
                  </div>
                  <div
                    style={{
                      background: "#111927",
                      borderRadius: 6,
                      height: 6,
                      marginTop: 6,
                      overflow: "hidden"
                    }}
                  >
                    <div
                      style={{
                        width: `${Math.min(100, value * 15)}%`,
                        height: "100%",
                        background: barColor
                      }}
                    />
                  </div>
                </div>
              );
            })}
          </div>

          <div
            style={{
              background: colors.panel,
              border: `1px solid ${colors.panelBorder}`,
              borderRadius: 12,
              padding: 16,
              animation: "fadeIn 0.6s ease"
            }}
          >
            <div style={{ marginBottom: 12, fontSize: 13, color: colors.muted }}>Severity Levels</div>
            {Object.keys(severityColors).map((level) => (
              <div key={level} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                <span
                  style={{
                    width: 10,
                    height: 10,
                    borderRadius: "50%",
                    background: severityColors[level],
                    boxShadow: `0 0 8px ${severityColors[level]}`
                  }}
                />
                <span style={{ fontSize: 12 }}>{level}</span>
              </div>
            ))}
          </div>

          <div
            style={{
              background: colors.panel,
              border: `1px solid ${colors.panelBorder}`,
              borderRadius: 12,
              padding: 16,
              animation: "fadeIn 0.6s ease"
            }}
          >
            <div style={{ marginBottom: 12, fontSize: 13, color: colors.muted }}>System Info</div>
            {[
              { label: "Engine", value: "Threat Engine v1" },
              { label: "ML Model", value: "TF-IDF + LogisticRegression" },
              { label: "Detection", value: `${stats?.detection_rate ?? 0}%` },
              { label: "AI Layer", value: "SOC Summaries" },
              { label: "Version", value: "1.0.0" }
            ].map((item) => (
              <div key={item.label} style={{ display: "flex", justifyContent: "space-between", fontSize: 12, marginBottom: 6 }}>
                <span style={{ color: colors.muted }}>{item.label}</span>
                <span>{item.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
