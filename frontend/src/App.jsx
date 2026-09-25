import { useEffect, useMemo, useState } from "react";
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  LineChart,
  Line,
} from "recharts";

import "./App.css";

const API = "";

function App() {
  const [requests, setRequests] = useState([]);
  const [backendStatus, setBackendStatus] = useState("CHECKING");
  const [activePage, setActivePage] = useState("Overview");
  const [lastUpdate, setLastUpdate] = useState(null);
  const [modelEvaluation, setModelEvaluation] = useState(null);

  // ============================================================
  // LOAD DATA
  // ============================================================

  const loadData = async () => {
    try {
      const response = await fetch(`${API}/dashboard/live-history`);

      if (!response.ok) {
        throw new Error("Failed to load dashboard data");
      }

      const data = await response.json();

      if (Array.isArray(data.requests)) {
        setRequests(data.requests);
      }

      setBackendStatus("ONLINE");
      setLastUpdate(new Date());
    } catch (error) {
      console.error("Dashboard error:", error);
      setBackendStatus("OFFLINE");
    }
  };

  const loadModelEvaluation = async () => {
    try {
      const response = await fetch(`${API}/dashboard/model-evaluation`);

      if (!response.ok) {
        throw new Error("Failed to load model evaluation");
      }

      const data = await response.json();
      setModelEvaluation(data);
    } catch (error) {
      console.error("Model evaluation error:", error);
    }
  };

  const checkHealth = async () => {
    try {
      const response = await fetch(`${API}/health`);

      if (!response.ok) {
        throw new Error("Backend unavailable");
      }

      setBackendStatus("ONLINE");
    } catch {
      setBackendStatus("OFFLINE");
    }
  };

  useEffect(() => {
    loadData();
    checkHealth();
    loadModelEvaluation();

    const interval = setInterval(() => {
      loadData();
      checkHealth();
      loadModelEvaluation();
    }, 2000);

    return () => clearInterval(interval);
  }, []);

  // ============================================================
  // NORMALIZE REQUEST DATA
  // ============================================================

  const normalizedRequests = useMemo(() => {
    return requests.map((r) => ({
      ...r,
      action: String(
        r.action ||
          r.proxy_action ||
          r.decision ||
          "ALLOW"
      ).toUpperCase(),

      attack_type:
        r.attack_type ||
        r.predicted_class_name ||
        r.predicted_class ||
        "BENIGN",

      risk_score: Number(
        r.risk_score ??
          r.risk?.risk_score ??
          0
      ),

      timestamp:
        r.timestamp ||
        r.created_at ||
        new Date().toISOString(),

      ip:
        r.ip ||
        r.source_ip ||
        r.client_ip ||
        "127.0.0.1",

      endpoint:
        r.endpoint ||
        "/proxy",
    }));
  }, [requests]);

  // ============================================================
  // STATISTICS
  // ============================================================

  const stats = useMemo(() => {
    const total = normalizedRequests.length;

    const allowed = normalizedRequests.filter(
      (r) => r.action === "ALLOW"
    ).length;

    const blocked = normalizedRequests.filter(
      (r) => r.action === "BLOCK"
    ).length;

    const rateLimited = normalizedRequests.filter(
      (r) =>
        r.action === "RATE_LIMIT" ||
        r.action === "RATE-LIMIT" ||
        r.action === "RATELIMIT"
    ).length;

    const attacks = normalizedRequests.filter(
      (r) =>
        r.action === "BLOCK" ||
        String(r.attack_type).toUpperCase() !== "BENIGN"
    ).length;

    const avgRisk =
      total > 0
        ? normalizedRequests.reduce(
            (sum, r) => sum + r.risk_score,
            0
          ) / total
        : 0;

    const maxRisk =
      total > 0
        ? Math.max(
            ...normalizedRequests.map(
              (r) => r.risk_score
            )
          )
        : 0;

    return {
      total,
      allowed,
      blocked,
      rateLimited,
      attacks,
      avgRisk,
      maxRisk,
    };
  }, [normalizedRequests]);

  // ============================================================
  // CHART DATA
  // ============================================================

  const decisionData = [
    {
      name: "Allowed",
      value: stats.allowed,
    },
    {
      name: "Blocked",
      value: stats.blocked,
    },
    {
      name: "Rate Limited",
      value: stats.rateLimited,
    },
  ];

  const attackMap = {};

  normalizedRequests.forEach((request) => {
    const type = request.attack_type || "UNKNOWN";

    attackMap[type] =
      (attackMap[type] || 0) + 1;
  });

  const attackData = Object.entries(
    attackMap
  ).map(([name, value]) => ({
    name,
    value,
  }));

  const trafficData = [...normalizedRequests]
    .slice(-20)
    .reverse()
    .map((request, index) => ({
      name: index + 1,
      risk: request.risk_score,
    }));

  const recentRequests = [
    ...normalizedRequests,
  ]
    .reverse()
    .slice(0, 12);

  // ============================================================
  // RISK
  // ============================================================

  const currentRisk =
    recentRequests.length > 0
      ? recentRequests[0].risk_score
      : 0;

  let riskLevel = "NORMAL";

  if (currentRisk >= 0.8) {
    riskLevel = "CRITICAL";
  } else if (currentRisk >= 0.6) {
    riskLevel = "ESCALATING";
  } else if (currentRisk >= 0.3) {
    riskLevel = "SUSPICIOUS";
  } else if (currentRisk >= 0.15) {
    riskLevel = "WATCH";
  }

  // ============================================================
  // SIDEBAR
  // ============================================================

  const navigation = [
    {
      name: "Overview",
      icon: "🏠",
    },
    {
      name: "Traffic Monitoring",
      icon: "📊",
    },
    {
      name: "Attack Detection",
      icon: "🛡️",
    },
    {
      name: "Model Evaluation",
      icon: "🧠",
    },
    {
      name: "Risk Analysis",
      icon: "⚙️",
    },
    {
      name: "Mitigation Center",
      icon: "🛠️",
    },
    {
      name: "Backend Health",
      icon: "🔗",
    },
  ];

  // ============================================================
  // HELPERS
  // ============================================================

  const formatTime = (timestamp) => {
    try {
      return new Date(
        timestamp
      ).toLocaleTimeString();
    } catch {
      return "-";
    }
  };

  const getActionClass = (action) => {
    if (action === "BLOCK") {
      return "action-block";
    }

    if (
      action === "RATE_LIMIT" ||
      action === "RATE-LIMIT"
    ) {
      return "action-rate";
    }

    return "action-allow";
  };

  const getAttackClass = (attack) => {
    return String(attack).toUpperCase() ===
      "BENIGN"
      ? "badge-benign"
      : "badge-danger";
  };

  // ============================================================
  // OVERVIEW
  // ============================================================

  const renderOverview = () => (
    <>
      <div className="page-title">
        <div>
          <h1>DDoS Detection &amp;Intelligent Reverse Proxy</h1>
          <p>
            Real-time monitoring, detection and
            autonomous mitigation
          </p>
        </div>

        <div className="running-pill">
          <span className="status-dot online" />
          System Running
          <span className="separator">|</span>
          Uptime Protected
        </div>
      </div>

      {/* STAT CARDS */}

      <section className="stat-grid">
        <div className="stat-card blue">
          <div className="stat-label">
            TOTAL REQUESTS
          </div>

          <div className="stat-value">
            {stats.total}
          </div>

          <div className="stat-description">
            Live monitored requests
          </div>
        </div>

        <div className="stat-card green">
          <div className="stat-label">
            ALLOWED
          </div>

          <div className="stat-value">
            {stats.allowed}
          </div>

          <div className="stat-description">
            Safe requests
          </div>
        </div>

        <div className="stat-card red">
          <div className="stat-label">
            BLOCKED
          </div>

          <div className="stat-value">
            {stats.blocked}
          </div>

          <div className="stat-description">
            Threats blocked
          </div>
        </div>

        <div className="stat-card orange">
          <div className="stat-label">
            RATE LIMITED
          </div>

          <div className="stat-value">
            {stats.rateLimited}
          </div>

          <div className="stat-description">
            Excess requests
          </div>
        </div>

        <div className="stat-card red">
          <div className="stat-label">
            ATTACKS DETECTED
          </div>

          <div className="stat-value">
            {stats.attacks}
          </div>

          <div className="stat-description">
            ML detected threats
          </div>
        </div>

        <div className="stat-card purple">
          <div className="stat-label">
            AVG RISK SCORE
          </div>

          <div className="stat-value">
            {stats.avgRisk.toFixed(3)}
          </div>

          <div className="stat-description">
            Multi-evidence risk
          </div>
        </div>
      </section>

      {/* CHARTS */}

      <section className="dashboard-grid">
        <div className="dashboard-panel">
          <div className="panel-heading">
            <div>
              <h2>Security Decisions</h2>
              <p>Current traffic disposition</p>
            </div>

            <span className="live-label">
              Live
            </span>
          </div>

          <div className="chart-box">
            <ResponsiveContainer
              width="100%"
              height={300}
            >
              <PieChart>
                <Pie
                  data={decisionData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={105}
                  label
                >
                  <Cell fill="#22c55e" />
                  <Cell fill="#ef4444" />
                  <Cell fill="#f59e0b" />
                </Pie>

                <Tooltip
                  contentStyle={{
                    background: "#111827",
                    border:
                      "1px solid #334155",
                    color: "#fff",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="dashboard-panel">
          <div className="panel-heading">
            <div>
              <h2>Attack Distribution</h2>
              <p>ML classification results</p>
            </div>

            <span className="live-label">
              ML Classification
            </span>
          </div>

          <div className="chart-box">
            <ResponsiveContainer
              width="100%"
              height={300}
            >
              <BarChart data={attackData}>
                <CartesianGrid
                  strokeDasharray="3 3"
                  stroke="#334155"
                />

                <XAxis
                  dataKey="name"
                  stroke="#94a3b8"
                  angle={-18}
                  textAnchor="end"
                  height={70}
                />

                <YAxis stroke="#94a3b8" />

                <Tooltip
                  contentStyle={{
                    background: "#111827",
                    border:
                      "1px solid #334155",
                  }}
                />

                <Bar
                  dataKey="value"
                  fill="#8b5cf6"
                  radius={[
                    6,
                    6,
                    0,
                    0,
                  ]}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </section>

      {/* RISK TREND */}

      <section className="dashboard-panel">
        <div className="panel-heading">
          <div>
            <h2>Risk Trend</h2>
            <p>
              Recent multi-evidence risk scores
            </p>
          </div>

          <span className="risk-current">
            Current: {currentRisk.toFixed(3)}
          </span>
        </div>

        <div className="chart-box">
          <ResponsiveContainer
            width="100%"
            height={260}
          >
            <LineChart data={trafficData}>
              <CartesianGrid
                strokeDasharray="3 3"
                stroke="#334155"
              />

              <XAxis
                dataKey="name"
                stroke="#94a3b8"
              />

              <YAxis
                stroke="#94a3b8"
                domain={[0, 1]}
              />

              <Tooltip
                contentStyle={{
                  background: "#111827",
                  border:
                    "1px solid #334155",
                }}
              />

              <Line
                type="monotone"
                dataKey="risk"
                stroke="#3b82f6"
                strokeWidth={3}
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </section>
    </>
  );

  // ============================================================
  // TRAFFIC MONITORING
  // ============================================================

  const renderTraffic = () => (
    <>
      <div className="page-title">
        <div>
          <h1>Traffic Monitoring</h1>
          <p>
            Real-time HTTP request monitoring
          </p>
        </div>

        <button
          className="refresh-button"
          onClick={loadData}
        >
          ↻ Refresh
        </button>
      </div>

      <div className="stat-grid four">
        <div className="stat-card blue">
          <div className="stat-label">
            TOTAL REQUESTS
          </div>

          <div className="stat-value">
            {stats.total}
          </div>
        </div>

        <div className="stat-card green">
          <div className="stat-label">
            ALLOWED
          </div>

          <div className="stat-value">
            {stats.allowed}
          </div>
        </div>

        <div className="stat-card red">
          <div className="stat-label">
            BLOCKED
          </div>

          <div className="stat-value">
            {stats.blocked}
          </div>
        </div>

        <div className="stat-card orange">
          <div className="stat-label">
            RATE LIMITED
          </div>

          <div className="stat-value">
            {stats.rateLimited}
          </div>
        </div>
      </div>

      <RequestTable
        requests={recentRequests}
        formatTime={formatTime}
        getAttackClass={getAttackClass}
        getActionClass={getActionClass}
      />
    </>
  );

  // ============================================================
  // ATTACK DETECTION
  // ============================================================

  const renderAttackDetection = () => (
    <>
      <div className="page-title">
        <div>
          <h1>Attack Detection</h1>
          <p>
            Machine learning based traffic
            classification
          </p>
        </div>

        <div className="model-status">
          <span className="status-dot online" />
          Cascade Active: Student DNN + FT-Transformer
        </div>
      </div>

      <div className="stat-grid four">
        <div className="stat-card blue">
          <div className="stat-label">
            ML INFERENCES
          </div>

          <div className="stat-value">
            {stats.total}
          </div>
        </div>

        <div className="stat-card green">
          <div className="stat-label">
            BENIGN
          </div>

          <div className="stat-value">
            {normalizedRequests.filter(
              (r) =>
                String(
                  r.attack_type
                ).toUpperCase() === "BENIGN"
            ).length}
          </div>
        </div>

        <div className="stat-card red">
          <div className="stat-label">
            ATTACKS FLAGGED
          </div>

          <div className="stat-value">
            {stats.attacks}
          </div>
        </div>

        <div className="stat-card purple">
          <div className="stat-label">
            MAX RISK
          </div>

          <div className="stat-value">
            {stats.maxRisk.toFixed(3)}
          </div>
        </div>
      </div>

      <section className="dashboard-grid">
        <div className="dashboard-panel">
          <div className="panel-heading">
            <div>
              <h2>
                Multi-Class Attack Distribution
              </h2>

              <p>
                Trained attack categories
              </p>
            </div>
          </div>

          <div className="chart-box">
            <ResponsiveContainer
              width="100%"
              height={330}
            >
              <BarChart data={attackData}>
                <CartesianGrid
                  strokeDasharray="3 3"
                  stroke="#334155"
                />

                <XAxis
                  dataKey="name"
                  stroke="#94a3b8"
                  angle={-20}
                  textAnchor="end"
                  height={80}
                />

                <YAxis stroke="#94a3b8" />

                <Tooltip
                  contentStyle={{
                    background: "#111827",
                    border:
                      "1px solid #334155",
                  }}
                />

                <Bar
                  dataKey="value"
                  fill="#8b5cf6"
                  radius={[
                    6,
                    6,
                    0,
                    0,
                  ]}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="dashboard-panel">
          <div className="panel-heading">
            <div>
              <h2>Attack vs Benign</h2>
              <p>Traffic classification ratio</p>
            </div>
          </div>

          <div className="chart-box">
            <ResponsiveContainer
              width="100%"
              height={330}
            >
              <PieChart>
                <Pie
                  data={[
                    {
                      name: "Benign",
                      value:
                        normalizedRequests.filter(
                          (r) =>
                            String(
                              r.attack_type
                            ).toUpperCase() ===
                            "BENIGN"
                        ).length,
                    },
                    {
                      name: "Attacks",
                      value: stats.attacks,
                    },
                  ]}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  innerRadius={65}
                  outerRadius={110}
                  label
                >
                  <Cell fill="#22c55e" />
                  <Cell fill="#ef4444" />
                </Pie>

                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </section>

      <RequestTable
        requests={recentRequests}
        formatTime={formatTime}
        getAttackClass={getAttackClass}
        getActionClass={getActionClass}
      />
    </>
  );

  // ============================================================
  // MODEL EVALUATION
  // ============================================================

  const renderModelEvaluation = () => {
    const evaluation = modelEvaluation?.evaluation;
    const xgb = modelEvaluation?.xgboost;
    const student = modelEvaluation?.student;
    const teacher = modelEvaluation?.teacher;
    const cascade = modelEvaluation?.cascade;
    const limiter = modelEvaluation?.adaptive_limiter;
    const decay = modelEvaluation?.reputation_decay;

    const comparisonData = [
      {
        name: "XGBoost",
        accuracy: Number(xgb?.accuracy || 0) * 100,
        role: "Baseline",
      },
      {
        name: "Student DNN",
        accuracy: Number(student?.accuracy || 0) * 100,
        role: "Fast Detector",
      },
      {
        name: "FT-Transformer",
        accuracy: Number(teacher?.accuracy || 0) * 100,
        role: "Teacher",
      },
      {
        name: "Final Cascade",
        accuracy: Number(cascade?.accuracy || 0) * 100,
        role: "Production",
      },
    ];

    return (
      <>
        <div className="page-title">
          <div>
            <h1>Model Evaluation &amp; AI Cascade</h1>
            <p>
              XGBoost baseline, Student DNN, FT-Transformer teacher and adaptive protection
            </p>
          </div>

          <div className="model-status">
            <span className="status-dot online" />
            Live Evaluation
          </div>
        </div>

        <div className="stat-grid">
          <div className="stat-card blue">
            <div className="stat-label">XGBOOST BASELINE</div>
            <div className="stat-value">
              {xgb ? `${(Number(xgb.accuracy) * 100).toFixed(2)}%` : "—"}
            </div>
            <div className="stat-description">Macro F1: {xgb ? Number(xgb.macro_f1).toFixed(4) : "—"}</div>
          </div>

          <div className="stat-card green">
            <div className="stat-label">STUDENT DNN</div>
            <div className="stat-value">
              {student ? `${(Number(student.accuracy) * 100).toFixed(2)}%` : "—"}
            </div>
            <div className="stat-description">Handles {student ? Number(student.handling_percent).toFixed(1) : "—"}% of requests</div>
          </div>

          <div className="stat-card orange">
            <div className="stat-label">FT-TRANSFORMER</div>
            <div className="stat-value">
              {teacher ? `${(Number(teacher.accuracy) * 100).toFixed(2)}%` : "—"}
            </div>
            <div className="stat-description">Teacher escalation: {teacher ? Number(teacher.escalation_percent).toFixed(1) : "—"}%</div>
          </div>

          <div className="stat-card purple">
            <div className="stat-label">FINAL CASCADE</div>
            <div className="stat-value">
              {cascade ? `${Number(cascade.accuracy_percent).toFixed(2)}%` : "—"}
            </div>
            <div className="stat-description">Attack success: {cascade ? Number(cascade.attack_success_percent).toFixed(2) : "—"}%</div>
          </div>
        </div>

        <section className="dashboard-grid">
          <div className="dashboard-panel">
            <div className="panel-heading">
              <div>
                <h2>Model Accuracy Comparison</h2>
                <p>Baseline versus production cascade</p>
              </div>
            </div>

            <div className="chart-box">
              <ResponsiveContainer width="100%" height={330}>
                <BarChart data={comparisonData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="name" stroke="#94a3b8" />
                  <YAxis domain={[0, 100]} stroke="#94a3b8" />
                  <Tooltip
                    formatter={(value) => [`${Number(value).toFixed(2)}%`, "Accuracy"]}
                    contentStyle={{ background: "#111827", border: "1px solid #334155" }}
                  />
                  <Bar dataKey="accuracy" fill="#8b5cf6" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="dashboard-panel">
            <div className="panel-heading">
              <div>
                <h2>Inference Cascade</h2>
                <p>How AegisProxy makes the final decision</p>
              </div>
            </div>

            <div style={{ display: "grid", gap: "14px", padding: "18px" }}>
              <div className="stat-card blue">
                <div className="stat-label">1 • BASELINE</div>
                <div className="stat-value" style={{ fontSize: "24px" }}>XGBoost</div>
                <div className="stat-description">28 features • 6 classes • 15,000 test samples</div>
              </div>

              <div className="stat-card green">
                <div className="stat-label">2 • PRIMARY FAST DETECTOR</div>
                <div className="stat-value" style={{ fontSize: "24px" }}>Student DNN</div>
                <div className="stat-description">{student ? Number(student.handling_percent).toFixed(1) : "—"}% handled without escalation</div>
              </div>

              <div className="stat-card orange">
                <div className="stat-label">3 • ESCALATION TEACHER</div>
                <div className="stat-value" style={{ fontSize: "24px" }}>FT-Transformer</div>
                <div className="stat-description">{teacher ? Number(teacher.escalation_percent).toFixed(1) : "—"}% escalated for deeper evaluation</div>
              </div>

              <div className="stat-card purple">
                <div className="stat-label">4 • FINAL DECISION</div>
                <div className="stat-value" style={{ fontSize: "24px" }}>Cascade</div>
                <div className="stat-description">Student + teacher + risk engine + adaptive limiter</div>
              </div>
            </div>
          </div>
        </section>

        <section className="dashboard-panel" style={{ marginTop: "20px" }}>
          <div className="panel-heading">
            <div>
              <h2>Detailed Evaluation Results</h2>
              <p>{evaluation?.dataset || "E4 replay evaluation"}</p>
            </div>
          </div>

          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>MODEL</th>
                  <th>ROLE</th>
                  <th>ACCURACY</th>
                  <th>CONFIDENCE</th>
                  <th>HANDLING / ESCALATION</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td><strong>XGBoost</strong></td>
                  <td>Baseline</td>
                  <td>{xgb ? `${(Number(xgb.accuracy) * 100).toFixed(2)}%` : "—"}</td>
                  <td>ROC-AUC {xgb ? Number(xgb.macro_roc_auc).toFixed(4) : "—"}</td>
                  <td>{xgb ? `${xgb.test_samples} test samples` : "—"}</td>
                </tr>
                <tr>
                  <td><strong>Student DNN</strong></td>
                  <td>Primary Fast Detector</td>
                  <td>{student ? `${(Number(student.accuracy) * 100).toFixed(2)}%` : "—"}</td>
                  <td>{student ? Number(student.mean_confidence).toFixed(4) : "—"}</td>
                  <td>{student ? `${Number(student.samples_handled)} handled (${Number(student.handling_percent).toFixed(1)}%)` : "—"}</td>
                </tr>
                <tr>
                  <td><strong>FT-Transformer</strong></td>
                  <td>Escalation Teacher</td>
                  <td>{teacher ? `${(Number(teacher.accuracy) * 100).toFixed(2)}%` : "—"}</td>
                  <td>{teacher ? Number(teacher.mean_confidence).toFixed(4) : "—"}</td>
                  <td>{teacher ? `${Number(teacher.samples_handled)} escalated (${Number(teacher.escalation_percent).toFixed(1)}%)` : "—"}</td>
                </tr>
                <tr>
                  <td><strong>Student + FT-Transformer</strong></td>
                  <td>Final Detection Cascade</td>
                  <td>{cascade ? `${Number(cascade.accuracy_percent).toFixed(2)}%` : "—"}</td>
                  <td>Attack success {cascade ? `${Number(cascade.attack_success_percent).toFixed(2)}%` : "—"}</td>
                  <td>{cascade ? `${Number(cascade.cascade_bypass_percent).toFixed(1)}% bypassed teacher` : "—"}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <section className="dashboard-grid" style={{ marginTop: "20px" }}>
          <div className="dashboard-panel">
            <div className="panel-heading">
              <div>
                <h2>Adaptive Limiter</h2>
                <p>Reputation-aware request control</p>
              </div>
              <span className="live-label">{limiter?.status || "ACTIVE"}</span>
            </div>

            <div className="risk-factors" style={{ padding: "20px" }}>
              <RiskBar label="Initial Rate" value={Math.min(Number(limiter?.initial_rate || 0) * 2, 100)} type="info" />
              <RiskBar label="Minimum Rate" value={Math.min(Number(limiter?.minimum_rate || 0) * 10, 100)} type="warning" />
              <RiskBar label="Reputation Ceiling" value={Number(limiter?.maximum_reputation || 0)} type="danger" />
            </div>
          </div>

          <div className="dashboard-panel">
            <div className="panel-heading">
              <div>
                <h2>Reputation Decay</h2>
                <p>Recovery after attack activity</p>
              </div>
              <span className="live-label">{decay?.status || "ACTIVE"}</span>
            </div>

            <div className="chart-box">
              <ResponsiveContainer width="100%" height={260}>
                <LineChart
                  data={[
                    { time: "Start", reputation: Number(decay?.initial_reputation || 0) },
                    { time: "1s", reputation: Number(decay?.after_1_second || 0) },
                    { time: "2s", reputation: Number(decay?.after_2_seconds || 0) },
                    { time: "3s", reputation: Number(decay?.after_3_seconds || 0) },
                    { time: "4s", reputation: Number(decay?.after_4_seconds || 0) },
                    { time: "5s", reputation: Number(decay?.after_5_seconds || 0) },
                  ]}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="time" stroke="#94a3b8" />
                  <YAxis domain={[0, 100]} stroke="#94a3b8" />
                  <Tooltip contentStyle={{ background: "#111827", border: "1px solid #334155" }} />
                  <Line type="monotone" dataKey="reputation" stroke="#3b82f6" strokeWidth={3} dot />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        </section>
      </>
    );
  };

  // ============================================================
  // RISK ANALYSIS
  // ============================================================

  const renderRiskAnalysis = () => (
    <>
      <div className="page-title">
        <div>
          <h1>Multi-Signal Dynamic Risk Engine</h1>
          <p>
            Real-time risk scoring across operational
            security tiers
          </p>
        </div>
      </div>

      <div className="risk-summary">
        <div>
          <span>Current Risk Score</span>
          <strong>
            {currentRisk.toFixed(3)} / 1.000
          </strong>
        </div>

        <div>
          <span>Current Risk Level</span>
          <strong className="risk-level">
            {riskLevel}
          </strong>
        </div>

        <div>
          <span>Max Risk Observed</span>
          <strong>
            {stats.maxRisk.toFixed(3)}
          </strong>
        </div>

        <div>
          <span>Average Risk</span>
          <strong>
            {stats.avgRisk.toFixed(3)}
          </strong>
        </div>
      </div>

      <section className="dashboard-grid">
        <div className="dashboard-panel">
          <div className="panel-heading">
            <div>
              <h2>Risk Factor Breakdown</h2>
              <p>
                Latest request risk contribution
              </p>
            </div>
          </div>

          <div className="risk-factors">
            <RiskBar
              label="ML Threat Score"
              value={Math.min(
                currentRisk * 100,
                100
              )}
              type="danger"
            />

            <RiskBar
              label="Frequency Score"
              value={Math.min(
                stats.total * 2,
                100
              )}
              type="warning"
            />

            <RiskBar
              label="Burst Score"
              value={
                currentRisk > 0.6
                  ? 80
                  : 0
              }
              type="warning"
            />

            <RiskBar
              label="Request Risk"
              value={Math.min(
                currentRisk * 100,
                100
              )}
              type="info"
            />
          </div>
        </div>

        <div className="dashboard-panel">
          <div className="panel-heading">
            <div>
              <h2>Risk Level Distribution</h2>
              <p>Historical security states</p>
            </div>
          </div>

          <div className="risk-levels">
            <div className="level normal">
              <span>NORMAL</span>
              <strong>
                {normalizedRequests.filter(
                  (r) => r.risk_score < 0.15
                ).length}
              </strong>
            </div>

            <div className="level watch">
              <span>WATCH</span>
              <strong>
                {normalizedRequests.filter(
                  (r) =>
                    r.risk_score >= 0.15 &&
                    r.risk_score < 0.3
                ).length}
              </strong>
            </div>

            <div className="level suspicious">
              <span>SUSPICIOUS</span>
              <strong>
                {normalizedRequests.filter(
                  (r) =>
                    r.risk_score >= 0.3 &&
                    r.risk_score < 0.6
                ).length}
              </strong>
            </div>

            <div className="level critical">
              <span>CRITICAL</span>
              <strong>
                {normalizedRequests.filter(
                  (r) => r.risk_score >= 0.6
                ).length}
              </strong>
            </div>
          </div>
        </div>
      </section>

      <RequestTable
        requests={recentRequests}
        formatTime={formatTime}
        getAttackClass={getAttackClass}
        getActionClass={getActionClass}
      />
    </>
  );

  // ============================================================
  // MITIGATION CENTER
  // ============================================================

  const renderMitigation = () => (
    <>
      <div className="page-title">
        <div>
          <h1>Mitigation Center</h1>
          <p>
            Autonomous security policy decisions
          </p>
        </div>
      </div>

      <div className="mitigation-grid">
        <div className="mitigation-card allow">
          <div className="mitigation-icon">
            ✓
          </div>

          <h2>ALLOW</h2>

          <strong>{stats.allowed}</strong>

          <p>
            Requests passed safely through the
            reverse proxy.
          </p>
        </div>

        <div className="mitigation-card rate">
          <div className="mitigation-icon">
            ⏱
          </div>

          <h2>RATE LIMIT</h2>

          <strong>
            {stats.rateLimited}
          </strong>

          <p>
            Excess traffic controlled by adaptive
            rate limiting.
          </p>
        </div>

        <div className="mitigation-card block">
          <div className="mitigation-icon">
            !
          </div>

          <h2>BLOCK</h2>

          <strong>{stats.blocked}</strong>

          <p>
            Malicious or high-risk requests
            rejected.
          </p>
        </div>
      </div>

      <section className="dashboard-panel">
        <div className="panel-heading">
          <div>
            <h2>Recent Mitigation Actions</h2>
            <p>
              Automatically generated policy
              decisions
            </p>
          </div>
        </div>

        <RequestTable
          requests={recentRequests}
          formatTime={formatTime}
          getAttackClass={getAttackClass}
          getActionClass={getActionClass}
        />
      </section>
    </>
  );

  // ============================================================
  // BACKEND HEALTH
  // ============================================================

  const renderBackendHealth = () => (
    <>
      <div className="page-title">
        <div>
          <h1>Backend Health</h1>
          <p>
            AegisProxy service and ML infrastructure
          </p>
        </div>
      </div>

      <div className="health-grid">
        <HealthCard
          title="Reverse Proxy"
          status={backendStatus}
          description="Request interception layer"
        />

        <HealthCard
          title="ML Detection"
          status={backendStatus}
          description="Student DNN + FT-Transformer cascade"
        />

        <HealthCard
          title="Risk Engine"
          status={backendStatus}
          description="Multi-evidence risk calculation"
        />

        <HealthCard
          title="Policy Engine"
          status={backendStatus}
          description="Allow / Rate Limit / Block"
        />
      </div>

      <section className="dashboard-panel system-panel">
        <div className="panel-heading">
          <div>
            <h2>System Information</h2>
            <p>
              Current AegisProxy runtime status
            </p>
          </div>
        </div>

        <div className="system-info">
          <div>
            <span>Application</span>
            <strong>AegisProxy</strong>
          </div>

          <div>
            <span>Production Model</span>
            <strong>Student DNN + FT-Transformer</strong>
          </div>

          <div>
            <span>Baseline Model</span>
            <strong>XGBoost</strong>
          </div>

          <div>
            <span>Frontend Status</span>
            <strong className="green-text">
              {backendStatus}
            </strong>
          </div>

          <div>
            <span>Requests Loaded</span>
            <strong>{stats.total}</strong>
          </div>

          <div>
            <span>Last Update</span>
            <strong>
              {lastUpdate
                ? lastUpdate.toLocaleTimeString()
                : "-"}
            </strong>
          </div>
        </div>
      </section>
    </>
  );

  // ============================================================
  // MAIN PAGE
  // ============================================================

  const renderPage = () => {
    switch (activePage) {
      case "Traffic Monitoring":
        return renderTraffic();

      case "Attack Detection":
        return renderAttackDetection();

      case "Model Evaluation":
        return renderModelEvaluation();

      case "Risk Analysis":
        return renderRiskAnalysis();

      case "Mitigation Center":
        return renderMitigation();

      case "Backend Health":
        return renderBackendHealth();

      default:
        return renderOverview();
    }
  };

  return (
    <div className="app-shell">

      {/* SIDEBAR */}

      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">
            🛡️
          </div>

          <div>
            <div className="brand-title">
              DDoS Shield
            </div>

            <div className="brand-subtitle">
              Intelligent Reverse Proxy
            </div>
          </div>
        </div>

        <nav className="sidebar-nav">
          {navigation.map((item) => (
            <button
              key={item.name}
              className={
                activePage === item.name
                  ? "nav-item active"
                  : "nav-item"
              }
              onClick={() =>
                setActivePage(item.name)
              }
            >
              <span className="nav-icon">
                {item.icon}
              </span>

              <span>{item.name}</span>
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="system-card">
            <div className="system-card-title">
              <span
                className={
                  backendStatus === "ONLINE"
                    ? "status-dot online"
                    : "status-dot offline"
                }
              />

              System{" "}
              {backendStatus === "ONLINE"
                ? "Online"
                : "Offline"}
            </div>

            <div className="system-row">
              <span>Proxy</span>
              <strong>ACTIVE</strong>
            </div>

            <div className="system-row">
              <span>Backend</span>
              <strong>
                {backendStatus}
              </strong>
            </div>
          </div>
        </div>
      </aside>

      {/* MAIN CONTENT */}

      <div className="main-area">
        <header className="topbar">
          <div className="mobile-brand">
            AEGIS<span>PROXY</span>
          </div>

          <div className="topbar-status">
            <span
              className={
                backendStatus === "ONLINE"
                  ? "status-dot online"
                  : "status-dot offline"
              }
            />

            <strong>
              {backendStatus}
            </strong>
          </div>
        </header>

        <main className="content">
          {renderPage()}
        </main>

        <footer className="footer">
          AegisProxy v1.0 •
          Risk-Aware Intelligent Reverse Proxy
          <span>
            {lastUpdate
              ? ` • Updated ${lastUpdate.toLocaleTimeString()}`
              : ""}
          </span>
        </footer>
      </div>
    </div>
  );
}

// ============================================================
// REQUEST TABLE
// ============================================================

function RequestTable({
  requests,
  formatTime,
  getAttackClass,
  getActionClass,
}) {
  return (
    <section className="dashboard-panel table-panel">
      <div className="panel-heading">
        <div>
          <h2>Live Request History</h2>

          <p>
            Automatically refreshed every 2
            seconds
          </p>
        </div>
      </div>

      <div className="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>TIME</th>
              <th>SOURCE IP</th>
              <th>ENDPOINT</th>
              <th>ATTACK TYPE</th>
              <th>RISK</th>
              <th>ACTION</th>
            </tr>
          </thead>

          <tbody>
            {requests.length === 0 ? (
              <tr>
                <td
                  colSpan="6"
                  className="empty"
                >
                  No requests recorded yet
                </td>
              </tr>
            ) : (
              requests.map((request, index) => (
                <tr key={index}>
                  <td>
                    {formatTime(
                      request.timestamp
                    )}
                  </td>

                  <td>
                    {request.ip}
                  </td>

                  <td>
                    {request.endpoint}
                  </td>

                  <td>
                    <span
                      className={`badge ${getAttackClass(
                        request.attack_type
                      )}`}
                    >
                      {request.attack_type}
                    </span>
                  </td>

                  <td>
                    <strong>
                      {request.risk_score.toFixed(
                        3
                      )}
                    </strong>
                  </td>

                  <td>
                    <span
                      className={`action-badge ${getActionClass(
                        request.action
                      )}`}
                    >
                      {request.action}
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

// ============================================================
// RISK BAR
// ============================================================

function RiskBar({
  label,
  value,
  type,
}) {
  return (
    <div className="risk-bar-row">
      <div className="risk-bar-label">
        <span>{label}</span>
        <strong>
          {value.toFixed(1)}
        </strong>
      </div>

      <div className="risk-bar-track">
        <div
          className={`risk-bar-fill ${type}`}
          style={{
            width: `${Math.min(
              value,
              100
            )}%`,
          }}
        />
      </div>
    </div>
  );
}

// ============================================================
// HEALTH CARD
// ============================================================

function HealthCard({
  title,
  status,
  description,
}) {
  return (
    <div className="health-card">
      <div className="health-header">
        <span className="health-icon">
          ✓
        </span>

        <span
          className={
            status === "ONLINE"
              ? "health-online"
              : "health-offline"
          }
        >
          {status}
        </span>
      </div>

      <h2>{title}</h2>

      <p>{description}</p>
    </div>
  );
}

export default App;