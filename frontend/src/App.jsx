import { useState } from "react";

import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Handle,
  Position,
} from "@xyflow/react";

import "@xyflow/react/dist/style.css";
import "./App.css";

import LocationMap from "./LocationMap";
import useTheme, { THEME_OPTIONS } from "./theme";
import formatLocation, { formatCoordinates } from "./formatLocation";

const API_BASE = import.meta.env.VITE_API_URL || "http://127.0.0.1:8001";
const API_URL = `${API_BASE}/analyze`;

const SENDER_STATUS_LABELS = {
  TRUSTED: "✓ Trusted sender",
  AUTHENTICATED: "✓ Authenticated sender",
  NOT_VERIFIED: "✗ Sender not verified",
};
const REPORT_URL = `${API_BASE}/report`;


/* ============================================================
   FORENSIC NODE
   ============================================================ */

function ForensicNode({ data }) {
  const nodeType = data.nodeType || "UNKNOWN";
  const classification = data.properties?.classification || "";

  return (
    <div className={`forensic-node node-${nodeType.toLowerCase()}`}>

      <Handle
        type="target"
        position={Position.Left}
        className="node-handle"
      />

      <div className="forensic-node-header">
        <span className="forensic-node-icon">
          {data.icon}
        </span>

        <span className="forensic-node-type">
          {nodeType}
        </span>
      </div>

      <div className="forensic-node-label">
        {data.shortLabel}
      </div>

      {classification && (
        <div className="forensic-node-classification">
          {classification}
        </div>
      )}

      <Handle
        type="source"
        position={Position.Right}
        className="node-handle"
      />

    </div>
  );
}


/* ============================================================
   NODE TYPE
   ============================================================ */

const nodeTypes = {
  forensic: ForensicNode,
};


/* ============================================================
   ICONS
   ============================================================ */

function getNodeIcon(type) {
  const icons = {
    EMAIL: "✉",
    SENDER: "👤",
    URL: "🔗",
    DOMAIN: "🌐",
    RELAY_HOST: "🖥",
    IP: "◉",
    COUNTRY: "◎",
    ASN: "◇",
  };

  return icons[type] || "●";
}


/* ============================================================
   SHORT LABEL
   ============================================================ */

function createShortLabel(node) {
  const label = node.label || "Unknown";

  const limits = {
    EMAIL: 35,
    SENDER: 28,
    URL: 28,
    DOMAIN: 26,
    RELAY_HOST: 26,
    IP: 24,
    COUNTRY: 24,
    ASN: 24,
  };

  const limit = limits[node.type] || 28;

  if (label.length > limit) {
    return `${label.substring(0, limit)}...`;
  }

  return label;
}


/* ============================================================
   SAFE GRAPH LAYOUT
   ============================================================ */

function getPosition(node, index) {

  const gap = 125;

  switch (node.type) {

    case "EMAIL":
      return {
        x: 50,
        y: 350,
      };

    case "SENDER":
      return {
        x: 360,
        y: 50,
      };

    case "URL":
      return {
        x: 360,
        y: 150 + index * gap,
      };

    case "RELAY_HOST":
      return {
        x: 360,
        y: 650 + index * gap,
      };

    case "DOMAIN":
      return {
        x: 720,
        y: 80 + index * gap,
      };

    case "IP":
      return {
        x: 720,
        y: 650 + index * gap,
      };

    case "COUNTRY":
      return {
        x: 1060,
        y: 600 + index * gap,
      };

    case "ASN":
      return {
        x: 1060,
        y: 850 + index * gap,
      };

    default:
      return {
        x: 50,
        y: index * gap,
      };
  }
}


/* ============================================================
   BACKEND GRAPH → REACT FLOW
   ============================================================ */

function convertGraphToReactFlow(graph) {

  if (!graph) {
    return {
      nodes: [],
      edges: [],
    };
  }

  const backendNodes = graph.nodes || [];
  const backendEdges = graph.edges || [];

  const counters = {};

  const nodes = backendNodes.map((node) => {

    const type = node.type || "UNKNOWN";

    if (counters[type] === undefined) {
      counters[type] = 0;
    }

    const index = counters[type];

    counters[type] += 1;

    return {
      id: node.id,

      type: "forensic",

      position: getPosition(node, index),

      data: {
        nodeType: type,

        icon: getNodeIcon(type),

        shortLabel: createShortLabel(node),

        fullLabel: node.label || "Unknown",

        properties: node.properties || {},
      },

      draggable: true,
    };
  });


  const edges = backendEdges.map((edge, index) => {

    const warning =
      edge.properties?.header_warning;

    return {
      id: `edge-${index}`,

      source: edge.source,

      target: edge.target,

      label: edge.relationship,

      animated:
        edge.relationship === "OBSERVED_AT",

      style: {
        strokeWidth: 1.5,
      },

      labelStyle: {
        fontSize: 8,
        fontWeight: 700,
      },

      labelBgStyle: {
        fill: "var(--graph-label-bg)",
        fillOpacity: 0.95,
      },

      className:
        warning ? "warning-edge" : "",

      data: {
        relationship: edge.relationship,
        properties: edge.properties || {},
      },
    };
  });


  return {
    nodes,
    edges,
  };
}


/* ============================================================
   FORMAT PROPERTY
   ============================================================ */

function formatPropertyValue(value) {

  if (
    value === null ||
    value === undefined
  ) {
    return "N/A";
  }

  if (typeof value === "object") {
    return JSON.stringify(
      value,
      null,
      2
    );
  }

  return String(value);
}


/* ============================================================
   NODE DETAILS
   ============================================================ */

function NodeDetails({
  node,
  onClose,
}) {

  if (!node) {

    return (
      <div className="node-details empty-details">

        <div className="details-empty-icon">
          ◈
        </div>

        <h3>
          Select Evidence
        </h3>

        <p>
          Click a node in the investigation
          graph to inspect its data.
        </p>

      </div>
    );
  }


  const properties =
    node.data?.properties || {};


  return (
    <div className="node-details">

      <div className="details-header">

        <div>

          <div className="details-type">
            {node.data?.icon}{" "}
            {node.data?.nodeType}
          </div>

          <h3>
            {node.data?.fullLabel}
          </h3>

        </div>

        <button
          className="details-close"
          onClick={onClose}
        >
          ×
        </button>

      </div>


      <div className="details-divider" />


      <div className="details-section">

        <span className="details-section-title">
          NODE ID
        </span>

        <div className="details-value mono">
          {node.id}
        </div>

      </div>


      {Object.keys(properties).length > 0 && (

        <div className="details-section">

          <span className="details-section-title">
            PROPERTIES
          </span>

          <div className="details-properties">

            {Object.entries(properties).map(
              ([key, value]) => (

                <div
                  className="property-row"
                  key={key}
                >

                  <span className="property-key">
                    {key}
                  </span>

                  <span className="property-value">
                    {formatPropertyValue(value)}
                  </span>

                </div>

              )
            )}

          </div>

        </div>

      )}

    </div>
  );
}


/* ============================================================
   THEME SWITCHER
   ============================================================ */

const THEME_LABELS = {
  system: "Auto",
  light: "Light",
  dark: "Dark",
};

function ThemeSwitcher({ preference, onChange }) {
  return (
    <div
      className="theme-switcher"
      role="radiogroup"
      aria-label="Color theme"
    >
      {THEME_OPTIONS.map((option) => (
        <button
          key={option}
          type="button"
          role="radio"
          aria-checked={preference === option}
          className={preference === option ? "active" : ""}
          onClick={() => onChange(option)}
        >
          {THEME_LABELS[option]}
        </button>
      ))}
    </div>
  );
}


/* ============================================================
   MAIN APP
   ============================================================ */

function App() {

  const theme = useTheme();

  const [file, setFile] =
    useState(null);

  const [result, setResult] =
    useState(null);

  const [loading, setLoading] =
    useState(false);

  const [error, setError] =
    useState("");

  const [selectedNode, setSelectedNode] =
    useState(null);


  /* ==========================================================
     ANALYZE
     ========================================================== */

  async function analyzeEmail() {

    if (!file) {

      setError(
        "Please select an .eml file first."
      );

      return;
    }

    setLoading(true);

    setError("");

    setResult(null);

    setSelectedNode(null);


    const formData =
      new FormData();

    formData.append(
      "file",
      file
    );


    try {

      const response =
        await fetch(
          API_URL,
          {
            method: "POST",
            body: formData,
          }
        );


      const data =
        await response.json();


      if (!response.ok) {

        throw new Error(
          data.detail ||
          "Analysis failed."
        );
      }


      setResult(data);

    } catch (err) {

      setError(
        err.message ||
        "Something went wrong."
      );

    } finally {

      setLoading(false);

    }
  }


  /* ==========================================================
     OPEN FORENSIC REPORT
     ========================================================== */

  function openForensicReport() {

    window.open(
      REPORT_URL,
      "_blank",
      "noopener,noreferrer"
    );
  }


  /* ==========================================================
     DATA
     ========================================================== */

  const risk =
    result?.risk_assessment?.risk;

  const ml =
    result?.risk_assessment?.ml_detection;

  const sender =
    result?.risk_assessment?.sender_verification;

  const email =
    result?.parsed_email;

  const geolocation =
    result?.geolocation || [];

  const relayPath =
    result
      ?.security_analysis
      ?.routing
      ?.relay_path || [];

  const signals =
    result
      ?.security_analysis
      ?.security_signals
      ?.signals || [];

  const graph =
    result?.investigation_graph;

  const reactFlowGraph =
    convertGraphToReactFlow(
      graph
    );


  /* ==========================================================
     UI
     ========================================================== */

  return (
    <div className="app">

      <header className="header">

        <div>

          <h1>
            MailTraceAI
          </h1>

          <p>
            AI-Powered Email Threat Detection
            & Forensic Intelligence
          </p>

        </div>

        <div className="header-actions">

          <ThemeSwitcher
            preference={theme.preference}
            onChange={theme.setPreference}
          />

          <div className="status">
            <span></span>
            SYSTEM ONLINE
          </div>

        </div>

      </header>


      <main className="container">

        {/* ==================================================
            UPLOAD
            ================================================== */}

        <section className="upload-card">

          <div className="upload-icon">
            ✉
          </div>

          <h2>
            Analyze Suspicious Email
          </h2>

          <p>
            Upload an <strong>.eml</strong> file
            to perform threat detection,
            security analysis, geolocation
            and forensic investigation.
          </p>

          <label className="file-input">

            <input
              type="file"
              accept=".eml"
              onChange={(e) => {

                setFile(
                  e.target.files[0]
                );

                setError("");

                setResult(null);

                setSelectedNode(null);

              }}
            />

            <span>
              {file
                ? file.name
                : "Choose .eml file"}
            </span>

          </label>


          <button
            className="analyze-button"
            onClick={analyzeEmail}
            disabled={loading}
          >

            {loading
              ? "ANALYZING..."
              : "ANALYZE EMAIL"}

          </button>


          {error && (
            <div className="error">
              {error}
            </div>
          )}

        </section>


        {result && (
          <>

            {/* ==================================================
                METRICS
                ================================================== */}

            <section className="dashboard-grid">

              <div className="metric-card">
                <span>RISK SCORE</span>
                <strong>
                  {risk?.score ?? "--"}/100
                </strong>
              </div>

              <div className="metric-card">
                <span>VERDICT</span>
                <strong>
                  {risk?.verdict ?? "--"}
                </strong>
              </div>

              <div className="metric-card">
                <span>AI PREDICTION</span>
                <strong>
                  {ml?.prediction ?? "--"}
                </strong>
              </div>

              <div className="metric-card">
                <span>PHISHING PROBABILITY</span>
                <strong>
                  {ml?.phishing_probability !== undefined
                    ? `${(
                        ml.phishing_probability * 100
                      ).toFixed(2)}%`
                    : "--"}
                </strong>
              </div>

            </section>


            {/* ==================================================
                SENDER VERIFICATION
                ================================================== */}

            {sender && (
              <section
                className={`sender-status sender-${sender.status.toLowerCase()}`}
              >
                <strong>
                  {SENDER_STATUS_LABELS[sender.status] ?? sender.status}
                  {sender.domain && (
                    <code>{sender.domain}</code>
                  )}
                  {sender.method && (
                    <span className="sender-method">
                      via {sender.method}
                    </span>
                  )}
                </strong>
                <p>{sender.reason}</p>
              </section>
            )}


            {/* ==================================================
                FORENSIC REPORT
                ================================================== */}

            <section className="panel report-panel">

              <div className="report-section-content">

                <div>
                  <h2>
                    Forensic Report
                  </h2>

                  <p className="muted">
                    Open the generated forensic
                    investigation report containing
                    the analyzed evidence, security
                    findings, infrastructure intelligence,
                    risk assessment and evidence integrity.
                  </p>
                </div>

                <button
                  className="report-button"
                  onClick={openForensicReport}
                >
                  📄 VIEW FORENSIC REPORT
                </button>

              </div>

            </section>


            {/* ==================================================
                EMAIL
                ================================================== */}

            <section className="panel">

              <h2>
                Email Information
              </h2>

              <div className="info-grid">

                <div>
                  <label>FROM</label>
                  <p>
                    {email?.from || "N/A"}
                  </p>
                </div>

                <div>
                  <label>TO</label>
                  <p>
                    {email?.to || "N/A"}
                  </p>
                </div>

                <div className="full">
                  <label>SUBJECT</label>
                  <p>
                    {email?.subject || "N/A"}
                  </p>
                </div>

              </div>

            </section>


            {/* ==================================================
                SECURITY
                ================================================== */}

            <section className="panel">

              <h2>
                Security Findings
              </h2>

              {signals.length === 0 ? (

                <p className="muted">
                  No security signals detected.
                </p>

              ) : (

                <div className="findings">

                  {signals.map(
                    (signal, index) => (

                      <div
                        className="finding"
                        key={index}
                      >

                        <div>

                          <strong>
                            {signal.type}
                          </strong>

                          <p>
                            {signal.description}
                          </p>

                        </div>

                        <span>
                          {signal.severity}
                        </span>

                      </div>

                    )
                  )}

                </div>

              )}

            </section>


            {/* ==================================================
                INFRASTRUCTURE
                ================================================== */}

            <section className="panel">

              <h2>
                Infrastructure Intelligence
              </h2>

              {geolocation.length === 0 ? (

                <p className="muted">
                  No public infrastructure IPs found.
                </p>

              ) : (

                <>

                <LocationMap
                  theme={theme.resolved}
                  geolocation={geolocation}
                  relayPath={relayPath}
                  senderIpSource={
                    result
                      ?.security_analysis
                      ?.routing
                      ?.sender_ip_source
                  }
                  senderUtcOffset={
                    result
                      ?.security_analysis
                      ?.identity
                      ?.date_utc_offset
                  }
                />

                <div className="table-wrapper">

                  <table>

                    <thead>

                      <tr>
                        <th>IP ADDRESS</th>
                        <th>LOCATION</th>
                        <th>COORDINATES</th>
                        <th>ASN</th>
                        <th>NETWORK</th>
                      </tr>

                    </thead>

                    <tbody>

                      {geolocation.map(
                        (item) => (

                          <tr key={item.ip}>

                            <td>
                              {item.ip}
                            </td>

                            <td>
                              {formatLocation(item)}
                            </td>

                            <td className="coordinates-cell">
                              {formatCoordinates(
                                item.latitude,
                                item.longitude
                              )}
                            </td>

                            <td>
                              {item.asn || "N/A"}
                            </td>

                            <td>
                              {item.asn_name || "N/A"}
                            </td>

                          </tr>

                        )
                      )}

                    </tbody>

                  </table>

                </div>

                </>

              )}

            </section>


          </>
        )}

      </main>

    </div>
  );
}


export default App;