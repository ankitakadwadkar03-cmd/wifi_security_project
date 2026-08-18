import { useEffect, useState } from "react";
import StatusBadge from "../components/StatusBadge";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000";

function formatAttackType(value) {
  return String(value || "Unknown")
    .replaceAll("_", " ")
    .toLowerCase()
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export default function ThreatCenterPage() {
  const [threats, setThreats] = useState([]);
  const [alertHistory, setAlertHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [analysisLoading, setAnalysisLoading] = useState(false);
  const [analysisMessage, setAnalysisMessage] = useState("");
  const [analysisError, setAnalysisError] = useState("");

  async function runThreatAnalysis() {
    try {
      setAnalysisLoading(true);
      setAnalysisMessage("");
      setAnalysisError("");

      const response = await fetch(
        `${API_BASE_URL}/api/threats/analyze`,
        {
          method: "POST",
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.message ||
            `Threat analysis returned HTTP ${response.status}`
        );
      }

      setAnalysisMessage(
        `${data.message} ${data.network_count ?? 0} network(s) analyzed, ` +
          `${data.session_packet_count ?? 0} latest-session packet(s), ` +
          `${data.finding_count ?? 0} finding(s).`
      );

      const threatsResponse = await fetch(
        `${API_BASE_URL}/api/threats`
      );

      if (!threatsResponse.ok) {
        throw new Error(
          `Threat refresh returned HTTP ${threatsResponse.status}`
        );
      }

      const threatsData = await threatsResponse.json();

      setThreats(
        Array.isArray(threatsData.threats)
          ? threatsData.threats
          : []
      );
    } catch (analysisRequestError) {
      console.error(
        "Threat analysis failed:",
        analysisRequestError
      );

      setAnalysisError(
        analysisRequestError.message ||
          "Threat analysis could not be completed."
      );
    } finally {
      setAnalysisLoading(false);
    }
  }

  useEffect(() => {
    const controller = new AbortController();

    async function loadThreats(showLoading = false) {
      try {
        if (showLoading) {
          setLoading(true);
        }

        setError("");

        const response = await fetch(`${API_BASE_URL}/api/threats`, {
          signal: controller.signal,
        });

        if (!response.ok) {
          throw new Error(`Backend returned HTTP ${response.status}`);
        }

        const data = await response.json();
        setThreats(Array.isArray(data.threats) ? data.threats : []);
      } catch (fetchError) {
        if (fetchError.name !== "AbortError") {
          console.error("Failed to load threats:", fetchError);
          setError(
            "Unable to connect to the threat-analysis API. Start the Flask backend and refresh this page."
          );
        }
      } finally {
        if (showLoading) {
          setLoading(false);
        }
      }
    }

    async function loadAlertHistory(showLoading = false) {
      try {
        if (showLoading) {
          setHistoryLoading(true);
        }

        const response = await fetch(
          `${API_BASE_URL}/api/alerts/history?limit=20`,
          {
            signal: controller.signal,
          }
        );

        if (!response.ok) {
          throw new Error(
            `Alert history endpoint returned HTTP ${response.status}`
          );
        }

        const data = await response.json();

        setAlertHistory(
          Array.isArray(data.alerts)
            ? data.alerts
            : []
        );
      } catch (fetchError) {
        if (fetchError.name !== "AbortError") {
          console.error(
            "Failed to load alert history:",
            fetchError
          );
        }
      } finally {
        if (showLoading) {
          setHistoryLoading(false);
        }
      }
    }

    loadThreats(true);
    loadAlertHistory(true);

    const pollingTimer = window.setInterval(() => {
      loadThreats(false);
      loadAlertHistory(false);
    }, 2000);

    return () => {
      controller.abort();
      window.clearInterval(pollingTimer);
    };
  }, []);

  return (
    <section className="appPage threatCenterPage">
      <div className="pageHeader">
        <span>Security Monitoring</span>
        <h1>Threat Center</h1>
        <p>
          Review potential wireless-security findings produced by NetShield.
          Automated detections should be verified before taking action.
        </p>
      </div>

      <div className="threatAnalysisActions">
        <button
          type="button"
          onClick={runThreatAnalysis}
          disabled={analysisLoading}
        >
          {analysisLoading
            ? "Analyzing..."
            : "Run Threat Analysis"}
        </button>

        <p>
          Uses the latest WiFi scan and latest completed packet-capture
          session to generate fresh threat classifications.
        </p>
      </div>

      {analysisMessage && (
        <p className="scannerActionMessage">
          {analysisMessage}
        </p>
      )}

      {analysisError && (
        <p className="scannerActionMessage errorMessage">
          {analysisError}
        </p>
      )}

      {loading && (
        <div className="networkTableMessage">
          Loading security findings...
        </div>
      )}

      {!loading && error && (
        <div className="networkTableMessage errorMessage">
          {error}
        </div>
      )}

      {!loading && !error && threats.length === 0 && (
        <div className="networkTableMessage">
          No suspicious wireless findings are currently available.
        </div>
      )}

      {!loading && !error && threats.length > 0 && (
        <>
          <div className="threatSummaryBar">
            <div>
              <span>Findings requiring review</span>
              <strong>{threats.length}</strong>
            </div>

            <p>
              These are potential findings from automated analysis, not
              confirmed attacks.
            </p>
          </div>

          <div className="threatGrid">
            {threats.map((item) => (
              <div
                className="threatCard"
                key={`${item.bssid}-${item.attack_type}`}
              >
                <div className="threatTop">
                  <StatusBadge value={item.severity} />
                </div>

                <h2>{item.title}</h2>
                <p>{item.summary}</p>

                <div className="threatDetails">
                  <div>
                    <span>SSID</span>
                    <strong>
                      {item.ssid === "Unknown_Device"
                        ? "Unknown network"
                        : item.ssid}
                    </strong>
                  </div>

                  <div>
                    <span>BSSID</span>
                    <strong>{item.bssid}</strong>
                  </div>

                  <div>
                    <span>Classification</span>
                    <strong>{formatAttackType(item.attack_type)}</strong>
                  </div>

                  <div>
                    <span>Encryption</span>
                    <strong>{item.encryption}</strong>
                  </div>

                  <div>
                    <span>Packets Observed</span>
                    <strong>{item.total_packets}</strong>
                  </div>

                  <div>
                    <span>Risk Level</span>
                    <strong>{item.risk_level}</strong>
                  </div>
                </div>
              </div>
            ))}
          </div>

          <div className="sharedVerification">
            <div>
              <span>Verification checklist</span>
              <h2>Before treating a finding as a real threat</h2>
            </div>

            <ul>
              <li>Compare the BSSID with the trusted router record.</li>
              <li>Repeat the scan to confirm the access point persists.</li>
              <li>Verify the network owner before connecting.</li>
              <li>Review packet evidence and encryption information.</li>
            </ul>
          </div>
        </>
      )}

      <div className="alertHistorySection">
        <div className="threatSummaryBar">
          <div>
            <span>Recent Alert Evidence</span>
            <strong>{alertHistory.length}</strong>
          </div>

          <p>
            Saved live packet alerts remain available for later review even
            after the activity is no longer currently detected.
          </p>
        </div>

        {alertHistory.length > 0 && (
          <div className="alertEvidenceActions">
            <a
              href={`${API_BASE_URL}/api/reports/download/live_packet_alert_history.json`}
              download
            >
              Export JSON
            </a>

            <a
              href={`${API_BASE_URL}/api/reports/download/live_packet_alert_history.log`}
              download
            >
              Export Log
            </a>
          </div>
        )}

        {historyLoading && (
          <div className="networkTableMessage">
            Loading alert evidence...
          </div>
        )}

        {!historyLoading && alertHistory.length === 0 && (
          <div className="networkTableMessage">
            No live packet alert evidence has been recorded yet.
          </div>
        )}

        {!historyLoading && alertHistory.length > 0 && (
          <div className="threatGrid">
            {alertHistory.map((item) => (
              <div
                className="threatCard"
                key={`${item.recorded_at}-${item.alert_type}-${item.bssid}`}
              >
                <div className="threatTop">
                  <StatusBadge value={item.severity} />
                </div>

                <h2>{item.title}</h2>
                <p>{item.summary}</p>

                <div className="threatDetails">
                  <div>
                    <span>Recorded At</span>
                    <strong>{item.recorded_at || "Unknown"}</strong>
                  </div>

                  <div>
                    <span>Last Seen</span>
                    <strong>{item.last_seen || "Unknown"}</strong>
                  </div>

                  <div>
                    <span>Source / BSSID</span>
                    <strong>{item.bssid || "Unknown"}</strong>
                  </div>

                  <div>
                    <span>Classification</span>
                    <strong>
                      {formatAttackType(item.alert_type)}
                    </strong>
                  </div>

                  <div>
                    <span>Packets Observed</span>
                    <strong>{item.total_packets ?? 0}</strong>
                  </div>

                  <div>
                    <span>Evidence Time</span>
                    <strong>
                      {item.evidence_timestamp || "Unknown"}
                    </strong>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="securityTips">
        <h2>Best Practices</h2>

        <div className="tipsGrid">
          <div className="tipCard">
            <h3>Use WPA3</h3>
            <p>
              Prefer WPA3 or WPA2 encrypted networks instead of open hotspots.
            </p>
          </div>

          <div className="tipCard">
            <h3>Disable Auto Connect</h3>
            <p>
              Prevent your device from automatically joining unknown networks.
            </p>
          </div>

          <div className="tipCard">
            <h3>Verify Network Identity</h3>
            <p>
              Compare the SSID and BSSID with information provided by the
              network owner.
            </p>
          </div>

          <div className="tipCard">
            <h3>Update Router</h3>
            <p>
              Keep router firmware updated to protect against known
              vulnerabilities.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}
