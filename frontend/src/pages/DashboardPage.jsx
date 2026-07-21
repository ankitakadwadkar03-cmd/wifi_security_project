import { useEffect, useState } from "react";
import StatusBadge from "../components/StatusBadge";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000";

export default function DashboardPage({ setCurrentPage }) {
  const [networks, setNetworks] = useState([]);
  const [threats, setThreats] = useState([]);
  const [latestHistory, setLatestHistory] = useState(null);
  const [backendStatus, setBackendStatus] = useState("Checking");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const controller = new AbortController();

    async function loadDashboard() {
      try {
        setLoading(true);
        setError("");

        const [
          healthResponse,
          networksResponse,
          threatsResponse,
          historyResponse,
        ] = await Promise.all([
          fetch(`${API_BASE_URL}/api/health`, {
            signal: controller.signal,
          }),
          fetch(`${API_BASE_URL}/api/networks`, {
            signal: controller.signal,
          }),
          fetch(`${API_BASE_URL}/api/threats`, {
            signal: controller.signal,
          }),
          fetch(`${API_BASE_URL}/api/history`, {
            signal: controller.signal,
          }),
        ]);

        if (
          !healthResponse.ok ||
          !networksResponse.ok ||
          !threatsResponse.ok ||
          !historyResponse.ok
        ) {
          throw new Error("One or more NetShield API routes returned an error.");
        }

        const healthData = await healthResponse.json();
        const networkData = await networksResponse.json();
        const threatData = await threatsResponse.json();
        const historyData = await historyResponse.json();

        setBackendStatus(
          healthData.status === "ok" ? "Active" : "Offline"
        );

        setNetworks(
          Array.isArray(networkData.networks)
            ? networkData.networks
            : []
        );

        setThreats(
          Array.isArray(threatData.threats)
            ? threatData.threats
            : []
        );

        setLatestHistory(historyData.latest || null);
      } catch (fetchError) {
        if (fetchError.name !== "AbortError") {
          console.error("Dashboard API error:", fetchError);
          setBackendStatus("Offline");
          setError(
            "Unable to load complete NetShield data. Check that the Flask backend is running and refresh this page."
          );
        }
      } finally {
        setLoading(false);
      }
    }

    loadDashboard();

    return () => controller.abort();
  }, []);

  const recentNetworks = networks.slice(0, 5);
  const latestThreat = threats[0];

  const securityScore = latestHistory
    ? `${Number(
        latestHistory.average_security_score
      ).toFixed(0)}%`
    : "—";

  return (
    <section className="appPage dashboardPage">
      <div className="pageHeader">
        <span>Monitoring Console</span>
        <h1>Dashboard</h1>
        <p>
          Overview of real wireless scan results, backend availability,
          potential security findings and saved analysis history.
        </p>
      </div>

      <div className="metricGrid">
        <div className="metricCard">
          <span>Backend Scanner</span>
          <strong>{backendStatus}</strong>
          <p>
            {backendStatus === "Active"
              ? "NetShield API is available"
              : "NetShield API is not available"}
          </p>
        </div>

        <div className="metricCard">
          <span>Networks Monitored</span>
          <strong>{loading ? "..." : networks.length}</strong>
          <p>Latest wireless scanner results</p>
        </div>

        <div className="metricCard danger">
          <span>Potential Findings</span>
          <strong>{loading ? "..." : threats.length}</strong>
          <p>
            {threats.length === 1
              ? "1 automated finding requires review"
              : `${threats.length} automated findings require review`}
          </p>
        </div>

        <div className="metricCard success">
          <span>Security Score</span>
          <strong>{loading ? "..." : securityScore}</strong>
          <p>Latest saved historical analysis score</p>
        </div>
      </div>

      {error && (
        <div className="networkTableMessage errorMessage">
          {error}
        </div>
      )}

      <div className="dashboardLayout">
        <div className="largePanel">
          <div className="panelTitle">
            <h2>Recent Wireless Findings</h2>

            <button
              type="button"
              onClick={() => setCurrentPage("networks")}
            >
              View Networks
            </button>
          </div>

          <div className="cleanTable">
            <div className="tableHead">
              <span>SSID</span>
              <span>Encryption</span>
              <span>Status</span>
              <span>Attack Type</span>
            </div>

            {loading && (
              <div className="networkTableMessage">
                Loading scanner results...
              </div>
            )}

            {!loading && !error && recentNetworks.length === 0 && (
              <div className="networkTableMessage">
                No scanned networks are available.
              </div>
            )}

            {!loading &&
              !error &&
              recentNetworks.map((row) => (
                <div
                  className="tableData"
                  key={`${row.bssid}-${row.channel}`}
                >
                  <span>{row.ssid}</span>
                  <span>{row.encryption}</span>
                  <span>
                    <StatusBadge value={row.status} />
                  </span>
                  <span>{row.attack}</span>
                </div>
              ))}
          </div>
        </div>

        <div className="sidePanel">
          <h2>Latest Finding</h2>

          {latestThreat ? (
            <>
              <StatusBadge value={latestThreat.severity} />

              <h3>{latestThreat.title}</h3>

              <p>
                BSSID: {latestThreat.bssid}. {latestThreat.summary}
              </p>

              <button
                type="button"
                onClick={() => setCurrentPage("threats")}
              >
                Review Findings
              </button>
            </>
          ) : (
            <>
              <StatusBadge value="Safe" />

              <h3>No potential findings</h3>

              <p>
                The latest security report contains no automated
                findings requiring review.
              </p>

              <button
                type="button"
                onClick={() => setCurrentPage("threats")}
              >
                Open Threat Center
              </button>
            </>
          )}
        </div>
      </div>
    </section>
  );
}
