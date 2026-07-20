import { useEffect, useState } from "react";
import StatusBadge from "../components/StatusBadge";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000";

export default function DashboardPage({ setCurrentPage }) {
  const [networks, setNetworks] = useState([]);
  const [backendStatus, setBackendStatus] = useState("Checking");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const controller = new AbortController();

    async function loadDashboard() {
      try {
        setLoading(true);
        setError("");

        const [healthResponse, networksResponse] = await Promise.all([
          fetch(`${API_BASE_URL}/api/health`, {
            signal: controller.signal,
          }),
          fetch(`${API_BASE_URL}/api/networks`, {
            signal: controller.signal,
          }),
        ]);

        if (!healthResponse.ok || !networksResponse.ok) {
          throw new Error("The NetShield backend returned an error.");
        }

        const healthData = await healthResponse.json();
        const networkData = await networksResponse.json();

        setBackendStatus(healthData.status === "ok" ? "Active" : "Offline");
        setNetworks(
          Array.isArray(networkData.networks) ? networkData.networks : []
        );
      } catch (fetchError) {
        if (fetchError.name !== "AbortError") {
          console.error("Dashboard API error:", fetchError);
          setBackendStatus("Offline");
          setError(
            "Unable to connect to the NetShield backend. Start the Flask API and refresh this page."
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

  return (
    <section className="appPage dashboardPage">
      <div className="pageHeader">
        <span>Monitoring Console</span>
        <h1>Dashboard</h1>
        <p>
          Overview of real wireless scan results, backend availability and
          security-analysis status.
        </p>
      </div>

      <div className="metricGrid">
        <div className="metricCard">
          <span>Backend Scanner</span>
          <strong>{backendStatus}</strong>
          <p>
            {backendStatus === "Active"
              ? "Scanner API is available"
              : "Scanner API is not available"}
          </p>
        </div>

        <div className="metricCard">
          <span>Networks Monitored</span>
          <strong>{loading ? "..." : networks.length}</strong>
          <p>Latest wireless scanner results</p>
        </div>

        <div className="metricCard danger">
          <span>Threats Found</span>
          <strong>—</strong>
          <p>Threat-detection module not connected yet</p>
        </div>

        <div className="metricCard success">
          <span>Security Score</span>
          <strong>—</strong>
          <p>Available after real threat analysis</p>
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
          <h2>Latest Alert</h2>
          <StatusBadge value="Unclassified" />
          <h3>Threat analysis pending</h3>
          <p>
            Wireless networks have been discovered successfully. Connect the
            threat-detection modules before classifying access points or
            generating security alerts.
          </p>
          <button
            type="button"
            onClick={() => setCurrentPage("threats")}
          >
            Open Threat Center
          </button>
        </div>
      </div>
    </section>
  );
}
