import { useEffect, useState } from "react";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000";

function formatTimestamp(value) {
  if (!value) {
    return "Unknown time";
  }

  const parsedDate = new Date(value.replace(" ", "T"));

  if (Number.isNaN(parsedDate.getTime())) {
    return value;
  }

  return parsedDate.toLocaleString();
}

function formatTrend(value, suffix = "") {
  if (value === null || value === undefined) {
    return "No previous scan";
  }

  if (value === 0) {
    return `No change${suffix}`;
  }

  const sign = value > 0 ? "+" : "";
  return `${sign}${value}${suffix} from previous scan`;
}

export default function HistoryPage() {
  const [history, setHistory] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const controller = new AbortController();

    async function loadHistory() {
      try {
        setLoading(true);
        setError("");

        const response = await fetch(`${API_BASE_URL}/api/history`, {
          signal: controller.signal,
        });

        if (!response.ok) {
          throw new Error(`Backend returned HTTP ${response.status}`);
        }

        const data = await response.json();
        setHistory(data);
      } catch (fetchError) {
        if (fetchError.name !== "AbortError") {
          console.error("Failed to load history:", fetchError);
          setError(
            "Unable to connect to the History API. Start the Flask backend and refresh this page."
          );
        }
      } finally {
        setLoading(false);
      }
    }

    loadHistory();

    return () => controller.abort();
  }, []);

  const latest = history?.latest;
  const summaries = Array.isArray(history?.summaries)
    ? history.summaries
    : [];
  const trends = history?.trends || {};

  return (
    <section className="appPage historyPage">
      <div className="pageHeader">
        <span>Historical Analysis</span>
        <h1>History</h1>
        <p>
          Compare saved WiFi scans, monitor security trends, and understand
          how the wireless environment changed between analyses.
        </p>
      </div>

      {loading && (
        <div className="networkTableMessage">
          Loading saved scan history...
        </div>
      )}

      {!loading && error && (
        <div className="networkTableMessage errorMessage">
          {error}
        </div>
      )}

      {!loading && !error && !latest && (
        <div className="networkTableMessage">
          No historical scans are currently stored.
        </div>
      )}

      {!loading && !error && latest && (
        <>
          <div className="historyGrid">
            <div className="historyCard">
              <div className="historyValue">
                {history.scan_count}
              </div>
              <h2>Saved Scans</h2>
              <p>Completed scan summaries stored in the history database.</p>
            </div>

            <div className="historyCard">
              <div className="historyValue">
                {latest.total_networks}
              </div>
              <h2>Latest Networks</h2>
              <p>{formatTrend(trends.network_change)}</p>
            </div>

            <div className="historyCard">
              <div className="historyValue">
                {Number(latest.average_security_score).toFixed(0)}%
              </div>
              <h2>Average Score</h2>
              <p>{formatTrend(trends.score_change, " points")}</p>
            </div>

            <div className="historyCard">
              <div className="historyValue">
                {latest.potential_findings}
              </div>
              <h2>Potential Findings</h2>
              <p>{formatTrend(trends.finding_change)}</p>
            </div>
          </div>

          <div className="timelinePanel">
            <h2>Saved Scan Timeline</h2>

            {summaries.map((scan, index) => (
              <div
                className="timelineItem"
                key={scan.scan_timestamp}
              >
                <span className="timelineDot"></span>

                <div>
                  <strong>
                    {index === 0
                      ? "Latest Saved Scan"
                      : `Previous Scan ${index}`}
                  </strong>

                  <p className="timelineDate">
                    {formatTimestamp(scan.scan_timestamp)}
                  </p>

                  <p>
                    {scan.total_networks} networks,{" "}
                    {scan.potential_findings} potential findings,{" "}
                    {Number(scan.average_security_score).toFixed(0)}%
                    average security score.
                  </p>

                  <div className="historyScanDetails">
                    <span>Safe: {scan.safe_count}</span>
                    <span>Rogue candidates: {scan.rogue_count}</span>
                    <span>Evil-twin candidates: {scan.evil_twin_count}</span>
                    <span>Warnings: {scan.warning_count}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </section>
  );
}
