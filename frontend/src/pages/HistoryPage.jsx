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

  const [archiveLoading, setArchiveLoading] = useState(false);
  const [archiveMessage, setArchiveMessage] = useState("");
  const [archiveError, setArchiveError] = useState("");

  async function loadHistory(signal) {
    try {
      setLoading(true);
      setError("");

      const response = await fetch(
        `${API_BASE_URL}/api/history`,
        signal ? { signal } : undefined
      );

      if (!response.ok) {
        throw new Error(
          `Backend returned HTTP ${response.status}`
        );
      }

      const data = await response.json();

      setHistory(data);
    } catch (fetchError) {
      if (fetchError.name !== "AbortError") {
        console.error(
          "Failed to load history:",
          fetchError
        );

        setError(
          "Unable to connect to the History API. " +
            "Start the Flask backend and refresh this page."
        );
      }
    } finally {
      if (!signal?.aborted) {
        setLoading(false);
      }
    }
  }

  useEffect(() => {
    const controller = new AbortController();

    loadHistory(controller.signal);

    return () => controller.abort();
  }, []);

  async function archiveLegacyHistory() {
    if (
      archiveLoading ||
      !history?.archive_legacy_url
    ) {
      return;
    }

    try {
      setArchiveLoading(true);
      setArchiveMessage("");
      setArchiveError("");

      const response = await fetch(
        `${API_BASE_URL}${history.archive_legacy_url}`,
        {
          method: "POST",
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.message ||
            `Legacy history archive returned HTTP ${response.status}`
        );
      }

      setArchiveMessage(
        `${data.message} Archived: ${
          Array.isArray(data.archived_files)
            ? data.archived_files.join(", ")
            : "legacy history files"
        }.`
      );

      await loadHistory();
    } catch (archiveRequestError) {
      console.error(
        "Legacy history archive failed:",
        archiveRequestError
      );

      setArchiveError(
        archiveRequestError.message ||
          "Legacy history could not be archived."
      );

      await loadHistory();
    } finally {
      setArchiveLoading(false);
    }
  }

  const latest = history?.latest;

  const summaries = Array.isArray(
    history?.summaries
  )
    ? history.summaries
    : [];

  const trends = history?.trends || {};

  const legacyHistory =
    history?.history_status === "legacy" &&
    history?.migration_required;

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

      {!loading && !error && legacyHistory && (
        <div className="networkTableMessage">
          <strong>Legacy history detected.</strong>

          <br />

          {history.message ||
            "Older history was created before the current baseline-aware threat-detection logic."}

          <br />
          <br />

          The old history will be preserved in an archive. It will not be
          mixed with the new baseline-aware NetShield timeline.

          <br />
          <br />

          <button
            type="button"
            className="primaryButton"
            onClick={archiveLegacyHistory}
            disabled={archiveLoading}
          >
            {archiveLoading
              ? "Archiving..."
              : "Archive Legacy History"}
          </button>
        </div>
      )}

      {archiveMessage && (
        <p className="scannerActionMessage">
          {archiveMessage}
        </p>
      )}

      {archiveError && (
        <p className="scannerActionMessage errorMessage">
          {archiveError}
        </p>
      )}

      {!loading &&
        !error &&
        !legacyHistory &&
        !latest && (
          <div className="networkTableMessage">
            {history?.message ||
              "No historical scans are currently stored."}
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

              <p>
                Completed scan summaries stored in the history database.
              </p>
            </div>

            <div className="historyCard">
              <div className="historyValue">
                {latest.total_networks}
              </div>

              <h2>Latest Networks</h2>

              <p>
                {formatTrend(
                  trends.network_change
                )}
              </p>
            </div>

            <div className="historyCard">
              <div className="historyValue">
                {Number(
                  latest.average_security_score
                ).toFixed(0)}
                %
              </div>

              <h2>Average Score</h2>

              <p>
                {formatTrend(
                  trends.score_change,
                  " points"
                )}
              </p>
            </div>

            <div className="historyCard">
              <div className="historyValue">
                {latest.potential_findings}
              </div>

              <h2>Potential Findings</h2>

              <p>
                {formatTrend(
                  trends.finding_change
                )}
              </p>
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
                    {formatTimestamp(
                      scan.scan_timestamp
                    )}
                  </p>

                  <p>
                    {scan.total_networks} networks,{" "}
                    {scan.potential_findings} potential findings,{" "}
                    {Number(
                      scan.average_security_score
                    ).toFixed(0)}
                    % average security score.
                  </p>

                  <div className="historyScanDetails">
                    <span>
                      Safe: {scan.safe_count}
                    </span>

                    <span>
                      Rogue candidates: {scan.rogue_count}
                    </span>

                    <span>
                      Evil-twin candidates: {scan.evil_twin_count}
                    </span>

                    <span>
                      Suspicious: {scan.suspicious_count ?? 0}
                    </span>

                    <span>
                      Weak encryption:{" "}
                      {scan.weak_encryption_count ?? 0}
                    </span>

                    <span>
                      Unverified networks:{" "}
                      {scan.unknown_network_count ?? 0}
                    </span>

                    <span>
                      Warnings: {scan.warning_count}
                    </span>
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
