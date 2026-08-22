import { useEffect, useState } from "react";
import StatusBadge from "../components/StatusBadge";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000";

function formatModifiedDate(value) {
  if (!value) {
    return "Unknown";
  }

  return new Date(value).toLocaleString();
}

function formatStatus(value) {
  return String(value || "Unknown")
    .replaceAll("_", " ")
    .toLowerCase()
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export default function ReportsPage() {
  const [reports, setReports] = useState([]);
  const [advisorStatus, setAdvisorStatus] = useState(null);
  const [alertStatus, setAlertStatus] = useState(null);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [advisorLoading, setAdvisorLoading] = useState(false);
  const [advisorMessage, setAdvisorMessage] = useState("");
  const [advisorError, setAdvisorError] = useState("");

  const [alertLoading, setAlertLoading] = useState(false);
  const [alertMessage, setAlertMessage] = useState("");
  const [alertError, setAlertError] = useState("");

  async function loadReports(signal) {
    try {
      setLoading(true);
      setError("");

      const response = await fetch(
        `${API_BASE_URL}/api/reports`,
        signal ? { signal } : undefined
      );

      if (!response.ok) {
        throw new Error(`Backend returned HTTP ${response.status}`);
      }

      const data = await response.json();

      setReports(
        Array.isArray(data.reports)
          ? data.reports
          : []
      );

      setAdvisorStatus(
        data.security_advisor || null
      );

      setAlertStatus(
        data.alert_notifications || null
      );
    } catch (fetchError) {
      if (fetchError.name !== "AbortError") {
        console.error(
          "Failed to load reports:",
          fetchError
        );

        setError(
          "Unable to connect to the Reports API. " +
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

    loadReports(controller.signal);

    return () => controller.abort();
  }, []);

  async function generateSecurityAdvisor() {
    if (
      advisorLoading ||
      advisorStatus?.threat_analysis_required
    ) {
      return;
    }

    try {
      setAdvisorLoading(true);
      setAdvisorMessage("");
      setAdvisorError("");

      const generateUrl =
        advisorStatus?.generate_url ||
        "/api/security-advisor/generate";

      const response = await fetch(
        `${API_BASE_URL}${generateUrl}`,
        {
          method: "POST",
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.message ||
            `Security Advisor returned HTTP ${response.status}`
        );
      }

      setAdvisorMessage(
        `${data.message} ` +
          `${data.network_count ?? 0} network(s) reviewed, ` +
          `score ${data.overall_score ?? "Unknown"}/100, ` +
          `grade ${data.overall_grade ?? "Unknown"}.`
      );

      await loadReports();
    } catch (advisorRequestError) {
      console.error(
        "Security Advisor generation failed:",
        advisorRequestError
      );

      setAdvisorError(
        advisorRequestError.message ||
          "Security Advisor could not be generated."
      );

      await loadReports();
    } finally {
      setAdvisorLoading(false);
    }
  }

  async function archiveLegacyAlerts() {
    if (
      alertLoading ||
      !alertStatus?.archive_legacy_url
    ) {
      return;
    }

    try {
      setAlertLoading(true);
      setAlertMessage("");
      setAlertError("");

      const response = await fetch(
        `${API_BASE_URL}${alertStatus.archive_legacy_url}`,
        {
          method: "POST",
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.message ||
            `Alert archive returned HTTP ${response.status}`
        );
      }

      setAlertMessage(
        `${data.message} Archived: ${
          Array.isArray(data.archived_files)
            ? data.archived_files.join(", ")
            : "legacy alert files"
        }.`
      );

      await loadReports();
    } catch (archiveError) {
      console.error(
        "Legacy Alert Notification archive failed:",
        archiveError
      );

      setAlertError(
        archiveError.message ||
          "Legacy Alert Notification files could not be archived."
      );

      await loadReports();
    } finally {
      setAlertLoading(false);
    }
  }

  async function generateAlertNotifications() {
    if (
      alertLoading ||
      !alertStatus?.generate_url ||
      alertStatus?.threat_analysis_required ||
      alertStatus?.migration_required
    ) {
      return;
    }

    try {
      setAlertLoading(true);
      setAlertMessage("");
      setAlertError("");

      const response = await fetch(
        `${API_BASE_URL}${alertStatus.generate_url}`,
        {
          method: "POST",
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.message ||
            `Alert Notification generation returned HTTP ${response.status}`
        );
      }

      const summary = data.summary || {};

      setAlertMessage(
        data.state === "already_recorded"
          ? data.message
          : `${data.message} ${
              data.alert_count ?? 0
            } alert(s) generated: ${
              summary.critical_alerts ?? 0
            } critical, ${
              summary.high_alerts ?? 0
            } high, ${
              summary.medium_alerts ?? 0
            } medium, ${
              summary.low_alerts ?? 0
            } low, ${
              summary.information_alerts ?? 0
            } informational.`
      );

      await loadReports();
    } catch (generationError) {
      console.error(
        "Alert Notification generation failed:",
        generationError
      );

      setAlertError(
        generationError.message ||
          "Alert Notifications could not be generated."
      );

      await loadReports();
    } finally {
      setAlertLoading(false);
    }
  }

  function viewReport(report) {
    window.open(
      `${API_BASE_URL}${report.view_url}`,
      "_blank",
      "noopener,noreferrer"
    );
  }

  const advisorBlocked =
    Boolean(
      advisorStatus?.threat_analysis_required
    );

  const legacyAlerts =
    alertStatus?.status === "legacy" &&
    alertStatus?.migration_required;

  const alertGenerationBlocked =
    Boolean(
      alertStatus?.threat_analysis_required ||
      alertStatus?.migration_required ||
      alertStatus?.status === "incomplete" ||
      alertStatus?.status === "unavailable"
    );

  return (
    <section className="appPage reportsPage">
      <div className="pageHeader">
        <span>Security Documentation</span>

        <h1>Reports</h1>

        <p>
          View and download security reports generated by the NetShield
          analysis modules.
        </p>
      </div>

      {!loading && !error && advisorStatus && (
        <div className="advisorGenerationPanel">
          <div className="advisorGenerationContent">
            <div>
              <span className="advisorGenerationLabel">
                Module 7
              </span>

              <h2>Security Advisor</h2>

              <p>
                Convert the current Threat Analysis report into clear
                explanations, recommendations, and an overall security
                grade.
              </p>
            </div>

            <div className="advisorGenerationStatus">
              <StatusBadge
                value={formatStatus(
                  advisorStatus.status
                )}
              />

              <span>
                {advisorStatus.message}
              </span>
            </div>
          </div>

          <div className="advisorGenerationActions">
            <button
              type="button"
              className="primaryButton"
              onClick={generateSecurityAdvisor}
              disabled={
                advisorLoading ||
                advisorBlocked
              }
            >
              {advisorLoading
                ? "Generating..."
                : "Generate Security Advisor"}
            </button>

            {advisorBlocked && (
              <p>
                Run fresh Threat Analysis in the Threat Center before
                generating Security Advisor recommendations.
              </p>
            )}

            {!advisorBlocked &&
              advisorStatus.generation_required && (
                <p>
                  Advisor generation is available for the current
                  Threat Analysis report.
                </p>
              )}

            {!advisorBlocked &&
              !advisorStatus.generation_required && (
                <p>
                  Security Advisor reports match the current Threat
                  Analysis.
                </p>
              )}
          </div>
        </div>
      )}

      {!loading && !error && alertStatus && (
        <div className="advisorGenerationPanel">
          <div className="advisorGenerationContent">
            <div>
              <span className="advisorGenerationLabel">
                Module 9
              </span>

              <h2>Alert Notifications</h2>

              <p>
                Convert the current Threat Analysis findings into
                severity-based security notifications while keeping
                live packet-alert evidence separate.
              </p>
            </div>

            <div className="advisorGenerationStatus">
              <StatusBadge
                value={formatStatus(
                  alertStatus.status
                )}
              />

              <span>
                {alertStatus.message}
              </span>
            </div>
          </div>

          <div className="advisorGenerationActions">
            {legacyAlerts ? (
              <>
                <button
                  type="button"
                  className="primaryButton"
                  onClick={archiveLegacyAlerts}
                  disabled={
                    alertLoading ||
                    !alertStatus.archive_legacy_url
                  }
                >
                  {alertLoading
                    ? "Archiving..."
                    : "Archive Legacy Alerts"}
                </button>

                <p>
                  Preserve the old Module 9 alert files before
                  generating baseline-aware Alert Notifications.
                </p>
              </>
            ) : (
              <>
                <button
                  type="button"
                  className="primaryButton"
                  onClick={generateAlertNotifications}
                  disabled={
                    alertLoading ||
                    alertGenerationBlocked
                  }
                >
                  {alertLoading
                    ? "Generating..."
                    : alertStatus.status === "current"
                      ? "Update Alert Notifications"
                      : "Generate Alert Notifications"}
                </button>

                {alertStatus.threat_analysis_required && (
                  <p>
                    Run fresh Threat Analysis in the Threat Center
                    before generating Alert Notifications.
                  </p>
                )}

                {!alertStatus.threat_analysis_required &&
                  alertStatus.generation_required &&
                  !alertStatus.migration_required && (
                    <p>
                      Alert Notification generation is available for
                      the current Threat Analysis report.
                    </p>
                  )}

                {!alertStatus.generation_required &&
                  alertStatus.status === "current" && (
                    <p>
                      Alert Notifications match the current Threat
                      Analysis. Re-running will not duplicate alerts.
                    </p>
                  )}

                {alertStatus.migration_required &&
                  !legacyAlerts && (
                    <p>
                      Saved Module 9 outputs require review before
                      new alerts can be generated.
                    </p>
                  )}
              </>
            )}
          </div>
        </div>
      )}

      {alertMessage && (
        <p className="scannerActionMessage">
          {alertMessage}
        </p>
      )}

      {alertError && (
        <p className="scannerActionMessage errorMessage">
          {alertError}
        </p>
      )}

      {advisorMessage && (
        <p className="scannerActionMessage">
          {advisorMessage}
        </p>
      )}

      {advisorError && (
        <p className="scannerActionMessage errorMessage">
          {advisorError}
        </p>
      )}

      {!loading && !error && (
        <div className="reportsSummary">
          <span>Generated report files</span>
          <strong>{reports.length}</strong>
        </div>
      )}

      {loading && (
        <div className="networkTableMessage">
          Loading generated reports...
        </div>
      )}

      {!loading && error && (
        <div className="networkTableMessage errorMessage">
          {error}
        </div>
      )}

      {!loading && !error && reports.length === 0 && (
        <div className="networkTableMessage">
          No generated reports are currently available.
        </div>
      )}

      {!loading && !error && reports.length > 0 && (
        <div className="reportsGrid">
          {reports.map((report) => {
            const hasFreshness =
              Boolean(report.freshness_status);

            const reportIsStale =
              hasFreshness &&
              report.freshness_status !== "current";

            return (
              <div
                className="reportCard"
                key={report.filename}
              >
                <div className="docIcon">
                  <span></span>
                </div>

                <StatusBadge value={report.type} />

                <span className="reportCategory">
                  {report.category}
                </span>

                <h2>{report.title}</h2>

                <p>{report.description}</p>

                {hasFreshness && (
                  <div
                    className={`reportFreshness ${
                      reportIsStale
                        ? "reportFreshnessWarning"
                        : ""
                    }`}
                  >
                    <strong>
                      {formatStatus(
                        report.freshness_status
                      )}
                    </strong>

                    <span>
                      {report.freshness_message}
                    </span>
                  </div>
                )}

                <div className="reportMetadata">
                  <span>{report.filename}</span>
                  <span>{report.size}</span>
                  <span>
                    {formatModifiedDate(
                      report.modified_at
                    )}
                  </span>
                </div>

                <div className="reportActions">
                  <button
                    type="button"
                    onClick={() =>
                      viewReport(report)
                    }
                  >
                    {reportIsStale
                      ? "View Saved Report"
                      : "View Report"}
                  </button>

                  <a
                    href={`${API_BASE_URL}${report.download_url}`}
                    download
                  >
                    Download
                  </a>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}
