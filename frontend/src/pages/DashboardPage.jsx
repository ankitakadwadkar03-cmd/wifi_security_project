import { useEffect, useState } from "react";
import StatusBadge from "../components/StatusBadge";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000";

const EMPTY_SCANNER_STATUS = {
  state: "idle",
  running: false,
  interface: null,
  message: "Checking scanner status...",
  adapter: {
    available: false,
    interfaces: [],
    message: "Checking wireless adapter...",
  },
};

const EMPTY_CAPTURE_STATUS = {
  state: "idle",
  running: false,
  interface: null,
  pid: null,
  message: "Checking packet-capture status...",
  packet_log_found: false,
  adapter: {
    available: false,
    interfaces: [],
    message: "Checking wireless adapter...",
  },
};

export default function DashboardPage({ setCurrentPage }) {
  const [networks, setNetworks] = useState([]);
  const [threats, setThreats] = useState([]);
  const [latestHistory, setLatestHistory] = useState(null);
  const [backendStatus, setBackendStatus] = useState("Checking");
  const [scannerStatus, setScannerStatus] = useState(EMPTY_SCANNER_STATUS);
  const [captureStatus, setCaptureStatus] = useState(EMPTY_CAPTURE_STATUS);
  const [selectedInterface, setSelectedInterface] = useState("");
  const [scannerActionLoading, setScannerActionLoading] = useState(false);
  const [scannerMessage, setScannerMessage] = useState("");
  const [captureActionLoading, setCaptureActionLoading] = useState(false);
  const [captureMessage, setCaptureMessage] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function loadScannerStatus() {
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/scanner/status`
      );

      if (!response.ok) {
        throw new Error(`Scanner status returned HTTP ${response.status}`);
      }

      const data = await response.json();
      setScannerStatus(data);

      const interfaces = Array.isArray(data.adapter?.interfaces)
        ? data.adapter.interfaces
        : [];

      setSelectedInterface((currentInterface) => {
        const currentStillExists = interfaces.some(
          (item) => item.name === currentInterface
        );

        if (currentStillExists) {
          return currentInterface;
        }

        return interfaces[0]?.name || "";
      });
    } catch (statusError) {
      console.error("Scanner status error:", statusError);

      setScannerStatus({
        ...EMPTY_SCANNER_STATUS,
        state: "error",
        message: "Unable to read scanner status.",
      });
    }
  }

  async function loadCaptureStatus() {
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/capture/status`
      );

      if (!response.ok) {
        throw new Error(
          `Capture status returned HTTP ${response.status}`
        );
      }

      const data = await response.json();
      setCaptureStatus(data);
    } catch (statusError) {
      console.error("Packet-capture status error:", statusError);

      setCaptureStatus({
        ...EMPTY_CAPTURE_STATUS,
        state: "error",
        message: "Unable to read packet-capture status.",
      });
    }
  }

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
    loadScannerStatus();
    loadCaptureStatus();

    const pollingTimer = window.setInterval(() => {
      loadScannerStatus();
      loadCaptureStatus();
    }, 2000);

    return () => {
      controller.abort();
      window.clearInterval(pollingTimer);
    };
  }, []);

  async function runScannerAction(action) {
    try {
      setScannerActionLoading(true);
      setScannerMessage("");

      const requestOptions = {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
      };

      if (action === "start") {
        requestOptions.body = JSON.stringify({
          interface: selectedInterface || null,
        });
      }

      const response = await fetch(
        `${API_BASE_URL}/api/scanner/${action}`,
        requestOptions
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.message ||
            data.scanner?.message ||
            `Unable to ${action} scanner.`
        );
      }

      setScannerMessage(
        data.scanner?.message ||
          data.message ||
          `Scanner ${action} request completed.`
      );

      await loadScannerStatus();
    } catch (actionError) {
      console.error(`Scanner ${action} error:`, actionError);
      setScannerMessage(actionError.message);
      await loadScannerStatus();
    } finally {
      setScannerActionLoading(false);
    }
  }

  async function runCaptureAction(action) {
    try {
      setCaptureActionLoading(true);
      setCaptureMessage("");

      const requestOptions = {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
      };

      if (action === "start") {
        requestOptions.body = JSON.stringify({
          interface: selectedInterface || null,
        });
      }

      const response = await fetch(
        `${API_BASE_URL}/api/capture/${action}`,
        requestOptions
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.message ||
            data.capture?.message ||
            `Unable to ${action} packet capture.`
        );
      }

      setCaptureMessage(
        data.capture?.message ||
          data.message ||
          `Packet-capture ${action} request completed.`
      );

      await Promise.all([
        loadCaptureStatus(),
        loadScannerStatus(),
      ]);
    } catch (actionError) {
      console.error(
        `Packet-capture ${action} error:`,
        actionError
      );

      setCaptureMessage(actionError.message);

      await Promise.all([
        loadCaptureStatus(),
        loadScannerStatus(),
      ]);
    } finally {
      setCaptureActionLoading(false);
    }
  }

  const recentNetworks = networks.slice(0, 5);
  const latestThreat = threats[0];

  const securityScore = latestHistory
    ? `${Number(
        latestHistory.average_security_score
      ).toFixed(0)}%`
    : "—";

  const adapter = scannerStatus.adapter || EMPTY_SCANNER_STATUS.adapter;
  const interfaces = Array.isArray(adapter.interfaces)
    ? adapter.interfaces
    : [];

  const scannerRunning = Boolean(scannerStatus.running);
  const captureRunning = Boolean(captureStatus.running);

  const canStartScanner =
    adapter.available &&
    selectedInterface &&
    !scannerRunning &&
    !captureRunning &&
    !scannerActionLoading &&
    !captureActionLoading;

  const canStopScanner =
    scannerRunning &&
    !scannerActionLoading &&
    !captureActionLoading;

  const canStartCapture =
    adapter.available &&
    selectedInterface &&
    !captureRunning &&
    !scannerRunning &&
    !captureActionLoading &&
    !scannerActionLoading;

  const canStopCapture =
    captureRunning &&
    !captureActionLoading &&
    !scannerActionLoading;

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
          <span>Backend API</span>
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

      <div className="scannerControlPanel">
        <div className="scannerControlHeader">
          <div>
            <span>Wireless Scanner Control</span>
            <h2>Start or stop real-time WiFi scanning</h2>
          </div>

          <div
            className={`scannerStateBadge scanner-${scannerStatus.state}`}
          >
            {scannerStatus.state.replaceAll("_", " ")}
          </div>
        </div>

        <div className="scannerControlGrid">
          <div className="scannerInfoItem">
            <span>Adapter Status</span>
            <strong>
              {adapter.available ? "Detected" : "Not Detected"}
            </strong>
            <p>{adapter.message}</p>
          </div>

          <div className="scannerInfoItem">
            <span>Wireless Interface</span>

            {interfaces.length > 0 ? (
              <select
                value={selectedInterface}
                disabled={scannerRunning || captureRunning}
                onChange={(event) =>
                  setSelectedInterface(event.target.value)
                }
              >
                {interfaces.map((item) => (
                  <option key={item.name} value={item.name}>
                    {item.name} — {item.mode}
                  </option>
                ))}
              </select>
            ) : (
              <strong>Unavailable</strong>
            )}

            <p>
              {scannerStatus.interface
                ? `Scanner interface: ${scannerStatus.interface}`
                : adapter.available
                  ? "Wireless interface is ready for scanning."
                  : "Connect a compatible USB WiFi adapter."}
            </p>
          </div>

          <div className="scannerInfoItem">
            <span>Scanner Process</span>
            <strong>
              {scannerStatus.pid
                ? `PID ${scannerStatus.pid}`
                : "No active process"}
            </strong>
            <p>{scannerStatus.message}</p>
          </div>
        </div>

        <div className="scannerActions">
          <button
            type="button"
            className="startScanButton"
            disabled={!canStartScanner}
            onClick={() => runScannerAction("start")}
          >
            {scannerActionLoading && !scannerRunning
              ? "Starting..."
              : "Start Scan"}
          </button>

          <button
            type="button"
            className="stopScanButton"
            disabled={!canStopScanner}
            onClick={() => runScannerAction("stop")}
          >
            {scannerActionLoading && scannerRunning
              ? "Stopping..."
              : "Stop Scan"}
          </button>
        </div>

        {scannerMessage && (
          <p className="scannerActionMessage">
            {scannerMessage}
          </p>
        )}
      </div>

      <div className="scannerControlPanel captureControlPanel">
        <div className="scannerControlHeader">
          <div>
            <span>Live Packet Capture</span>
            <h2>Capture and analyze authorized WiFi traffic</h2>
          </div>

          <div
            className={`scannerStateBadge scanner-${captureStatus.state}`}
          >
            {captureStatus.state.replaceAll("_", " ")}
          </div>
        </div>

        <div className="scannerControlGrid">
          <div className="scannerInfoItem">
            <span>Capture Interface</span>
            <strong>
              {captureStatus.adapter?.interfaces?.[0]
                ? `${captureStatus.adapter.interfaces[0].name} — ${captureStatus.adapter.interfaces[0].mode}`
                : selectedInterface || "Unavailable"}
            </strong>
            <p>
              {captureRunning
                ? "The adapter is operating in monitor mode."
                : scannerRunning
                  ? "The adapter is currently reserved by the WiFi scanner."
                  : "The selected managed interface is ready."}
            </p>
          </div>

          <div className="scannerInfoItem">
            <span>Capture Process</span>
            <strong>
              {captureStatus.pid
                ? `PID ${captureStatus.pid}`
                : "No active process"}
            </strong>
            <p>{captureStatus.message}</p>
          </div>

          <div className="scannerInfoItem">
            <span>Packet Log</span>
            <strong>
              {captureStatus.packet_log_found
                ? "CSV Available"
                : "No Capture Yet"}
            </strong>
            <p>Saved to packet_logs/wifi_packets.csv</p>
          </div>
        </div>

        <div className="scannerActions">
          <button
            type="button"
            className="startScanButton"
            disabled={!canStartCapture}
            onClick={() => runCaptureAction("start")}
          >
            {captureActionLoading && !captureRunning
              ? "Starting..."
              : "Start Capture"}
          </button>

          <button
            type="button"
            className="stopScanButton"
            disabled={!canStopCapture}
            onClick={() => runCaptureAction("stop")}
          >
            {captureActionLoading && captureRunning
              ? "Stopping..."
              : "Stop Capture"}
          </button>
        </div>

        {captureMessage && (
          <p className="scannerActionMessage">
            {captureMessage}
          </p>
        )}
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
