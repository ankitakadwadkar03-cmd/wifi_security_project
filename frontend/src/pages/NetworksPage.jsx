import { useEffect, useMemo, useState } from "react";
import StatusBadge from "../components/StatusBadge";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000";


function getSignalClass(signal) {
  const value = Number(signal);

  if (!Number.isFinite(value)) {
    return "signalUnknown";
  }

  if (value >= -60) {
    return "signalStrong";
  }

  if (value >= -70) {
    return "signalModerate";
  }

  if (value >= -80) {
    return "signalWeak";
  }

  return "signalVeryWeak";
}

export default function NetworksPage() {
  const [query, setQuery] = useState("");
  const [networkRows, setNetworkRows] = useState([]);
  const [networkUpdatedAt, setNetworkUpdatedAt] = useState(null);
  const [networkAgeSeconds, setNetworkAgeSeconds] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const controller = new AbortController();

    async function loadNetworks(showLoading = false) {
      try {
        if (showLoading) {
          setLoading(true);
        }

        setError("");

        const response = await fetch(`${API_BASE_URL}/api/networks`, {
          signal: controller.signal,
        });

        if (!response.ok) {
          throw new Error(`Backend returned HTTP ${response.status}`);
        }

        const data = await response.json();

        setNetworkRows(
          Array.isArray(data.networks) ? data.networks : []
        );

        setNetworkUpdatedAt(data.updated_at || null);
        setNetworkAgeSeconds(
          Number.isFinite(Number(data.age_seconds))
            ? Number(data.age_seconds)
            : null
        );
      } catch (fetchError) {
        if (fetchError.name !== "AbortError") {
          console.error("Failed to load networks:", fetchError);
          setError(
            "Unable to connect to the NetShield backend. Make sure the Flask API is running."
          );
        }
      } finally {
        if (showLoading) {
          setLoading(false);
        }
      }
    }

    async function loadScannerStatus() {
      try {
        const response = await fetch(
          `${API_BASE_URL}/api/scanner/status`,
          {
            signal: controller.signal,
          }
        );

        if (!response.ok) {
          return null;
        }

        return await response.json();
      } catch (fetchError) {
        if (fetchError.name !== "AbortError") {
          console.error(
            "Failed to load scanner status:",
            fetchError
          );
        }

        return null;
      }
    }

    loadNetworks(true);

    let scannerWasRunning = false;

    const pollingTimer = window.setInterval(async () => {
      const scannerStatus = await loadScannerStatus();

      if (scannerStatus?.running) {
        scannerWasRunning = true;
        loadNetworks(false);
      } else if (scannerWasRunning) {
        scannerWasRunning = false;
        loadNetworks(false);
      }
    }, 2000);

    return () => {
      controller.abort();
      window.clearInterval(pollingTimer);
    };
  }, []);

  const networkFreshness =
    networkAgeSeconds === null
      ? "No scan timestamp available"
      : networkAgeSeconds < 60
        ? `Updated ${Math.round(networkAgeSeconds)}s ago`
        : networkAgeSeconds < 3600
          ? `Updated ${Math.round(networkAgeSeconds / 60)}m ago`
          : `Updated ${Math.round(networkAgeSeconds / 3600)}h ago`;

  const filteredRows = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();

    if (!normalizedQuery) {
      return networkRows;
    }

    return networkRows.filter((row) =>
      [
        row.ssid,
        row.bssid,
        row.frequency,
        row.signal,
        row.channel,
        row.encryption,
        row.status,
        row.attack,
      ]
        .join(" ")
        .toLowerCase()
        .includes(normalizedQuery)
    );
  }, [networkRows, query]);

  function exportNetworksCsv() {
    if (filteredRows.length === 0) {
      return;
    }

    const headers = [
      "SSID",
      "BSSID",
      "Frequency",
      "Signal",
      "Channel",
      "Encryption",
      "Status",
      "Attack",
    ];

    const escapeCsvValue = (value) =>
      `"${String(value ?? "").replace(/"/g, '""')}"`;

    const rows = filteredRows.map((row) => [
      row.ssid,
      row.bssid,
      row.frequency,
      row.signal,
      row.channel,
      row.encryption,
      row.status,
      row.attack,
    ]);

    const csvContent = [
      headers.map(escapeCsvValue).join(","),
      ...rows.map((row) => row.map(escapeCsvValue).join(",")),
    ].join("\n");

    const blob = new Blob([csvContent], {
      type: "text/csv;charset=utf-8;",
    });

    const downloadUrl = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = downloadUrl;
    link.download = "netshield_networks.csv";
    document.body.appendChild(link);
    link.click();
    link.remove();

    URL.revokeObjectURL(downloadUrl);
  }

  return (
    <section className="appPage networksPage">
      <div className="pageHeader">
        <span>Network Inventory</span>
        <h1>Networks</h1>
        <p>
          View real WiFi networks discovered by the NetShield scanner,
          including SSID, BSSID, signal strength, channel, frequency and
          encryption.
        </p>
      </div>

      <div className="networkFreshnessBar">
        <span>Scanner Results</span>
        <strong>
          {networkUpdatedAt
            ? networkFreshness
            : "No scanner results available"}
        </strong>
        <p>{networkRows.length} networks currently stored</p>
      </div>

      <div className="toolbar">
        <input
          type="text"
          placeholder="Search SSID, BSSID, signal, channel or encryption..."
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />

        <button
          type="button"
          onClick={exportNetworksCsv}
          disabled={loading || filteredRows.length === 0}
        >
          Export CSV
        </button>
      </div>

      <div className="tablePanel">
        <div className="networkTable head">
          <span>SSID</span>
          <span>BSSID</span>
          <span>Frequency</span>
          <span>Signal</span>
          <span>Channel</span>
          <span>Encryption</span>
          <span>Status</span>
          <span>Attack</span>
        </div>

        {loading && (
          <div className="networkTableMessage">
            Loading real scanner results...
          </div>
        )}

        {!loading && error && (
          <div className="networkTableMessage errorMessage">{error}</div>
        )}

        {!loading && !error && filteredRows.length === 0 && (
          <div className="networkTableMessage">
            No networks match your search.
          </div>
        )}

        {!loading &&
          !error &&
          filteredRows.map((row) => (
            <div
              className="networkTable"
              key={`${row.bssid}-${row.channel}`}
            >
              <span>{row.ssid}</span>
              <span>{row.bssid}</span>
              <span>{row.frequency || "Unknown"}</span>
              <span
                className={`signalValue ${getSignalClass(row.signal)}`}
              >
                {row.signal ? `${row.signal} dBm` : "Unknown"}
              </span>
              <span>{row.channel || "Unknown"}</span>
              <span>{row.encryption}</span>
              <span>
                <StatusBadge value={row.status} />
              </span>
              <span>{row.attack}</span>
            </div>
          ))}
      </div>
    </section>
  );
}
