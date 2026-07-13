import { useMemo, useState } from "react";
import StatusBadge from "../components/StatusBadge";
import { networkRows } from "../data/demoData";

export default function NetworksPage() {
  const [query, setQuery] = useState("");

  const filteredRows = useMemo(() => {
    return networkRows.filter((row) =>
      `${row.ssid} ${row.bssid} ${row.vendor} ${row.attack}`
        .toLowerCase()
        .includes(query.toLowerCase())
    );
  }, [query]);

  return (
    <section className="appPage">
      <div className="pageHeader">
        <span>Network Inventory</span>
        <h1>Networks</h1>
        <p>
          View discovered WiFi networks with SSID, BSSID, vendor, signal,
          channel, encryption, and threat classification.
        </p>
      </div>

      <div className="toolbar">
        <input
          type="text"
          placeholder="Search SSID, BSSID, vendor, attack type..."
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
        <button>Export CSV</button>
      </div>

      <div className="tablePanel">
        <div className="networkTable head">
          <span>SSID</span>
          <span>BSSID</span>
          <span>Vendor</span>
          <span>Signal</span>
          <span>Channel</span>
          <span>Encryption</span>
          <span>Status</span>
          <span>Attack</span>
        </div>

        {filteredRows.map((row) => (
          <div className="networkTable" key={row.bssid}>
            <span>{row.ssid}</span>
            <span>{row.bssid}</span>
            <span>{row.vendor}</span>
            <span>{row.signal}</span>
            <span>{row.channel}</span>
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
