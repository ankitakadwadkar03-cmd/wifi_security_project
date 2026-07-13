import StatusBadge from "../components/StatusBadge";
import { networkRows } from "../data/demoData";

export default function DashboardPage({ setCurrentPage }) {
  return (
    <section className="appPage">
      <div className="pageHeader">
        <span>Monitoring Console</span>
        <h1>Dashboard</h1>
        <p>
          Overview of wireless scan results, backend scanner status, recent
          alerts, and security posture.
        </p>
      </div>

      <div className="metricGrid">
        <div className="metricCard">
          <span>Backend Scanner</span>
          <strong>Active</strong>
          <p>Monitoring device running on wlan0mon</p>
        </div>

        <div className="metricCard">
          <span>Networks Monitored</span>
          <strong>24</strong>
          <p>Latest wireless environment snapshot</p>
        </div>

        <div className="metricCard danger">
          <span>Threats Found</span>
          <strong>03</strong>
          <p>Requires administrator review</p>
        </div>

        <div className="metricCard success">
          <span>Security Score</span>
          <strong>82%</strong>
          <p>Current monitored area rating</p>
        </div>
      </div>

      <div className="dashboardLayout">
        <div className="largePanel">
          <div className="panelTitle">
            <h2>Recent Wireless Findings</h2>
            <button onClick={() => setCurrentPage("networks")}>
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

            {networkRows.map((row) => (
              <div className="tableData" key={row.bssid}>
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
          <StatusBadge value="High" />
          <h3>Possible Rogue AP detected</h3>
          <p>
            An unknown access point was observed in the monitored wireless
            environment. Review the BSSID before users connect.
          </p>
          <button onClick={() => setCurrentPage("threats")}>
            Investigate
          </button>
        </div>
      </div>
    </section>
  );
}
