import { threatCards } from "../data/demoData";
import StatusBadge from "../components/StatusBadge";

export default function ThreatCenterPage() {
  return (
    <section className="appPage">

      <div className="pageHeader">
        <span>Security Monitoring</span>
        <h1>Threat Center</h1>
        <p>
          Review suspicious wireless activities detected by NetShield and
          understand their severity before connecting to a network.
        </p>
      </div>

      <div className="threatGrid">

        {threatCards.map((item) => (
          <div className="threatCard" key={item.title}>

            <div className="threatTop">
              <StatusBadge value={item.severity} />
            </div>

            <h2>{item.title}</h2>

            <p>{item.text}</p>

            <div className="recommendationBox">
              <h3>Recommendation</h3>

              <ul>

                <li>Verify the network before connecting.</li>

                <li>Check the BSSID and encryption type.</li>

                <li>Avoid unknown or open WiFi networks.</li>

                <li>Disconnect immediately if suspicious behaviour is detected.</li>

              </ul>
            </div>

          </div>
        ))}

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
            <h3>Monitor Devices</h3>
            <p>
              Periodically review connected devices and remove unknown clients.
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
