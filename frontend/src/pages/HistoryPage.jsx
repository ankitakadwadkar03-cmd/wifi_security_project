import { historyItems } from "../data/demoData";

export default function HistoryPage() {
  return (
    <section className="appPage">
      <div className="pageHeader">
        <span>Historical Analysis</span>
        <h1>History</h1>
        <p>
          Compare previous WiFi scans, monitor trends, and understand how your
          wireless environment has changed over time.
        </p>
      </div>

      <div className="historyGrid">
        {historyItems.map((item) => (
          <div className="historyCard" key={item.title}>
            <div className="historyValue">
              {item.value}
            </div>

            <h2>{item.title}</h2>

            <p>{item.text}</p>
          </div>
        ))}
      </div>

      <div className="timelinePanel">
        <h2>Recent Scan Timeline</h2>

        <div className="timelineItem">
          <span className="timelineDot"></span>
          <div>
            <strong>Current Scan</strong>
            <p>3 suspicious wireless events detected.</p>
          </div>
        </div>

        <div className="timelineItem">
          <span className="timelineDot"></span>
          <div>
            <strong>Previous Scan</strong>
            <p>5 wireless events detected.</p>
          </div>
        </div>

        <div className="timelineItem">
          <span className="timelineDot"></span>
          <div>
            <strong>Older Scan</strong>
            <p>8 wireless events detected.</p>
          </div>
        </div>
      </div>
    </section>
  );
}
