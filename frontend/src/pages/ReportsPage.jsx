import { reportCards } from "../data/demoData";
import StatusBadge from "../components/StatusBadge";

export default function ReportsPage() {
  return (
    <section className="appPage">
      <div className="pageHeader">
        <span>Security Documentation</span>
        <h1>Reports</h1>
        <p>
          View generated security reports, advisor summaries, historical trend
          reports, and alert logs.
        </p>
      </div>

      <div className="reportsGrid">
        {reportCards.map((report) => (
          <div className="reportCard" key={report.title}>
            <div className="docIcon">
              <span></span>
            </div>

            <StatusBadge value={report.type} />

            <h2>{report.title}</h2>
            <p>{report.text}</p>

            <div className="reportActions">
              <button>View Report</button>
              <button>Export</button>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
