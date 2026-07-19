import { featureCards, threatCards } from "../data/demoData";
import StatusBadge from "../components/StatusBadge";

import wifiScanningImage from "../assets/wifi scanning photo.jpg";
import packetAnalysisImage from "../assets/live packet analysis photo.jpg";
import threatDetectionImage from "../assets/Threat photo.jpg";
import securityAdvisorImage from "../assets/security photo.jpg";

import { FaShieldAlt, FaLock } from "react-icons/fa";
import { MdWifi } from "react-icons/md";
import { HiOutlineShieldCheck } from "react-icons/hi";

export default function HomePage({ setCurrentPage }) {
  return (
    <>
      <section className="heroSection referenceHero">
        <div className="heroContent referenceHeroContent">
          <span className="eyebrow">
            Real-time Protection. Smarter Connections.
          </span>

          <div className="referenceBrand">
           <h1>Net<span>Shield</span>
           </h1>
          </div>
          <h2>
            Wireless Threat Detection
            <br />
            and <span>Security Advisor</span>
          </h2>

          <p>
            Detect threats, analyze wireless activity, and get expert security
            insights to stay safe and secure before you connect.
          </p>

          <div className="heroButtons">
            <button
              className="primaryButton referencePrimary"
              onClick={() => setCurrentPage("dashboard")}
            >
              Open Dashboard
            </button>

            <button
              className="secondaryButton referenceSecondary"
              onClick={() => setCurrentPage("threats")}
            >
              See How It Works
            </button>
          </div>

          <div className="referenceFeatureRow">
            <div>
              <FaShieldAlt className="featureIcon wifiIcon" />

              <div className="featureCardText">
                <strong>Real-time</strong>
                <span>Threat Detection</span>
              </div>
            </div>

            <div>
              <MdWifi className="featureIcon signalIcon" />

              <div className="featureCardText">
                <strong>Wireless Signal</strong>
                <span>Analysis</span>
              </div>
            </div>

            <div>
              <HiOutlineShieldCheck className="featureIcon shieldIcon" />

              <div className="featureCardText">
                <strong>Security Advisor</strong>
                <span>&amp; Alerts</span>
              </div>
            </div>

            <div>
              <FaLock className="featureIcon lockIcon" />

              <div className="featureCardText">
                <strong>Privacy by</strong>
                <span>Design</span>
              </div>
            </div>
          </div>
        </div>

      </section>

      <section className="featureIntro">
        <span>Core Capabilities</span>

        <h2>Complete Wireless Security, All in One Place</h2>

        <p>
          NetShield brings wireless scanning, packet visibility, threat detection,
          security alerts, reports, and actionable recommendations together in one
          unified platform.
        </p>
      </section>

      <section className="featureStack">
        {featureCards.map((feature, index) => (
          <div
            className={`featureBlock ${index % 2 === 1 ? "reverse" : ""}`}
            key={feature.title}
          >
            <div className="featureTextBlock">
              <span>{feature.tag}</span>

              <h3>{feature.title}</h3>

              <p>{feature.text}</p>

              <ul>
                {feature.points.map((point) => (
                  <li key={point}>{point}</li>
                ))}
              </ul>
            </div>

            <div className={`visualBox ${feature.visual}Visual`}>
              {feature.visual === "radar" ? (
                <img
                  src={wifiScanningImage}
                  alt="WiFi network scanning"
                  className="capabilityImage"
                />
              ) : feature.visual === "packet" ? (
                <img
                  src={packetAnalysisImage}
                  alt="Live packet analysis"
                  className="capabilityImage"
                />
              ) : feature.visual === "threat" ? (
                <img
                  src={threatDetectionImage}
                  alt="Wireless threat detection"
                  className="threatCapabilityImage"
                />
              ) : feature.visual === "advisor" ? (
                <img
                  src={securityAdvisorImage}
                  alt="Security advisor"
                  className="advisorCapabilityImage"
                />
              ) : null}
            </div>
          </div>
        ))}
      </section>

      <section className="splitShowcase threatCoverageSection">
        <div>
          <span>Threat Coverage</span>

          <h2>Security signals that matter</h2>

          <p>
            The interface focuses on the conditions users and administrators
            actually need to review before trusting a wireless network.
          </p>

          <button
            className="primaryButton"
            onClick={() => setCurrentPage("threats")}
          >
            Open Threat Center
          </button>
        </div>

        <div className="threatMiniGrid">
          {threatCards.map((threat) => (
            <div key={threat.title}>
              <StatusBadge value={threat.severity} />

              <h3>{threat.title}</h3>

              <p>{threat.text}</p>
            </div>
          ))}
        </div>
      </section>
    </>
  );
}
