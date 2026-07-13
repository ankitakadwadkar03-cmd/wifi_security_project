import heroImage from "../assets/netshield-hero.jpg";

export default function HeroVisual() {
  return (
    <div className="referenceVisual">
      <div className="referenceVisualGlow"></div>

      <img
        src={heroImage}
        alt="NetShield WiFi security analyzer"
        className="referenceLaptopImage"
      />
    </div>
  );
}
