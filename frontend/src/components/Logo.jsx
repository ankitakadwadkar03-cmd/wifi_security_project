export default function Logo({ onClick }) {
  return (
    <button
      className="logoButton"
      onClick={() => onClick("home")}
    >
      <div className="logoMark">
        <div className="logoGlow"></div>
      </div>

      <div className="logoText">
       <div className="logoName">
         <span className="net">Net</span><span className="shield">Shield</span>
       </div>

       <small>WiFi Security Analyzer</small>
      </div>
    </button>
  );
}
