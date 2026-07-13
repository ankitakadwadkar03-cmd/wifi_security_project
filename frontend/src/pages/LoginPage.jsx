export default function LoginPage({ setCurrentPage }) {
  return (
    <section className="authPage">
      <div className="authCard">
        <span className="authTag">Secure Access</span>
        <h1>Login</h1>
        <p>Access your NetShield monitoring dashboard.</p>

        <input type="email" placeholder="Email address" />
        <input type="password" placeholder="Password" />

        <div className="authRow">
          <label>
            <input type="checkbox" /> Remember me
          </label>
          <button onClick={() => setCurrentPage("home")}>Forgot password?</button>
        </div>

        <button className="primaryButton authSubmit">Login</button>

        <p className="authSwitch">
          New to NetShield?{" "}
          <button onClick={() => setCurrentPage("register")}>Create account</button>
        </p>
      </div>
    </section>
  );
}
