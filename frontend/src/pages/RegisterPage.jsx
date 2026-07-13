export default function RegisterPage({ setCurrentPage }) {
  return (
    <section className="authPage">
      <div className="authCard">
        <span className="authTag">Create Account</span>
        <h1>Register</h1>
        <p>Create your NetShield account for secure WiFi monitoring.</p>

        <input type="text" placeholder="Full name" />
        <input type="email" placeholder="Email address" />
        <input type="password" placeholder="Password" />

        <button className="primaryButton authSubmit">Register</button>

        <p className="authSwitch">
          Already have an account?{" "}
          <button onClick={() => setCurrentPage("login")}>Login</button>
        </p>
      </div>
    </section>
  );
}
