import Logo from "./Logo";

export default function Navbar({ currentPage, setCurrentPage }) {
  const navItems = [
    { id: "home", label: "Home" },
    { id: "dashboard", label: "Dashboard" },
    { id: "networks", label: "Networks" },
    { id: "threats", label: "Threat Center" },
    { id: "reports", label: "Reports" },
    { id: "history", label: "History" },
  ];

  return (
    <header className="navbar">
      <div className="navbarLeft">
        <Logo onClick={setCurrentPage} />
      </div>

      <nav className="navbarCenter">
        {navItems.map((item) => (
          <button
            key={item.id}
            onClick={() => setCurrentPage(item.id)}
            className={
              currentPage === item.id
                ? "navItem activeNav"
                : "navItem"
            }
          >
            {item.label}
          </button>
        ))}
      </nav>

      <div className="navbarRight">
        <button
          className="loginButton"
          onClick={() => setCurrentPage("login")}
        >
          Login
        </button>

        <button
          className="registerButton"
          onClick={() => setCurrentPage("register")}
        >
          Register
        </button>
      </div>
    </header>
  );
}
