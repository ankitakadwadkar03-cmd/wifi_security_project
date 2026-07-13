import { useState } from "react";
import "./App.css";

import Navbar from "./components/Navbar";

import HomePage from "./pages/HomePage";
import LoginPage from "./pages/LoginPage";
import RegisterPage from "./pages/RegisterPage";
import DashboardPage from "./pages/DashboardPage";
import NetworksPage from "./pages/NetworksPage";
import ThreatCenterPage from "./pages/ThreatCenterPage";
import ReportsPage from "./pages/ReportsPage";
import HistoryPage from "./pages/HistoryPage";

export default function App() {
  const [currentPage, setCurrentPage] = useState("home");

  const renderPage = () => {
    if (currentPage === "login") {
      return <LoginPage setCurrentPage={setCurrentPage} />;
    }

    if (currentPage === "register") {
      return <RegisterPage setCurrentPage={setCurrentPage} />;
    }

    if (currentPage === "dashboard") {
      return <DashboardPage setCurrentPage={setCurrentPage} />;
    }

    if (currentPage === "networks") {
      return <NetworksPage />;
    }

    if (currentPage === "threats") {
      return <ThreatCenterPage />;
    }

    if (currentPage === "reports") {
      return <ReportsPage />;
    }

    if (currentPage === "history") {
      return <HistoryPage />;
    }

    return <HomePage setCurrentPage={setCurrentPage} />;
  };

  return (
    <main className={`netshieldApp page-${currentPage}`}>
      <Navbar
        currentPage={currentPage}
        setCurrentPage={setCurrentPage}
      />

      <div className="pageContent">
        {renderPage()}
      </div>
    </main>
  );
}
