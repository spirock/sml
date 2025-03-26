// src/App.tsx
import React from "react";
import { BrowserRouter, Routes, Route, Link } from 'react-router-dom';

import Dashboard from "./components/Dashboard";
import Logs from "./components/Logs";
import Rules from "./components/Rules";

function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-gray-100 p-4">
        <h1 className="text-3xl font-bold mb-4 text-center">SuricataML Dashboard</h1>

        <nav className="flex justify-center gap-6 mb-8">
          <Link to="/" className="hover:underline">Estadísticas</Link>
          <Link to="/logs" className="hover:underline">Logs</Link>
          <Link to="/rules" className="hover:underline">Reglas</Link>
        </nav>

        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/logs" element={<Logs />} />
          <Route path="/rules" element={<Rules />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}

export default App;
