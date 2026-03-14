import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./globals.css";

// Apply saved font size before first render to avoid flash
const _savedFontSize = localStorage.getItem("anya-font-size");
if (_savedFontSize) {
  document.documentElement.style.setProperty("--font-size-base", _savedFontSize);
}

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
