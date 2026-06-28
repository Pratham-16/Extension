// popup.js
//
// Pure rendering + the toggle. All real work (native host calls, proxy
// settings) lives in background.js; this script just reads/writes the
// "torStatus" storage key and reflects it.

const STATUS_KEY = "torStatus";

const torToggle = document.getElementById("torToggle");
const toggleLabel = document.getElementById("toggleLabel");
const stepText = document.getElementById("stepText");
const resultBox = document.getElementById("resultBox");
const exitIpLine = document.getElementById("exitIpLine");
const locationLine = document.getElementById("locationLine");

const icons = {
  service: document.getElementById("icon-service"),
  port: document.getElementById("icon-port"),
  tor: document.getElementById("icon-tor"),
  dns: document.getElementById("icon-dns"),
};

function setIcon(el, state) {
  // state: "pending" | "good" | "bad"
  el.className = `icon ${state}`;
  el.textContent = state === "good" ? "✓" : state === "bad" ? "✕" : "○";
}

function render(status) {
  if (!status) {
    toggleLabel.textContent = "Tor tunneling is off";
    torToggle.checked = false;
    torToggle.disabled = false;
    stepText.textContent = "";
    resultBox.classList.remove("visible");
    setIcon(icons.service, "pending");
    setIcon(icons.port, "pending");
    setIcon(icons.tor, "pending");
    setIcon(icons.dns, "pending");
    return;
  }

  const inFlight = status.phase === "progress";
  torToggle.disabled = inFlight;

  if (status.phase === "progress") {
    stepText.textContent = status.step || "Working…";
  } else if (status.phase === "error") {
    stepText.textContent = status.error || "Something went wrong.";
  } else {
    stepText.textContent = "";
  }

  if (status.phase === "started") {
    torToggle.checked = true;
    toggleLabel.textContent = status.success
      ? "Tor tunneling is on"
      : "Tor tunneling is on (verification failed)";

    setIcon(icons.service, status.tor_active ? "good" : "bad");
    setIcon(icons.port, status.socks_port_open ? "good" : "bad");
    setIcon(
      icons.tor,
      status.is_tor === true ? "good" : status.is_tor === false ? "bad" : "pending"
    );
    setIcon(icons.dns, "pending"); // always a manual check — see the button below

    if (status.exit_ip) {
      resultBox.classList.add("visible");
      exitIpLine.textContent = `Exit IP: ${status.exit_ip}`;
      locationLine.textContent = status.location
        ? `Location: ${status.location}`
        : "Location: unknown";
    } else {
      resultBox.classList.remove("visible");
    }

    if (status.error) {
      stepText.textContent = status.error;
    }
  }

  if (status.phase === "stopped") {
    torToggle.checked = false;
    toggleLabel.textContent = "Tor tunneling is off";
    resultBox.classList.remove("visible");
    setIcon(icons.service, "pending");
    setIcon(icons.port, "pending");
    setIcon(icons.tor, "pending");
    setIcon(icons.dns, "pending");
  }
}

torToggle.addEventListener("change", () => {
  const action = torToggle.checked ? "enable" : "disable";
  browser.runtime.sendMessage({ action });
});

document.getElementById("openCheckTor").addEventListener("click", () => {
  browser.tabs.create({ url: "https://check.torproject.org/" });
});

document.getElementById("openDnsLeak").addEventListener("click", () => {
  browser.tabs.create({ url: "https://dnsleaktest.com/" });
});

browser.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === "local" && changes[STATUS_KEY]) {
    render(changes[STATUS_KEY].newValue);
  }
});

(async function init() {
  const stored = await browser.storage.local.get(STATUS_KEY);
  render(stored[STATUS_KEY]);
})();