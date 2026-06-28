// popup.js
const STORAGE_KEY = "blockedDomains";
const PASS_KEY = "blockerPasscode";

const domainInput = document.getElementById("domainInput");
const addBtn = document.getElementById("addBtn");
const manageBtn = document.getElementById("manageBtn");
const domainList = document.getElementById("domainList");
const countLabel = document.getElementById("countLabel");
const statusEl = document.getElementById("status");

let statusTimer = null;

function setStatus(message) {
  statusEl.textContent = message;
  if (statusTimer) clearTimeout(statusTimer);
  statusTimer = setTimeout(() => { statusEl.textContent = ""; }, 2200);
}

function normalizeDomain(raw) {
  return raw.trim().toLowerCase().replace(/^[a-z]+:\/\//, "").replace(/^www\./, "").replace(/[/?#].*$/, "");
}

async function getDomains() {
  const stored = await chrome.storage.local.get(STORAGE_KEY);
  return stored[STORAGE_KEY] || [];
}

async function saveDomains(domains) {
  const unique = [...new Set(domains.filter(Boolean))].sort();
  await chrome.storage.local.set({ [STORAGE_KEY]: unique });
  return unique;
}

function renderList(domains) {
  domainList.innerHTML = "";
  countLabel.textContent = String(domains.length);

  if (domains.length === 0) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "Nothing blocked yet";
    domainList.appendChild(li);
    return;
  }

  domains.forEach((domain) => {
    const li = document.createElement("li");
    const name = document.createElement("span");
    name.className = "domain-name";
    name.textContent = domain;

    const removeBtn = document.createElement("button");
    removeBtn.className = "remove";
    removeBtn.textContent = "Remove";
    removeBtn.addEventListener("click", async () => {
      const storedPass = await chrome.storage.local.get(PASS_KEY);
      const activePasscode = storedPass[PASS_KEY];

      if (activePasscode) {
        // Safe fall back to prevent frame break inside small UI panels
        const userInput = prompt("Enter administrative passcode to unlock domain:");
        if (userInput !== activePasscode) {
          if (userInput !== null) setStatus("Incorrect passcode.");
          return;
        }
      }

      const current = await getDomains();
      const updated = await saveDomains(current.filter((d) => d !== domain));
      renderList(updated);
      setStatus(`Unblocked ${domain}`);
    });

    li.appendChild(name);
    li.appendChild(removeBtn);
    domainList.appendChild(li);
  });
}

async function addDomain(rawValue) {
  const domain = normalizeDomain(rawValue);
  if (!domain || !domain.includes(".")) {
    setStatus("Enter a valid domain.");
    return;
  }
  const current = await getDomains();
  const updated = await saveDomains([...current, domain]);
  renderList(updated);
  setStatus(`Blocked ${domain}`);
}

addBtn.addEventListener("click", () => {
  addDomain(domainInput.value);
  domainInput.value = "";
  domainInput.focus();
});

domainInput.addEventListener("keydown", (e) => { if (e.key === "Enter") addBtn.click(); });
manageBtn.addEventListener("click", () => { chrome.tabs.create({ url: chrome.runtime.getURL("manage.html") }); });

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === "local" && changes[STORAGE_KEY]) {
    renderList(changes[STORAGE_KEY].newValue || []);
  }
});

(async function init() { renderList(await getDomains()); })();