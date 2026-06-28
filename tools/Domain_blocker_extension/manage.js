// manage.js
const STORAGE_KEY = "blockedDomains";
const PASS_KEY = "blockerPasscode";

const domainInput = document.getElementById("domainInput");
const addBtn = document.getElementById("addBtn");
const fileInput = document.getElementById("fileInput");
const domainList = document.getElementById("domainList");
const countLabel = document.getElementById("countLabel");
const statusEl = document.getElementById("status");

// Passcode fields
const oldPasscodeInput = document.getElementById("oldPasscodeInput");
const passcodeInput = document.getElementById("passcodeInput");
const setPassBtn = document.getElementById("setPassBtn");
const panelTitle = document.getElementById("panelTitle");

// Custom UI Modal Elements
const customModal = document.getElementById("customModal");
const modalVerifyInput = document.getElementById("modalVerifyInput");
const modalCancelBtn = document.getElementById("modalCancelBtn");
const modalConfirmBtn = document.getElementById("modalConfirmBtn");

let statusTimer = null;
let modalResolveFn = null; // Asynchronous placeholder hook

function setStatus(message) {
  statusEl.textContent = message;
  if (statusTimer) clearTimeout(statusTimer);
  statusTimer = setTimeout(() => { statusEl.textContent = ""; }, 2500);
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

// Custom UI Prompt Modal Promise Handler
function requestPasscodeVerification() {
  return new Promise((resolve) => {
    modalVerifyInput.value = "";
    customModal.classList.add("active");
    modalVerifyInput.focus();
    modalResolveFn = resolve; 
  });
}

// Close and return modal context
function closeCustomModal(resultValue) {
  customModal.classList.remove("active");
  if (modalResolveFn) {
    modalResolveFn(resultValue);
    modalResolveFn = null;
  }
}

modalCancelBtn.addEventListener("click", () => closeCustomModal(null));
modalConfirmBtn.addEventListener("click", () => closeCustomModal(modalVerifyInput.value));
modalVerifyInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") modalConfirmBtn.click();
});

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
        // Trigger clean UI frame modal overlay instead of native prompt
        const userInput = await requestPasscodeVerification();
        if (userInput !== activePasscode) {
          if (userInput !== null) setStatus("Incorrect passcode. Action denied.");
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
    setStatus("Enter a valid domain, e.g. example.com");
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

function extractDomainFromLine(line) {
  const withoutComment = line.split("#")[0].trim();
  if (!withoutComment) return "";
  const parts = withoutComment.split(/\s+/);
  return normalizeDomain(parts[parts.length - 1]);
}

fileInput.addEventListener("change", async (event) => {
  const file = event.target.files[0];
  if (!file) return;
  const text = await file.text();
  const parsed = text.split(/\r?\n/).map(extractDomainFromLine).filter((d) => d && d.includes(".") && d !== "0.0.0.0" && d !== "localhost");
  const current = await getDomains();
  const updated = await saveDomains([...current, ...parsed]);
  renderList(updated);
  setStatus(`Imported ${parsed.length} domains`);
  fileInput.value = "";
});

// Secure Update Logic for modifying passcode rules
setPassBtn.addEventListener("click", async () => {
  const stored = await chrome.storage.local.get(PASS_KEY);
  const activePasscode = stored[PASS_KEY];
  const newPass = passcodeInput.value.trim();

  // 1st Issue Fix: If passcode is active, require old verification phrase matches
  if (activePasscode) {
    const oldInput = oldPasscodeInput.value.trim();
    if (oldInput !== activePasscode) {
      setStatus("Error: Current administrative passcode matches failed.");
      return;
    }
  }

  if (!newPass) {
    await chrome.storage.local.remove(PASS_KEY);
    setStatus("Administrative security restrictions removed.");
  } else {
    await chrome.storage.local.set({ [PASS_KEY]: newPass });
    setStatus("Administrative credentials modified successfully!");
  }

  passcodeInput.value = "";
  oldPasscodeInput.value = "";
  refreshPasscodeUI();
});

async function refreshPasscodeUI() {
  const stored = await chrome.storage.local.get(PASS_KEY);
  if (stored[PASS_KEY]) {
    panelTitle.textContent = "Modify Administrative Passcode Settings";
    oldPasscodeInput.style.display = "block";
    passcodeInput.placeholder = "Enter new passcode";
  } else {
    panelTitle.textContent = "Set Administration Passcode";
    oldPasscodeInput.style.display = "none";
    passcodeInput.placeholder = "New passcode (leave blank to disable)";
  }
}

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === "local" && changes[STORAGE_KEY]) {
    renderList(changes[STORAGE_KEY].newValue || []);
  }
});

(async function init() {
  renderList(await getDomains());
  refreshPasscodeUI();
})();