/**
 * popup.js
 * --------
 * Triggers the audit, renders findings into the severity columns,
 * the logical-flaws box, the cookie panel, and wires click-to-view-fix.
 */

const scanBtn = document.getElementById("scanBtn");
const statusEl = document.getElementById("status");
const reportEl = document.getElementById("report");
const criticalList = document.getElementById("criticalList");
const mediumList = document.getElementById("mediumList");
const lowList = document.getElementById("lowList");
const logicalList = document.getElementById("logicalList");
const cookieList = document.getElementById("cookieList");
const fixDetail = document.getElementById("fixDetail");
const scanMeta = document.getElementById("scanMeta");

// Rule IDs that represent structural/logical flaws rather than direct injection sinks.
// These get mirrored into the "Logical flaws in code" box in addition to their severity column.
const LOGICAL_FLAW_IDS = new Set(["AUTH_DEAD_CODE", "EMPTY_CATCH", "WEAK_RANDOM_TOKEN", "FETCH_DYNAMIC_URL"]);

function clearLists() {
  [criticalList, mediumList, lowList, logicalList, cookieList].forEach((el) => (el.innerHTML = ""));
  fixDetail.innerHTML = '<p class="fix-placeholder">Click any finding above to see its fix here.</p>';
}

function emptyNote(text) {
  const div = document.createElement("div");
  div.className = "empty-note";
  div.textContent = text;
  return div;
}

function renderCodeFinding(finding, container) {
  const item = document.createElement("div");
  item.className = "finding-item";
  if (finding.confidence === "low") item.classList.add("low-confidence");
  if (finding.isSummary) item.classList.add("summary-row");

  const locationLabel = finding.line != null
    ? `line ${finding.line}`
    : finding.charOffset != null
      ? `offset ${finding.charOffset}`
      : "";
  const confidenceTag = finding.confidence === "low" ? ' <span class="conf-tag">unverified</span>' : "";
  const headline = finding.plainSummary || finding.title;

  item.innerHTML = `
    <span class="f-headline">${escapeHtml(headline)}${confidenceTag}</span>
    <span class="f-title">${escapeHtml(finding.title)}</span>
    <span class="f-meta">${escapeHtml(finding.shortOrigin || finding.origin)}${locationLabel ? " · " + locationLabel : ""}</span>
  `;
  item.addEventListener("click", () => showFix(finding));
  container.appendChild(item);
}

function renderCookieFinding(finding) {
  const item = document.createElement("div");
  item.className = `cookie-item sev-${finding.severity}`;
  const tagColor = finding.severity === "critical" ? "var(--critical)" : finding.severity === "medium" ? "var(--medium)" : "var(--green-dim)";
  const vendorLabel = finding.vendor ? ` <span class="vendor-tag">${escapeHtml(finding.vendor)}</span>` : "";
  item.innerHTML = `
    <div class="cookie-row">
      <span class="cookie-name">${escapeHtml(finding.name)}</span>${vendorLabel}
      <span class="cookie-tag" style="color:${tagColor}">${finding.severity.toUpperCase()}</span>
    </div>
    <span class="cookie-headline">${escapeHtml(finding.headline)}</span>
  `;
  item.addEventListener("click", () => showCookieFix(finding));
  cookieList.appendChild(item);
}

function showFix(finding) {
  const confidenceNote = finding.confidence === "low"
    ? `<p class="fix-confidence">This file looks minified/bundled — treat this as a candidate to manually check, not a confirmed finding.</p>`
    : "";
  const plainLine = finding.plainSummary
    ? `<p class="fix-plain">${escapeHtml(finding.plainSummary)}</p>`
    : "";
  fixDetail.innerHTML = `
    <span class="fix-h">${escapeHtml(finding.title)} — ${finding.severity.toUpperCase()}</span>
    ${plainLine}
    ${confidenceNote}
    <p class="fix-why">${escapeHtml(finding.description)}</p>
    <p class="fix-how">FIX: ${escapeHtml(finding.fix)}</p>
    ${finding.snippet ? `<div class="fix-snippet">${escapeHtml(finding.snippet)}</div>` : ""}
  `;
}

function showCookieFix(finding) {
  const reasons = finding.reasons.map((r) => `<p class="fix-why">${escapeHtml(r)}</p>`).join("");
  const fixes = finding.fix.length
    ? finding.fix.map((f) => `<p class="fix-how">FIX: ${escapeHtml(f)}</p>`).join("")
    : "";
  fixDetail.innerHTML = `
    <span class="fix-h">${escapeHtml(finding.name)} (${escapeHtml(finding.domain)}) — ${finding.severity.toUpperCase()}</span>
    <p class="fix-plain">${escapeHtml(finding.headline)}</p>
    ${reasons}
    ${fixes}
    <div class="fix-snippet">HttpOnly: ${finding.flags.httpOnly} · Secure: ${finding.flags.secure} · SameSite: ${finding.flags.sameSite}</div>
  `;
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderReport(data) {
  clearLists();

  const { codeScan, cookieFindings } = data;
  const allFindings = codeScan.findings || [];

  // Third-party vendor code (Cloudflare, Google, Segment, etc.) isn't something
  // the site owner wrote or can fix directly — keep it out of the main
  // severity columns so the count there reflects this site's own code.
  const findings = allFindings.filter((f) => f.originType !== "third-party-vendor");
  const thirdPartyFindings = allFindings.filter((f) => f.originType === "third-party-vendor");

  const byCol = { critical: criticalList, medium: mediumList, low: lowList };
  const counts = { critical: 0, medium: 0, low: 0 };

  findings.forEach((f) => {
    renderCodeFinding(f, byCol[f.severity]);
    counts[f.severity]++;
    if (LOGICAL_FLAW_IDS.has(f.id)) {
      renderCodeFinding(f, logicalList);
    }
  });

  if (counts.critical === 0) criticalList.appendChild(emptyNote("No critical flaws found."));
  if (counts.medium === 0) mediumList.appendChild(emptyNote("No medium flaws found."));
  if (counts.low === 0) lowList.appendChild(emptyNote("No low-risk flaws found."));
  if (logicalList.children.length === 0) logicalList.appendChild(emptyNote("No logical-flow flaws found."));

  const sensitiveCookies = cookieFindings.filter((c) => c.severity !== "ok");
  if (sensitiveCookies.length === 0) {
    cookieList.appendChild(emptyNote("No sensitive/insecure cookies detected."));
  } else {
    sensitiveCookies
      .sort((a, b) => (a.severity === "critical" ? -1 : 1))
      .forEach(renderCookieFinding);
  }

  renderThirdPartySection(thirdPartyFindings);

  scanMeta.textContent =
    `Scanned ${codeScan.scannedInline} inline + ${codeScan.scannedExternal} external script(s)` +
    (codeScan.skippedExternal ? ` · ${codeScan.skippedExternal} external script(s) skipped (limit)` : "") +
    (thirdPartyFindings.length ? ` · ${thirdPartyFindings.length} third-party match(es) excluded from severity counts` : "") +
    ` · ${cookieFindings.length} cookie(s) checked · ${data.url}`;

  reportEl.classList.remove("hidden");
}

function renderThirdPartySection(thirdPartyFindings) {
  let section = document.getElementById("thirdPartySection");
  if (!section) {
    section = document.createElement("section");
    section.id = "thirdPartySection";
    section.className = "third-party-section";
    scanMeta.parentNode.insertBefore(section, scanMeta);
  }
  section.innerHTML = "";

  if (thirdPartyFindings.length === 0) {
    section.classList.add("hidden");
    return;
  }
  section.classList.remove("hidden");

  const header = document.createElement("h2");
  header.textContent = `THIRD-PARTY CODE (${thirdPartyFindings.length}) — informational only`;
  section.appendChild(header);

  const note = document.createElement("p");
  note.className = "third-party-note";
  note.textContent = "Patterns found inside vendor scripts (Cloudflare, Google, etc.) you don't control or write. Not counted as this site's own flaws.";
  section.appendChild(note);

  const list = document.createElement("div");
  list.className = "finding-list";
  thirdPartyFindings.slice(0, 10).forEach((f) => renderCodeFinding(f, list));
  section.appendChild(list);
}

scanBtn.addEventListener("click", () => {
  scanBtn.disabled = true;
  statusEl.textContent = "Scanning page JS and cookies...";

  chrome.runtime.sendMessage({ type: "RUN_FULL_AUDIT" }, (response) => {
    scanBtn.disabled = false;
    if (!response || response.error) {
      statusEl.textContent = `Error: ${response ? response.error : "no response"}`;
      return;
    }
    statusEl.textContent = "Scan complete.";
    renderReport(response);
  });
});