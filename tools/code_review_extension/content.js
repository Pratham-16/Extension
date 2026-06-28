/**
 * content.js
 * ----------
 * Runs in the page context. Collects:
 *  - inline <script> blocks (no src attribute)
 *  - external script sources, fetched best-effort (same-origin or CORS-permitting)
 * Then runs them through analyzeSource() from analyzer.js and reports
 * results back to the popup / background on request.
 */

(function () {
  const MAX_EXTERNAL_SCRIPTS = 15; // avoid hammering the page with fetches
  const FETCH_TIMEOUT_MS = 4000;

  // Hostnames that are well-known third-party infrastructure/vendor domains.
  // Code served from these is not something the site's own developers wrote
  // or can directly fix — flagging it as "this site's flaw" is misleading.
  const KNOWN_THIRD_PARTY_HOSTS = [
    /(^|\.)cloudflareinsights\.com$/,
    /(^|\.)cloudflare\.com$/,
    /(^|\.)googletagmanager\.com$/,
    /(^|\.)google-analytics\.com$/,
    /(^|\.)googleapis\.com$/,
    /(^|\.)gstatic\.com$/,
    /(^|\.)doubleclick\.net$/,
    /(^|\.)facebook\.net$/,
    /(^|\.)segment\.(io|com)$/,
    /(^|\.)intercom(cdn)?\.(io|com)$/,
    /(^|\.)stripe\.com$/,
    /(^|\.)hotjar\.com$/,
    /(^|\.)cdn\.jsdelivr\.net$/,
    /(^|\.)unpkg\.com$/,
    /(^|\.)jquery\.com$/
  ];

  // Path patterns that indicate vendor-injected code even when served from the
  // site's own domain — e.g. Cloudflare injects /cdn-cgi/ scripts on the
  // customer's own hostname; that's still Cloudflare's code, not the site's.
  const KNOWN_THIRD_PARTY_PATH_PATTERNS = [/\/cdn-cgi\//];

  function classifyOrigin(scriptUrl) {
    try {
      const url = new URL(scriptUrl, location.href);
      const sameHost = url.hostname === location.hostname;
      const isKnownThirdPartyHost = KNOWN_THIRD_PARTY_HOSTS.some((p) => p.test(url.hostname));
      const isKnownThirdPartyPath = KNOWN_THIRD_PARTY_PATH_PATTERNS.some((p) => p.test(url.pathname));

      if (isKnownThirdPartyHost || isKnownThirdPartyPath) return "third-party-vendor";
      if (!sameHost) return "third-party-other";
      return "first-party";
    } catch (e) {
      return "unknown";
    }
  }

  function fetchWithTimeout(url, ms) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), ms);
    return fetch(url, { signal: controller.signal })
      .then((res) => (res.ok ? res.text() : null))
      .catch(() => null)
      .finally(() => clearTimeout(timer));
  }

  async function collectAndAnalyze() {
    const scripts = Array.from(document.querySelectorAll("script"));
    const inlineBlocks = scripts.filter((s) => !s.src && s.textContent.trim().length > 0);
    const externalScripts = scripts.filter((s) => !!s.src).slice(0, MAX_EXTERNAL_SCRIPTS);

    let allFindings = [];

    // Inline scripts are always first-party — they're written directly into
    // this page's own HTML by whoever built the site (or injected by a
    // vendor's own inline snippet, which we can't fully distinguish here,
    // but the common case for inline blocks is first-party app code).
    inlineBlocks.forEach((s, i) => {
      const origin = `inline script #${i + 1}`;
      const findings = window.__auditorAnalyzeSource(s.textContent, origin);
      findings.forEach((f) => (f.originType = "first-party"));
      allFindings = allFindings.concat(findings);
    });

    // External scripts: classify by hostname/path before analyzing, so
    // third-party vendor code (Cloudflare, Google, Segment, etc.) can be
    // shown separately rather than mixed in with the site's own flaws.
    const fetches = externalScripts.map(async (s) => {
      const originType = classifyOrigin(s.src);
      const text = await fetchWithTimeout(s.src, FETCH_TIMEOUT_MS);
      if (text) {
        const findings = window.__auditorAnalyzeSource(text, s.src);
        findings.forEach((f) => (f.originType = originType));
        allFindings = allFindings.concat(findings);
      }
    });

    await Promise.all(fetches);

    const skippedExternal = scripts.filter((s) => !!s.src).length - externalScripts.length;

    return {
      url: location.href,
      scannedInline: inlineBlocks.length,
      scannedExternal: externalScripts.length,
      skippedExternal: Math.max(0, skippedExternal),
      findings: allFindings
    };
  }

  // Listen for the popup asking us to run the scan
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg && msg.type === "RUN_CODE_SCAN") {
      collectAndAnalyze().then((result) => sendResponse(result));
      return true; // keep the message channel open for the async response
    }
  });
})();