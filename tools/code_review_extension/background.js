/**
 * background.js
 * -------------
 * MV3 background script (works as a service worker in Chrome, and as a
 * background script in Firefox). Responsibilities:
 *  - Fetch all cookies for the active tab's domain via chrome.cookies API
 *  - Score them using the inlined cookie-rules logic below
 *  - Relay "run code scan" requests to the content script in the active tab
 *  - Combine both results and send back to the popup
 *
 * NOTE: cookie-rules.js logic is inlined directly here (rather than loaded
 * via importScripts) because importScripts is a service-worker-only API.
 * Firefox runs this file as a background script, not a worker, so
 * importScripts is unavailable there — inlining avoids the cross-browser
 * loading mismatch entirely.
 */

// ---------- cookie risk scoring (inlined from cookie-rules.js) ----------

// Cookie name patterns that genuinely suggest app-level session/auth state.
// Tightened from v1: word-boundary anchored, and deliberately narrower so
// vendor-prefixed analytics IDs (ajs_anonymous_id, anthropic-device-id) don't
// substring-match on "sid"/"id"/"auth" inside an unrelated name.
const SENSITIVE_NAME_PATTERNS = [
  /^session(id)?$/i, /^sess[_-]?id$/i, /sessionkey/i, /sessiontoken/i,
  /^auth[_-]?token$/i, /^access[_-]?token$/i, /^refresh[_-]?token$/i,
  /^jwt$/i, /^api[_-]?key$/i, /^csrf[_-]?token$/i, /^xsrf[_-]?token$/i,
  /activitysession/i, /loginsession/i
];

// Known third-party vendor cookies that are well-documented, vendor-managed,
// and not something this app's own session security depends on. We still
// surface them (so the person can see what's being set), but we don't treat
// high entropy on these as "looks like a stolen-session token."
// Matched by exact name or simple prefix against cookie.name.
const KNOWN_VENDOR_COOKIES = [
  // Segment analytics
  { match: /^ajs_anonymous_id$/i, vendor: "Segment", note: "Anonymous analytics ID, not an auth session." },
  { match: /^ajs_user_id$/i, vendor: "Segment", note: "Analytics user identifier, not an auth session." },
  // Google Identity Services
  { match: /^g_state$/i, vendor: "Google Identity Services", note: "Client-side Google Sign-In UI state, not your app's session." },
  // Datadog RUM
  { match: /^_dd_s$/i, vendor: "Datadog RUM", note: "Session-replay/monitoring cookie, not an app auth session." },
  // Cloudflare
  { match: /^(__cf_bm|cf_clearance|__cfruid)$/i, vendor: "Cloudflare", note: "Bot-management/anti-abuse cookie set by Cloudflare, not app-controlled." },
  { match: /^_cfuvid$/i, vendor: "Cloudflare", note: "Cloudflare rate-limiting support cookie." },
  // Stripe
  { match: /^__stripe_(mid|sid)$/i, vendor: "Stripe", note: "Stripe fraud-detection identifier, required by Stripe's own PCI-relevant flows." },
  // Google Ads / Analytics
  { match: /^_gcl_au$/i, vendor: "Google Ads", note: "Conversion-linking cookie for Google Ads, not an auth session." },
  { match: /^_ga(_[A-Z0-9]+)?$/i, vendor: "Google Analytics", note: "Analytics visitor identifier, not an auth session." },
  // Intercom
  { match: /^intercom-(device-id|session)-/i, vendor: "Intercom", note: "Support-widget device/session identifier, not your app's own auth session." },
  // Generic device/telemetry id naming used by many SaaS products
  { match: /device[_-]?id/i, vendor: "Device/telemetry", note: "Device identifier used for analytics/fraud-signals, not an auth session by itself." },
  { match: /consent[_-]?preferences?/i, vendor: "Consent management", note: "Stores cookie/consent banner choices, not sensitive account data." }
];

function matchKnownVendor(name) {
  return KNOWN_VENDOR_COOKIES.find((v) => v.match.test(name)) || null;
}

const JWT_PATTERN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

function looksLikeJwt(value) {
  return JWT_PATTERN.test(value);
}

function decodeJwtPayload(value) {
  try {
    const parts = value.split(".");
    const payload = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const decoded = atob(payload + "===".slice((payload.length + 3) % 4));
    return JSON.parse(decoded);
  } catch (e) {
    return null;
  }
}

function looksLikeBase64Json(value) {
  if (value.length < 8) return false;
  try {
    const decoded = atob(value);
    JSON.parse(decoded);
    return true;
  } catch (e) {
    return false;
  }
}

function estimateEntropy(value) {
  if (!value || value.length < 4) return 0;
  const freq = {};
  for (const ch of value) freq[ch] = (freq[ch] || 0) + 1;
  let entropy = 0;
  for (const ch in freq) {
    const p = freq[ch] / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function scoreCookie(cookie) {
  const reasons = [];
  const fix = [];
  let severity = "low";

  const knownVendor = matchKnownVendor(cookie.name);
  const nameLooksSensitive = !knownVendor && SENSITIVE_NAME_PATTERNS.some((p) => p.test(cookie.name));
  const isJwt = looksLikeJwt(cookie.value);
  const isBase64Json = !isJwt && looksLikeBase64Json(cookie.value);
  const entropy = estimateEntropy(cookie.value);
  // Known-vendor cookies never get the "looks like a session token" treatment
  // purely from entropy — that heuristic is what mismatched analytics/telemetry
  // IDs as critical session tokens in v1.
  const looksLikeSessionToken =
    !knownVendor && (nameLooksSensitive || isJwt || (entropy > 3.5 && cookie.value.length >= 16));


  if (looksLikeSessionToken && !cookie.httpOnly) {
    reasons.push("Missing HttpOnly — readable by page JavaScript, so any XSS can steal it.");
    fix.push("Set the HttpOnly flag so client-side JS cannot read this cookie.");
    severity = "critical";
  }

  if (!cookie.secure) {
    reasons.push("Missing Secure — can be sent over plain HTTP and intercepted on the network.");
    fix.push("Set the Secure flag so it's only sent over HTTPS.");
    if (looksLikeSessionToken) severity = "critical";
    else if (severity !== "critical") severity = "medium";
  }

  if (!cookie.sameSite || cookie.sameSite === "no_restriction" || cookie.sameSite === "unspecified") {
    reasons.push("Missing/weak SameSite — vulnerable to cross-site request forgery (CSRF).");
    fix.push("Set SameSite=Strict or Lax, depending on whether cross-site navigation needs to carry it.");
    if (looksLikeSessionToken && severity !== "critical") severity = "medium";
  }

  if (cookie.session === false && cookie.expirationDate) {
    const daysUntilExpiry = (cookie.expirationDate - Date.now() / 1000) / 86400;
    if (looksLikeSessionToken && daysUntilExpiry > 30) {
      reasons.push(`Long-lived session token — expires in ~${Math.round(daysUntilExpiry)} days, widening the window an attacker can reuse a stolen token.`);
      fix.push("Shorten session token lifetime; use short-lived access tokens plus a separate refresh-token flow if long sessions are needed.");
      if (severity === "low") severity = "medium";
    }
  }

  if (isJwt) {
    const payload = decodeJwtPayload(cookie.value);
    if (payload) {
      const exposedKeys = Object.keys(payload).filter((k) =>
        /role|admin|email|user|perm|scope/i.test(k)
      );
      if (exposedKeys.length > 0) {
        reasons.push(`JWT payload is readable without breaking encryption and exposes: ${exposedKeys.join(", ")}.`);
        fix.push("Treat JWT payloads as visible, not secret — never put data there you wouldn't show the user directly. Keep authorization decisions server-side.");
        if (severity === "low") severity = "medium";
      }
    }
  } else if (isBase64Json) {
    reasons.push("Cookie value is base64-encoded JSON, readable by anyone without needing to break any encryption.");
    fix.push("Avoid storing structured/sensitive data client-side in a reversible encoding. Store an opaque session ID and keep the data server-side.");
    if (severity === "low") severity = "medium";
  }

  if (nameLooksSensitive && entropy < 2.5 && cookie.value.length < 16) {
    reasons.push("Token-like cookie has low entropy / short length — may be predictable or sequential.");
    fix.push("Use a cryptographically random value of at least 128 bits for session identifiers.");
    if (severity === "low") severity = "medium";
  }

  // Vendor-managed cookies are not app session tokens — cap their ceiling at
  // "low" regardless of which attribute checks fired above. A SameSite/Secure
  // gap on a known analytics cookie is a real but minor flag, not the same
  // risk class as a gap on an actual session/auth cookie.
  if (knownVendor && severity !== "low") {
    severity = "low";
  }

  if (reasons.length === 0) {
    if (knownVendor) {
      reasons.push(`Identified as a ${knownVendor.vendor} cookie. ${knownVendor.note} No attribute issues detected.`);
    } else {
      reasons.push("No issues detected with current checks.");
    }
  } else if (knownVendor) {
    reasons.unshift(`Identified as a ${knownVendor.vendor} cookie. ${knownVendor.note}`);
  }

  // A short plain-language headline for the card itself, so the person doesn't
  // have to click in just to find out what's wrong. Picks the single most
  // important issue rather than listing everything. Vendor cookies get their
  // own framing first since they're never session-critical by definition here.
  let headline;
  if (knownVendor && reasons.length <= 1) {
    headline = `Third-party (${knownVendor.vendor}) — low risk to your app`;
  } else if (knownVendor) {
    headline = `Third-party (${knownVendor.vendor}), minor attribute gap — low risk to your app`;
  } else if (!cookie.httpOnly && looksLikeSessionToken) {
    headline = "Session cookie can be stolen via XSS (no HttpOnly)";
  } else if (!cookie.secure && looksLikeSessionToken) {
    headline = "Session cookie can be sent over plain HTTP (no Secure)";
  } else if (isJwt && reasons.some((r) => r.includes("JWT payload"))) {
    headline = "Token reveals role/email without decryption";
  } else if (isBase64Json) {
    headline = "Cookie value is readable without decryption";
  } else if (!cookie.sameSite || cookie.sameSite === "no_restriction" || cookie.sameSite === "unspecified") {
    headline = "Vulnerable to cross-site request forgery (no SameSite)";
  } else if (reasons.some((r) => r.includes("Long-lived"))) {
    headline = "Long-lived session — stays valid for months";
  } else {
    headline = "No issues detected";
  }

  return {
    name: cookie.name,
    domain: cookie.domain,
    path: cookie.path,
    severity: !knownVendor && reasons.length === 1 && reasons[0].startsWith("No issues") ? "ok" : severity,
    headline,
    reasons,
    fix,
    looksLikeSessionToken,
    vendor: knownVendor ? knownVendor.vendor : null,
    flags: {
      httpOnly: cookie.httpOnly,
      secure: cookie.secure,
      sameSite: cookie.sameSite
    }
  };
}

function scoreAllCookies(cookies) {
  return cookies.map(scoreCookie);
}

// ---------- audit orchestration ----------

function getCookiesForUrl(url) {
  return chrome.cookies.getAll({ url });
}

async function runFullAudit(tabId, url) {
  const [cookies, codeScanResult] = await Promise.all([
    getCookiesForUrl(url),
    chrome.tabs.sendMessage(tabId, { type: "RUN_CODE_SCAN" }).catch(() => null)
  ]);

  const cookieFindings = scoreAllCookies(cookies || []);

  return {
    url,
    cookieFindings,
    codeScan: codeScanResult || {
      url,
      scannedInline: 0,
      scannedExternal: 0,
      skippedExternal: 0,
      findings: [],
      error: "Could not reach content script on this page (try reloading the tab)."
    }
  };
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.type === "RUN_FULL_AUDIT") {
    chrome.tabs.query({ active: true, currentWindow: true }).then(async ([tab]) => {
      if (!tab || !tab.id || !tab.url) {
        sendResponse({ error: "No active tab found." });
        return;
      }
      try {
        const result = await runFullAudit(tab.id, tab.url);
        sendResponse(result);
      } catch (err) {
        sendResponse({ error: String(err) });
      }
    });
    return true; // keep the message channel open for the async response
  }
});