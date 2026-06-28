// background.js
//
// This service worker is the actual "blocking engine." It does not run on a
// timer or watch network traffic itself — instead it reacts whenever the
// blocklist in chrome.storage.local changes, and rebuilds the set of
// declarativeNetRequest rules to match. The browser engine enforces the
// rules natively, so blocking is instant and happens before any DNS lookup.

const STORAGE_KEY = "blockedDomains";

const RESOURCE_TYPES = [
  "main_frame",
  "sub_frame",
  "script",
  "xmlhttprequest",
  "image",
  "stylesheet",
  "font",
  "object",
  "media",
  "websocket",
  "other",
];

async function rebuildRules() {
  const stored = await chrome.storage.local.get(STORAGE_KEY);
  const domains = stored[STORAGE_KEY] || [];

  // Always start clean: pull whatever dynamic rules currently exist and
  // remove them, then add a fresh rule per domain. This keeps rule IDs
  // simple and avoids drift between storage and the live ruleset.
  const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existingRules.map((rule) => rule.id);

  const addRules = domains.map((domain, index) => ({
    id: index + 1,
    priority: 1,
    action: { type: "block" },
    condition: {
      // "||domain^" matches the domain itself and any subdomain, on any
      // scheme/port, the same filter syntax used by Adblock-style lists.
      urlFilter: `||${domain}^`,
      resourceTypes: RESOURCE_TYPES,
    },
  }));

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds,
    addRules,
  });
}

// Recompute rules whenever the popup edits the blocklist.
chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === "local" && changes[STORAGE_KEY]) {
    rebuildRules();
  }
});

// Recompute on browser start and on install/update, in case the dynamic
// ruleset didn't survive a restart.
chrome.runtime.onStartup.addListener(rebuildRules);
chrome.runtime.onInstalled.addListener(rebuildRules);