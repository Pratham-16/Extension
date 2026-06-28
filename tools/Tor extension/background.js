// background.js
const NATIVE_HOST = "com.b14ckwolf.tormode";
const STATUS_KEY = "torStatus";
let nativePort = null;

const browserEngine = typeof browser !== "undefined" ? browser : chrome;

function getNativePort() {
  if (!nativePort) {
    nativePort = browserEngine.runtime.connectNative(NATIVE_HOST);
    nativePort.onMessage.addListener(onNativeMessage);
    nativePort.onDisconnect.addListener(() => {
      const err = browserEngine.runtime.lastError;
      if (err) {
        broadcastStatus({
          phase: "error",
          error: `Couldn't reach the native host (${err.message}). Did you run native-host/install.sh?`,
        });
      }
      nativePort = null;
    });
  }
  return nativePort;
}

async function broadcastStatus(status) {
  await browserEngine.storage.local.set({ [STATUS_KEY]: status });
}

// Universal configuration injector handling both Gecko (Firefox) and Chromium scoping rules
async function applySocksProxy() {
  const isFirefox = typeof browser !== "undefined" && typeof browser.proxy !== "undefined";

  try {
    if (isFirefox) {
      // Manual proxy config — same shape Firefox's own preferences UI writes
      // when you pick "Manual proxy configuration" by hand.
      await browser.proxy.settings.set({
        value: {
          proxyType: "manual",
          socks: "127.0.0.1:9050",
          socksVersion: 5,
          proxyDNS: true, // resolve hostnames through the SOCKS proxy too (no DNS leak)
          passthrough: "localhost, 127.0.0.1, <local>"
        },
        scope: "regular"
      });
    } else {
      // Standard fixed server definition array layout for Chrome/Brave runtimes
      const chromeConfig = {
        mode: "fixed_servers",
        rules: {
          singleProxy: { scheme: "socks5", host: "127.0.0.1", port: 9050 },
          bypassList: ["localhost", "127.0.0.1", "<local>"]
        }
      };
      chrome.proxy.settings.set({ value: chromeConfig, scope: "regular" });
    }
    console.log("SOCKS5 Proxy rule injection sequence finalized successfully.");
  } catch (err) {
    console.error("Proxy execution failure:", err);
    const friendly = /private browsing permission/i.test(err.message)
      ? "Tor Mode needs private-browsing access to change your proxy. Go to about:addons → Tor Mode → set 'Run in Private Windows' to Allow, then toggle again."
      : `Proxy Error: ${err.message}`;
    broadcastStatus({ phase: "error", error: friendly });
  }
}

async function clearProxy() {
  try {
    await browserEngine.proxy.settings.clear({ scope: "regular" });
    console.log("Proxy routing settings cleanly cleared.");
  } catch (err) {
    // Fallback block if clean wrapper throws runtime scope drops
    if (typeof chrome !== "undefined" && chrome.proxy) {
      chrome.proxy.settings.clear({ scope: "regular" });
    }
  }
}

async function onNativeMessage(message) {
  await broadcastStatus(message);
  if (message.phase === "started" && message.tor_active && message.socks_port_open) {
    await applySocksProxy();
    await broadcastStatus({ ...message, proxyApplied: true });
  }
  if (message.phase === "stopped") {
    await clearProxy();
    await broadcastStatus({ ...message, proxyApplied: false });
  }
}

browserEngine.runtime.onMessage.addListener((msg) => {
  if (msg.action === "enable") {
    broadcastStatus({ phase: "progress", step: "Sending start request" });
    getNativePort().postMessage({ action: "start" });
  } else if (msg.action === "disable") {
    broadcastStatus({ phase: "progress", step: "Sending stop request" });
    getNativePort().postMessage({ action: "stop" });
  } else if (msg.action === "refresh") {
    getNativePort().postMessage({ action: "status" });
  }
});