/**
 * analyzer.js
 * -----------
 * v1 flaw-detection engine. Pattern-based (regex over source text),
 * scoped per <script> block. Each rule returns 0+ findings.
 *
 * Finding shape:
 * {
 *   id: string,            // stable rule id, e.g. "EVAL_USE"
 *   severity: "critical" | "medium" | "low",
 *   title: string,         // short human label
 *   description: string,  // why this is a flaw
 *   fix: string,           // recommended fix, plain language
 *   snippet: string,       // the matched line/snippet (truncated)
 *   line: number | null    // best-effort line number within the script block
 * }
 */

const RULES = [
  // ---------- CRITICAL ----------
  {
    id: "EVAL_USE",
    severity: "critical",
    title: "Use of eval()",
    plainSummary: "Page can run text as live code",
    pattern: /\beval\s*\(/g,
    description: "eval() executes arbitrary strings as code. If any part of the argument can be influenced by user input or URL data, this is a direct code-execution flaw.",
    fix: "Remove eval(). If you need to parse data, use JSON.parse(). If you need dynamic logic, use a lookup table/switch instead of building code as a string."
  },
  {
    id: "NEW_FUNCTION",
    severity: "critical",
    title: "Dynamic function construction (new Function)",
    plainSummary: "Page builds and runs code from a string",
    pattern: /\bnew\s+Function\s*\(/g,
    description: "new Function() compiles a string into executable code, the same risk class as eval(). Common in obfuscated or injected payloads.",
    fix: "Avoid constructing functions from strings. Refactor to a named function or a data-driven dispatch table."
  },
  {
    id: "INNERHTML_ASSIGN",
    severity: "critical",
    title: "Unsanitized innerHTML assignment",
    plainSummary: "Page can inject raw HTML without checking it",
    pattern: /\.innerHTML\s*=(?!=)/g,
    description: "Assigning to innerHTML renders raw HTML/JS. If the right-hand side includes any unsanitized input (URL params, API responses, form fields), this is a DOM-based XSS sink.",
    fix: "Use .textContent for plain text, or sanitize HTML with DOMPurify before assigning to innerHTML."
  },
  {
    id: "DOCUMENT_WRITE",
    severity: "critical",
    title: "document.write() usage",
    plainSummary: "Page writes raw HTML directly into itself",
    pattern: /\bdocument\.write\s*\(/g,
    description: "document.write() injects raw markup into the page at parse time. It's a classic XSS sink and also blocks rendering.",
    fix: "Replace with DOM APIs (createElement/appendChild) or template rendering. Never feed it dynamic/user-influenced strings."
  },
  {
    id: "HARDCODED_SECRET",
    severity: "critical",
    title: "Possible hardcoded credential or API key",
    plainSummary: "A password or API key may be exposed in the code",
    // Requires a clear secret-style key name as the FULL identifier (not a substring match
    // inside a longer minified name) and a high-entropy-looking value (mixed case + digits,
    // not just any 12+ char string — cuts down on matching hashes/locale codes/css classes).
    pattern: /\b(api[_-]?key|apikey|secret|secretkey|password|access[_-]?token|auth[_-]?token)\s*[:=]\s*["'`](?=[^"'`]*[A-Z])(?=[^"'`]*[a-z])(?=[^"'`]*\d)[A-Za-z0-9_\-\/+=]{16,}["'`]/gi,
    description: "A string matching common secret-naming patterns is hardcoded directly in client-side JS. Anything shipped to the browser is fully visible to any visitor.",
    fix: "Move the secret server-side. Client code should call your backend, which holds the credential, never the browser."
  },
  {
    id: "AUTH_DEAD_CODE",
    severity: "critical",
    title: "Unreachable code after return in auth-related function",
    plainSummary: "A login/permission check may never actually run",
    pattern: /return[^;]*;[\s\S]{0,3}\n\s*(if|else)\b[\s\S]{0,80}(auth|login|permission|role|admin)/gi,
    description: "Code referencing auth/role/permission checks appears immediately after a return statement in the same block, meaning it never executes. This often happens when a check is 'temporarily' disabled and forgotten.",
    fix: "Review the control flow. If the auth check is meant to run, move it before the return. If it's intentionally disabled, remove the dead code rather than leaving it as a false sense of security."
  },

  // ---------- MEDIUM ----------
  {
    id: "LOCALSTORAGE_TOKEN",
    severity: "medium",
    title: "Token-like value stored in localStorage/sessionStorage",
    plainSummary: "Login token stored where any script can read it",
    pattern: /(localStorage|sessionStorage)\.setItem\s*\(\s*["'`](?:[^"'`]*?(token|jwt|auth|session)[^"'`]*?)["'`]/gi,
    description: "Web Storage is readable by any JS on the page, including injected XSS payloads. Storing session/auth tokens here removes the HttpOnly protection a cookie would have.",
    fix: "Store session tokens in an HttpOnly, Secure, SameSite cookie instead, so client-side JS (and XSS payloads) can't read them."
  },
  {
    id: "EMPTY_CATCH",
    severity: "medium",
    title: "Empty catch block",
    plainSummary: "Errors are silently ignored instead of handled",
    pattern: /catch\s*\([^)]*\)\s*\{\s*\}/g,
    description: "Errors are being silently swallowed. If this wraps a security-relevant operation (auth check, signature verification, permission lookup), a failure could be silently treated as success.",
    fix: "At minimum, log the error. If this catch guards a security check, ensure the failure path denies access rather than falling through."
  },
  {
    id: "WEAK_RANDOM_TOKEN",
    severity: "medium",
    title: "Math.random() used for token/ID-like value",
    plainSummary: "Token/ID may be guessable, not truly random",
    pattern: /(token|id|session|nonce|csrf)\s*=\s*[^;\n]*Math\.random\(/gi,
    description: "Math.random() is not cryptographically secure and can be predictable. Using it for session IDs, tokens, or CSRF nonces makes them guessable.",
    fix: "Use crypto.getRandomValues() (browser) or a server-side CSPRNG for anything security-relevant."
  },
  {
    id: "TARGET_BLANK_NO_NOOPENER",
    severity: "medium",
    title: "target=\"_blank\" without rel=\"noopener\"",
    plainSummary: "Opened links can manipulate the original page",
    pattern: /target\s*=\s*["']_blank["'](?![^>]*rel\s*=\s*["'][^"']*noopener)/gi,
    description: "Links opened with target=\"_blank\" without rel=\"noopener\" let the new page access window.opener, enabling reverse-tabnabbing attacks.",
    fix: "Add rel=\"noopener noreferrer\" to any target=\"_blank\" link or dynamically created window."
  },
  {
    id: "FETCH_DYNAMIC_URL",
    severity: "medium",
    title: "fetch()/XHR called with a concatenated/dynamic URL",
    plainSummary: "A network request URL is built in a risky way",
    pattern: /fetch\s*\(\s*[^"'`)][^)]*\+[^)]*\)/g,
    description: "The request URL is being built via string concatenation rather than a fixed string or properly encoded parameter. If any part comes from user input, this can lead to SSRF or IDOR (accessing another user's resource by altering an ID).",
    fix: "Validate and allow-list any user-influenced part of the URL. Prefer encodeURIComponent() for inserted values and check authorization server-side regardless of what the client requests."
  },

  // ---------- LOW ----------
  {
    id: "CONSOLE_LOG_SENSITIVE",
    severity: "low",
    title: "console.log of a variable with a sensitive-sounding name",
    plainSummary: "A token or password may be printed to the console",
    pattern: /console\.(log|debug|info)\s*\([^)]*(token|password|secret|session|auth)[^)]*\)/gi,
    description: "Logging sensitive-looking variables leaves them visible in browser DevTools and can leak into error-tracking tools (Sentry, LogRocket) that capture console output.",
    fix: "Remove sensitive values from console output, or scrub/mask them before logging."
  },
  {
    id: "HTTP_HARDCODED_URL",
    severity: "low",
    title: "Hardcoded http:// (non-TLS) URL",
    plainSummary: "A request uses an unencrypted (non-HTTPS) link",
    // Excludes well-known non-network URI patterns that aren't actually outgoing
    // requests: XML/SVG namespaces, W3C schema URIs, and DTD references.
    pattern: /["'`]http:\/\/(?!localhost|127\.0\.0\.1|www\.w3\.org|schemas\.|xml\.org)[^"'`]{6,}["'`]/g,
    description: "A request or resource is hardcoded to plain HTTP rather than HTTPS, exposing it to network interception/tampering.",
    fix: "Use https:// for all non-local endpoints."
  },
  {
    id: "DEBUGGER_STATEMENT",
    severity: "low",
    title: "debugger statement left in code",
    plainSummary: "Leftover debug code from development",
    pattern: /\bdebugger\s*;/g,
    description: "A debugger statement was left in shipped code. Not a vulnerability by itself, but a sign of incomplete cleanup before deployment.",
    fix: "Remove debugger statements before shipping to production."
  }
];

// A file is treated as "minified" if its average line length is large.
// Hand-written/served-readable source rarely exceeds ~300 chars/line;
// bundlers/minifiers routinely produce single lines of 10k+ chars.
const MINIFIED_AVG_LINE_LENGTH = 300;

// Below this total length, don't apply minification logic at all — a short
// inline snippet (e.g. a small vendor IIFE) can be one long line without
// being a multi-thousand-line bundle, and the per-rule cap isn't needed
// when only a handful of matches are even possible.
const MINIFICATION_MIN_TOTAL_LENGTH = 2000;

// Cap how many findings a single rule can contribute per file. Minified
// bundles can match a noisy pattern dozens of times on what is really
// one region of code — past this cap we still count them, but stop
// emitting near-duplicate entries.
const MAX_FINDINGS_PER_RULE_PER_FILE = 3;

function detectMinified(source) {
  if (source.length < MINIFICATION_MIN_TOTAL_LENGTH) return false;
  const lines = source.split("\n");
  const avgLineLength = source.length / Math.max(1, lines.length);
  return avgLineLength > MINIFIED_AVG_LINE_LENGTH;
}

// Shortens a long script URL down to just the filename for compact display,
// keeping the full origin available separately for the detail view.
function shortenOrigin(origin) {
  if (!origin) return origin;
  if (origin.startsWith("inline")) return origin;
  try {
    const url = new URL(origin);
    const parts = url.pathname.split("/").filter(Boolean);
    return parts.length ? parts[parts.length - 1] : origin;
  } catch (e) {
    return origin;
  }
}

/**
 * Scans a single block of JS source text and returns findings.
 * @param {string} source - raw JS text
 * @param {string} origin - where this code came from (e.g. "inline#3", "https://cdn.example.com/app.js")
 */
function analyzeSource(source, origin) {
  const findings = [];
  if (!source || typeof source !== "string") return findings;

  const isMinified = detectMinified(source);
  const shortOrigin = shortenOrigin(origin);

  for (const rule of RULES) {
    // Reset regex state since RULES objects are reused across calls (global flag keeps lastIndex)
    rule.pattern.lastIndex = 0;
    let match;
    let ruleMatchCount = 0;
    let ruleSuppressedCount = 0;

    while ((match = rule.pattern.exec(source)) !== null) {
      ruleMatchCount++;

      const idx = match.index;
      const snippetStart = Math.max(0, idx - 20);
      const snippetEnd = Math.min(source.length, idx + match[0].length + 40);
      const snippet = source.slice(snippetStart, snippetEnd).trim().replace(/\s+/g, " ");

      // Zero-length match guard before any early continue, so we never loop forever
      if (match[0].length === 0) rule.pattern.lastIndex++;

      if (isMinified && ruleMatchCount > MAX_FINDINGS_PER_RULE_PER_FILE) {
        ruleSuppressedCount++;
        continue;
      }

      findings.push({
        id: rule.id,
        severity: rule.severity,
        title: rule.title,
        plainSummary: rule.plainSummary,
        description: rule.description,
        fix: rule.fix,
        snippet: snippet.length > 140 ? snippet.slice(0, 140) + "…" : snippet,
        line: isMinified ? null : source.slice(0, idx).split("\n").length,
        charOffset: isMinified ? idx : null,
        confidence: isMinified ? "low" : "normal",
        origin,
        shortOrigin
      });
    }

    if (ruleSuppressedCount > 0) {
      findings.push({
        id: rule.id + "_SUPPRESSED",
        severity: rule.severity,
        title: `${rule.title} — ${ruleSuppressedCount} more match(es) hidden`,
        plainSummary: `${ruleSuppressedCount} more matches of the same issue in this file`,
        description: `This minified file matched "${rule.title}" ${ruleMatchCount} times total. Showing the first ${MAX_FINDINGS_PER_RULE_PER_FILE}; the rest are very likely repeats of the same pattern across a bundled file, not independent flaws.`,
        fix: rule.fix,
        snippet: "",
        line: null,
        charOffset: null,
        confidence: "low",
        origin,
        shortOrigin,
        isSummary: true
      });
    }
  }
  return findings;
}

// Expose to content.js (both run in the same content-script world)
if (typeof window !== "undefined") {
  window.__auditorAnalyzeSource = analyzeSource;
}