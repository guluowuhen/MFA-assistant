const PERIOD = 30;
const DIGITS = 6;
const AUTO_CLOSE_ENABLED = true;
const AUTO_CLOSE_STABLE_MS = 1500;

const MFA_SYSTEMS_KEY = "mfaSystems";
const OVERRIDES_STORAGE_KEY = "mfaSecretOverrides";

function parseUrlParts(rawUrl) {
  try {
    const url = new URL(rawUrl, location.origin);
    return {
      origin: url.origin.toLowerCase(),
      path: url.pathname.replace(/\/+$/, "").toLowerCase()
    };
  } catch {
    return null;
  }
}

function looksLikeMfaInput(element) {
  if (!element || element.tagName !== "INPUT") return false;

  const attrs = [
    element.name,
    element.id,
    element.placeholder,
    element.getAttribute("aria-label"),
    element.autocomplete
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  const keywords = ["otp", "mfa", "2fa", "verify", "token", "auth", "one-time"];
  if (keywords.some((word) => attrs.includes(word))) return true;

  return element.type === "tel" || element.inputMode === "numeric";
}

function isLikelyMfaForm(form) {
  if (!(form instanceof HTMLFormElement)) return false;
  const inputs = form.querySelectorAll("input");
  for (const input of inputs) {
    if (looksLikeMfaInput(input)) return true;
  }
  return false;
}

function hasMfaInputHint() {
  const selectors = [
    "input[autocomplete='one-time-code']",
    "input[name*='otp' i]",
    "input[id*='otp' i]",
    "input[name*='mfa' i]",
    "input[id*='mfa' i]",
    "input[name*='verify' i]",
    "input[id*='verify' i]",
    "input[name*='token' i]",
    "input[id*='token' i]"
  ];

  return selectors.some((selector) => document.querySelector(selector));
}

function isLikelyAuthPage() {
  const raw = `${location.pathname} ${location.search} ${document.title}`.toLowerCase();
  const authWords = ["login", "signin", "sso", "auth", "mfa", "otp", "2fa", "verify", "token"];
  return authWords.some((word) => raw.includes(word));
}

function shouldAutoCloseWidget() {
  return !hasMfaInputHint() && !isLikelyAuthPage();
}

async function loadSystems() {
  try {
    const data = await chrome.storage.local.get(MFA_SYSTEMS_KEY);
    const systems = data?.[MFA_SYSTEMS_KEY];
    return Array.isArray(systems) ? systems : [];
  } catch {
    return [];
  }
}

function findSystemByMfaUrl(systems, currentHref) {
  const current = parseUrlParts(currentHref);
  if (!current) return null;

  for (const system of systems) {
    const mfaParts = parseUrlParts(system?.mfa_url || "");
    if (!mfaParts) continue;
    if (current.origin !== mfaParts.origin) continue;

    if (current.path === mfaParts.path || current.path.startsWith(`${mfaParts.path}/`)) {
      return system;
    }
  }

  return null;
}

async function loadSecretOverrides() {
  try {
    const data = await chrome.storage.local.get(OVERRIDES_STORAGE_KEY);
    const value = data?.[OVERRIDES_STORAGE_KEY];
    if (value && typeof value === "object" && !Array.isArray(value)) {
      return value;
    }
    return {};
  } catch {
    return {};
  }
}

function base32ToBytes(base32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = base32.toUpperCase().replace(/=+$/g, "").replace(/\s+/g, "");

  let bits = "";
  for (const c of clean) {
    const index = alphabet.indexOf(c);
    if (index === -1) {
      throw new Error("密钥不是有效的 Base32 格式");
    }
    bits += index.toString(2).padStart(5, "0");
  }

  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }

  return new Uint8Array(bytes);
}

async function generateTOTP(secret, timeMs = Date.now(), digits = DIGITS, period = PERIOD) {
  const key = await crypto.subtle.importKey(
    "raw",
    base32ToBytes(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );

  const counter = Math.floor(timeMs / 1000 / period);
  const counterBuffer = new ArrayBuffer(8);
  const view = new DataView(counterBuffer);
  view.setUint32(4, counter, false);

  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBuffer));
  const offset = hmac[hmac.length - 1] & 0x0f;

  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  return String(binary % 10 ** digits).padStart(digits, "0");
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    const ok = document.execCommand("copy");
    textarea.remove();
    return ok;
  }
}

function createWidget(systemName) {
  const root = document.createElement("div");
  root.id = "mfa-domain-helper-root";

  root.innerHTML = `
    <div class="mfa-card">
      <div class="mfa-head">
        <p class="mfa-title">MFA助手</p>
        <div class="mfa-host">系统：${systemName}</div>
      </div>
      <div class="mfa-body">
        <div class="mfa-code" id="mfa-code">------</div>
        <div class="mfa-sub" id="mfa-meta">-- 秒后刷新</div>
        <div class="mfa-bar-bg"><div class="mfa-bar" id="mfa-bar"></div></div>
        <div class="mfa-actions">
          <button class="mfa-copy" id="mfa-copy-btn">复制验证码</button>
          <button class="mfa-close" id="mfa-close-btn">关闭</button>
        </div>
      </div>
    </div>
  `;

  document.documentElement.appendChild(root);

  return {
    root,
    headEl: root.querySelector(".mfa-head"),
    codeEl: root.querySelector("#mfa-code"),
    metaEl: root.querySelector("#mfa-meta"),
    barEl: root.querySelector("#mfa-bar"),
    copyBtn: root.querySelector("#mfa-copy-btn"),
    closeBtn: root.querySelector("#mfa-close-btn")
  };
}

function enableDrag(root, handle) {
  let dragging = false;
  let offsetX = 0;
  let offsetY = 0;

  handle.addEventListener("pointerdown", (event) => {
    if (event.button !== 0) return;

    const rect = root.getBoundingClientRect();
    root.style.left = `${rect.left}px`;
    root.style.top = `${rect.top}px`;
    root.style.right = "auto";

    dragging = true;
    offsetX = event.clientX - rect.left;
    offsetY = event.clientY - rect.top;
    handle.setPointerCapture(event.pointerId);
  });

  handle.addEventListener("pointermove", (event) => {
    if (!dragging) return;

    const maxLeft = Math.max(0, window.innerWidth - root.offsetWidth);
    const maxTop = Math.max(0, window.innerHeight - root.offsetHeight);
    const left = Math.min(Math.max(0, event.clientX - offsetX), maxLeft);
    const top = Math.min(Math.max(0, event.clientY - offsetY), maxTop);

    root.style.left = `${left}px`;
    root.style.top = `${top}px`;
  });

  function stopDrag(event) {
    if (!dragging) return;
    dragging = false;
    if (event?.pointerId !== undefined) {
      handle.releasePointerCapture(event.pointerId);
    }
  }

  handle.addEventListener("pointerup", stopDrag);
  handle.addEventListener("pointercancel", stopDrag);
}

async function init() {
  const systems = await loadSystems();
  if (!systems.length) return;

  const matchedSystem = findSystemByMfaUrl(systems, location.href);
  if (!matchedSystem) return;

  const secretOverrides = await loadSecretOverrides();
  let currentSecret = secretOverrides[matchedSystem.name] || "";

  const ui = createWidget(matchedSystem.name || matchedSystem.mfa_url);
  enableDrag(ui.root, ui.headEl);
  let currentCode = "";
  let closeCandidateSince = 0;

  function closeWidget() {
    if (ui.root.isConnected) {
      ui.root.remove();
    }
  }

  async function refreshCode() {
    if (!currentSecret) {
      currentCode = "";
      ui.codeEl.textContent = "------";
      ui.copyBtn.disabled = true;
      return;
    }

    try {
      currentCode = await generateTOTP(currentSecret);
      ui.codeEl.textContent = `${currentCode.slice(0, 3)} ${currentCode.slice(3)}`;
      ui.copyBtn.disabled = false;
    } catch (error) {
      currentCode = "";
      ui.codeEl.textContent = "ERROR";
      ui.copyBtn.disabled = true;
      ui.metaEl.textContent = error.message || "生成失败";
    }
  }

  function refreshCountdown() {
    const nowSec = Math.floor(Date.now() / 1000);
    const remain = PERIOD - (nowSec % PERIOD);
    if (!currentSecret) {
      ui.metaEl.textContent = "未配置密钥，请到配置页绑定";
      ui.barEl.style.width = "0%";
      return;
    }

    ui.metaEl.textContent = `${remain} 秒后刷新`;
    ui.barEl.style.width = `${((PERIOD - remain) / PERIOD) * 100}%`;
  }

  ui.copyBtn.addEventListener("click", async () => {
    if (!currentCode) return;
    const ok = await copyText(currentCode);
    const old = ui.copyBtn.textContent;
    ui.copyBtn.textContent = ok ? "已复制" : "复制失败";
    setTimeout(() => {
      ui.copyBtn.textContent = old;
    }, 1000);
  });

  ui.closeBtn.addEventListener("click", () => {
    closeWidget();
  });

  document.addEventListener(
    "submit",
    (event) => {
      if (!AUTO_CLOSE_ENABLED || !ui.root.isConnected) return;
      const form = event.target;
      if (!isLikelyMfaForm(form)) return;
      setTimeout(closeWidget, 300);
    },
    true
  );

  refreshCode();
  refreshCountdown();
  setInterval(refreshCountdown, 200);
  setInterval(refreshCode, 1000);
  setInterval(() => {
    if (!AUTO_CLOSE_ENABLED || !ui.root.isConnected) return;

    const stillOnMfaPage = !!findSystemByMfaUrl(systems, location.href);
    if (!stillOnMfaPage || shouldAutoCloseWidget()) {
      if (!closeCandidateSince) {
        closeCandidateSince = Date.now();
        return;
      }

      if (Date.now() - closeCandidateSince >= AUTO_CLOSE_STABLE_MS) {
        closeWidget();
      }
      return;
    }

    closeCandidateSince = 0;
  }, 500);
}

init();
