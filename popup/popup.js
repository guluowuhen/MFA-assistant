const MFA_SYSTEMS_KEY = "mfaSystems";
const OVERRIDES_STORAGE_KEY = "mfaSecretOverrides";
const PERIOD = 30;
const DIGITS = 6;

const listEl = document.getElementById("list");
const msgEl = document.getElementById("msg");
const openConfigBtn = document.getElementById("openConfigBtn");

let systems = [];
let overrides = {};

function setMsg(text, isError = false) {
  msgEl.textContent = text;
  msgEl.style.color = isError ? "#dc2626" : "#64748b";
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
    return false;
  }
}

async function loadData() {
  const data = await chrome.storage.local.get([MFA_SYSTEMS_KEY, OVERRIDES_STORAGE_KEY]);
  systems = Array.isArray(data?.[MFA_SYSTEMS_KEY]) ? data[MFA_SYSTEMS_KEY] : [];
  overrides = data?.[OVERRIDES_STORAGE_KEY] && typeof data[OVERRIDES_STORAGE_KEY] === "object"
    ? data[OVERRIDES_STORAGE_KEY]
    : {};
}

function renderSkeleton() {
  listEl.innerHTML = "";
  if (!systems.length) {
    listEl.innerHTML = '<div class="item-meta">暂无绑定。点击右上角“配置”进行添加。</div>';
    return;
  }

  systems.forEach((item, index) => {
    const row = document.createElement("div");
    row.className = "item";
    row.dataset.index = String(index);
    row.innerHTML = `
      <div class="item-top">
        <div class="item-name">${item.name}</div>
        <button class="copy-btn" data-type="copy" data-index="${index}" type="button">复制</button>
      </div>
      <div class="item-url">${item.mfa_url}</div>
      <div class="item-code" id="code-${index}">------</div>
      <div class="item-meta" id="meta-${index}">未绑定密钥</div>
    `;
    listEl.appendChild(row);
  });
}

async function refreshCodes() {
  if (!systems.length) return;

  const nowSec = Math.floor(Date.now() / 1000);
  const remain = PERIOD - (nowSec % PERIOD);

  for (let i = 0; i < systems.length; i += 1) {
    const item = systems[i];
    const codeEl = document.getElementById(`code-${i}`);
    const metaEl = document.getElementById(`meta-${i}`);
    if (!codeEl || !metaEl) continue;

    const secret = overrides[item.name] || "";
    if (!secret) {
      codeEl.textContent = "------";
      metaEl.textContent = "未绑定密钥";
      continue;
    }

    try {
      const code = await generateTOTP(secret);
      codeEl.textContent = `${code.slice(0, 3)} ${code.slice(3)}`;
      metaEl.textContent = `${remain} 秒后刷新`;
    } catch {
      codeEl.textContent = "ERROR";
      metaEl.textContent = "密钥格式错误";
    }
  }
}

listEl.addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  if (target.dataset.type !== "copy") return;

  const index = Number(target.dataset.index);
  if (Number.isNaN(index) || index < 0 || index >= systems.length) return;

  const item = systems[index];
  const secret = overrides[item.name] || "";
  if (!secret) {
    setMsg(`系统 ${item.name} 尚未绑定密钥`, true);
    return;
  }

  try {
    const code = await generateTOTP(secret);
    const ok = await copyText(code);
    setMsg(ok ? `已复制 ${item.name} 的验证码` : "复制失败", !ok);
  } catch {
    setMsg("无法生成验证码，请先到配置页更新密钥", true);
  }
});

openConfigBtn.addEventListener("click", async () => {
  const url = chrome.runtime.getURL("manage/manage.html");
  await chrome.tabs.create({ url });
});

(async function init() {
  await loadData();
  renderSkeleton();
  await refreshCodes();

  setInterval(refreshCodes, 1000);
})();
