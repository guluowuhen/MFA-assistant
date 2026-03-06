const MFA_SYSTEMS_KEY = "mfaSystems";
const OVERRIDES_STORAGE_KEY = "mfaSecretOverrides";

const qrFilesInput = document.getElementById("qrFilesInput");
const clearPendingBtn = document.getElementById("clearPendingBtn");
const saveSelectedBtn = document.getElementById("saveSelectedBtn");
const manualAddBtn = document.getElementById("manualAddBtn");
const pendingTableBody = document.getElementById("pendingTableBody");
const savedListEl = document.getElementById("savedList");
const msgEl = document.getElementById("msg");

let pendingItems = [];

function setMsg(text, isError = false) {
  msgEl.textContent = text;
  msgEl.style.color = isError ? "#dc2626" : "#64748b";
}

function normalizeUrl(raw) {
  const url = new URL(raw.trim());
  return `${url.origin}${url.pathname}`.replace(/\/+$/, "");
}

function parseOtpAuthDetails(raw) {
  const text = String(raw || "").trim().replace(/^['"]|['"]$/g, "");
  const decodedText = /^otpauth%3a/i.test(text) ? decodeURIComponent(text) : text;
  const otpauthMatch = decodedText.match(/otpauth:\/\/[^\s"']+/i);
  const candidate = otpauthMatch ? otpauthMatch[0] : decodedText;

  let uri;
  try {
    uri = new URL(candidate);
  } catch {
    throw new Error("otpauth 链接格式不正确");
  }

  if (uri.protocol !== "otpauth:") {
    throw new Error("otpauth 链接格式不正确");
  }

  const hostType = uri.hostname.toLowerCase();
  const pathType = uri.pathname.toLowerCase();
  const isTotpHost = hostType === "totp";
  const isTotpPath = pathType.startsWith("/totp/");

  const secret = uri.searchParams.get("secret");
  if (!secret) throw new Error("otpauth 中缺少 secret");

  const issuer = uri.searchParams.get("issuer") || "";
  const labelPath = isTotpHost
    ? uri.pathname.replace(/^\//, "")
    : isTotpPath
      ? uri.pathname.replace(/^\/totp\//i, "")
      : uri.pathname.replace(/^\//, "");
  const rawLabel = decodeURIComponent(labelPath);
  const [label = "", account = ""] = rawLabel.split(":");
  const hostFallbackName = hostType && hostType !== "totp" ? hostType : "";

  return {
    secret: secret.toUpperCase().replace(/\s+/g, ""),
    defaultName: (issuer || label || account || hostFallbackName || "mfa").trim()
  };
}

function parseSecret(raw) {
  const text = String(raw || "").trim();
  if (!text) return "";

  if (text.toLowerCase().startsWith("otpauth://")) {
    return parseOtpAuthDetails(text).secret;
  }

  const secret = text.toUpperCase().replace(/\s+/g, "");
  if (!/^[A-Z2-7]+=*$/.test(secret)) {
    throw new Error("secret 格式不正确");
  }
  return secret;
}

async function decodeQrFromFile(file) {
  if (!file) throw new Error("未选择图片");
  const hasBarcodeDetector = "BarcodeDetector" in window;
  const hasJsQr = typeof window.jsQR === "function";
  if (!hasBarcodeDetector && !hasJsQr) {
    throw new Error("当前环境不支持二维码识别，请手动输入 secret/otpauth");
  }

  const supportsQrByBarcodeDetector = async () => {
    if (!hasBarcodeDetector) return false;
    if (typeof BarcodeDetector.getSupportedFormats !== "function") return true;
    try {
      const formats = await BarcodeDetector.getSupportedFormats();
      return Array.isArray(formats) && formats.includes("qr_code");
    } catch {
      return true;
    }
  };

  const canUseBarcodeDetector = await supportsQrByBarcodeDetector();
  const detector = canUseBarcodeDetector ? new BarcodeDetector({ formats: ["qr_code"] }) : null;
  const bitmap = await createImageBitmap(file);
  const rawCandidates = [];

  const collectValues = async (imageSource) => {
    if (!detector) return;
    const results = await detector.detect(imageSource);
    for (const item of results) {
      if (item && typeof item.rawValue === "string" && item.rawValue.trim()) {
        rawCandidates.push(item.rawValue.trim());
      }
    }
  };

  const runBarcodeDetectorPasses = async () => {
    if (!detector) return;

    // Pass 1: 原图
    await collectValues(bitmap);

    // Pass 2: 放大后重试（Arc 上对小图有时更稳定）
    if (!rawCandidates.length) {
      const scaleCanvas = document.createElement("canvas");
      const w = Math.max(1, Math.min(bitmap.width * 2, 2400));
      const h = Math.max(1, Math.min(bitmap.height * 2, 2400));
      scaleCanvas.width = w;
      scaleCanvas.height = h;
      const scaleCtx = scaleCanvas.getContext("2d");
      if (scaleCtx) {
        scaleCtx.imageSmoothingEnabled = false;
        scaleCtx.drawImage(bitmap, 0, 0, w, h);
        await collectValues(scaleCanvas);
      }
    }

    // Pass 3: 灰度增强后重试（提升黑白对比）
    if (!rawCandidates.length) {
      const grayCanvas = document.createElement("canvas");
      grayCanvas.width = bitmap.width;
      grayCanvas.height = bitmap.height;
      const grayCtx = grayCanvas.getContext("2d");
      if (grayCtx) {
        grayCtx.drawImage(bitmap, 0, 0);
        const imageData = grayCtx.getImageData(0, 0, grayCanvas.width, grayCanvas.height);
        const data = imageData.data;
        for (let i = 0; i < data.length; i += 4) {
          const lum = 0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2];
          const bw = lum > 150 ? 255 : 0;
          data[i] = bw;
          data[i + 1] = bw;
          data[i + 2] = bw;
        }
        grayCtx.putImageData(imageData, 0, 0);
        await collectValues(grayCanvas);
      }
    }
  };

  const tryJsQrFromCanvas = (canvas, threshold = null) => {
    if (!hasJsQr) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    if (typeof threshold === "number") {
      const data = imageData.data;
      for (let i = 0; i < data.length; i += 4) {
        const lum = 0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2];
        const bw = lum > threshold ? 255 : 0;
        data[i] = bw;
        data[i + 1] = bw;
        data[i + 2] = bw;
      }
    }
    const result = window.jsQR(imageData.data, canvas.width, canvas.height, {
      inversionAttempts: "attemptBoth"
    });
    if (result?.data && String(result.data).trim()) {
      rawCandidates.push(String(result.data).trim());
    }
  };

  const runJsQrFallbackPasses = () => {
    if (!hasJsQr || rawCandidates.length) return;
    const baseCanvas = document.createElement("canvas");
    baseCanvas.width = bitmap.width;
    baseCanvas.height = bitmap.height;
    const baseCtx = baseCanvas.getContext("2d");
    if (!baseCtx) return;
    baseCtx.drawImage(bitmap, 0, 0);
    tryJsQrFromCanvas(baseCanvas);

    if (!rawCandidates.length) {
      const scaleCanvas = document.createElement("canvas");
      const w = Math.max(1, Math.min(bitmap.width * 2, 2400));
      const h = Math.max(1, Math.min(bitmap.height * 2, 2400));
      scaleCanvas.width = w;
      scaleCanvas.height = h;
      const scaleCtx = scaleCanvas.getContext("2d");
      if (scaleCtx) {
        scaleCtx.imageSmoothingEnabled = false;
        scaleCtx.drawImage(bitmap, 0, 0, w, h);
        tryJsQrFromCanvas(scaleCanvas);
      }
    }

    if (!rawCandidates.length) {
      tryJsQrFromCanvas(baseCanvas, 150);
    }
  };

  await runBarcodeDetectorPasses();
  runJsQrFallbackPasses();
  bitmap.close();

  if (!rawCandidates.length) throw new Error("未识别到二维码");

  const uniqueCandidates = Array.from(new Set(rawCandidates));
  const scoreRaw = (text) => {
    let score = 0;
    if (/otpauth:\/\//i.test(text)) score += 100;
    if (/secret=/i.test(text)) score += 60;
    if (/issuer=/i.test(text)) score += 20;
    if (/^[A-Z2-7]+=*$/i.test(text.replace(/\s+/g, ""))) score += 10;
    return score;
  };

  uniqueCandidates.sort((a, b) => scoreRaw(b) - scoreRaw(a));
  const raw = uniqueCandidates[0] || "";

  if (!raw) {
    throw new Error("二维码内容为空");
  }
  return raw;
}

async function loadSystems() {
  const data = await chrome.storage.local.get(MFA_SYSTEMS_KEY);
  const systems = data?.[MFA_SYSTEMS_KEY];
  return Array.isArray(systems) ? systems : [];
}

async function saveSystems(systems) {
  await chrome.storage.local.set({ [MFA_SYSTEMS_KEY]: systems });
}

async function loadOverrides() {
  const data = await chrome.storage.local.get(OVERRIDES_STORAGE_KEY);
  const value = data?.[OVERRIDES_STORAGE_KEY];
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

async function saveOverrides(overrides) {
  await chrome.storage.local.set({ [OVERRIDES_STORAGE_KEY]: overrides });
}

function collectExistingSecretSet(overrides) {
  const set = new Set(Object.values(overrides).filter(Boolean));
  for (const item of pendingItems) {
    try {
      const secret = parseSecret(item.secretText || "");
      if (secret) set.add(secret);
    } catch {
      // ignore invalid in pending typing stage
    }
  }
  return set;
}

function renderPending() {
  pendingTableBody.innerHTML = "";
  if (!pendingItems.length) {
    pendingTableBody.innerHTML = '<tr><td colspan="4" class="muted">暂无待保存项。可上传二维码或点击右上角“新增”。</td></tr>';
    return;
  }

  pendingItems.forEach((item, index) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><input data-type="name" data-index="${index}" value="${item.name}" placeholder="系统名称" /></td>
      <td><input data-type="mfa_url" data-index="${index}" value="${item.mfa_url}" placeholder="mfa_url" /></td>
      <td><input data-type="secret" data-index="${index}" value="${item.secretText || ""}" placeholder="secret 或 otpauth" /></td>
      <td class="action-cell">
        <button class="btn-del" data-type="remove" data-index="${index}" type="button">移除</button>
      </td>
    `;
    pendingTableBody.appendChild(tr);
  });
}

async function renderSaved() {
  const systems = await loadSystems();
  savedListEl.innerHTML = "";

  if (!systems.length) {
    savedListEl.innerHTML = '<div class="muted">暂无已绑定系统。</div>';
    return;
  }

  systems.forEach((item, index) => {
    const row = document.createElement("div");
    row.className = "item";
    row.innerHTML = `
      <div class="item-head">
        <div class="item-name">${item.name}</div>
        <button class="btn-del" data-type="del_saved" data-index="${index}" type="button">删除</button>
      </div>
      <div class="item-file">${item.mfa_url}</div>
    `;
    savedListEl.appendChild(row);
  });
}

async function appendFiles(files) {
  if (!files.length) return;
  const overrides = await loadOverrides();
  const existingSecrets = collectExistingSecretSet(overrides);

  const tasks = Array.from(files).map(async (file) => {
    try {
      const raw = await decodeQrFromFile(file);
      const parsed = parseOtpAuthDetails(raw);
      if (existingSecrets.has(parsed.secret)) {
        return {
          ok: false,
          fileName: file.name,
          error: "重复二维码（secret 已存在）"
        };
      }
      existingSecrets.add(parsed.secret);
      return {
        ok: true,
        item: {
          name: parsed.defaultName,
          mfa_url: "",
          secretText: parsed.secret
        }
      };
    } catch (error) {
      return {
        ok: false,
        fileName: file.name,
        error: error.message || "解析失败"
      };
    }
  });

  const results = await Promise.all(tasks);
  const success = results.filter((x) => x.ok).map((x) => x.item);
  const failed = results.filter((x) => !x.ok);

  pendingItems = pendingItems.concat(success);
  renderPending();

  if (failed.length) {
    setMsg(`已解析 ${success.length} 张，失败 ${failed.length} 张：${failed[0].fileName}（${failed[0].error}）`, true);
  } else {
    setMsg(`成功解析 ${success.length} 张二维码`);
  }
}

function addEmptyRow() {
  pendingItems.push({
    name: "",
    mfa_url: "",
    secretText: ""
  });
  renderPending();
  setMsg("已新增空行，请填写后保存");
}

qrFilesInput.addEventListener("change", async () => {
  await appendFiles(qrFilesInput.files || []);
  qrFilesInput.value = "";
});

manualAddBtn.addEventListener("click", () => {
  addEmptyRow();
});

clearPendingBtn.addEventListener("click", () => {
  pendingItems = [];
  renderPending();
  setMsg("已清空待保存项");
});

pendingTableBody.addEventListener("input", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLInputElement)) return;
  const index = Number(target.dataset.index);
  const type = target.dataset.type;
  if (Number.isNaN(index) || index < 0 || index >= pendingItems.length) return;

  if (type === "name") pendingItems[index].name = target.value;
  if (type === "mfa_url") pendingItems[index].mfa_url = target.value;
  if (type === "secret") pendingItems[index].secretText = target.value;
});

pendingTableBody.addEventListener("click", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  if (target.dataset.type !== "remove") return;

  const index = Number(target.dataset.index);
  if (Number.isNaN(index) || index < 0 || index >= pendingItems.length) return;
  pendingItems.splice(index, 1);
  renderPending();
});

saveSelectedBtn.addEventListener("click", async () => {
  if (!pendingItems.length) {
    setMsg("暂无可保存的待保存项", true);
    return;
  }

  const systems = await loadSystems();
  const overrides = await loadOverrides();

  for (const item of pendingItems) {
    const name = item.name.trim();
    const rawUrl = item.mfa_url.trim();
    if (!name || !rawUrl) {
      setMsg("系统名称和 mfa_url 不能为空", true);
      return;
    }

    let normalized;
    try {
      normalized = normalizeUrl(rawUrl);
    } catch {
      setMsg(`mfa_url 非法：${rawUrl}`, true);
      return;
    }

    const idx = systems.findIndex((x) => x.name === name);
    if (idx >= 0) {
      systems[idx] = { name, mfa_url: normalized };
    } else {
      systems.push({ name, mfa_url: normalized });
    }

    if (item.secretText && item.secretText.trim()) {
      try {
        const secret = parseSecret(item.secretText);
        overrides[name] = secret;
      } catch (error) {
        setMsg(`${name} 的密钥格式错误：${error.message}`, true);
        return;
      }
    }
  }

  await saveSystems(systems);
  await saveOverrides(overrides);

  const savedCount = pendingItems.length;
  pendingItems = [];
  renderPending();
  await renderSaved();
  setMsg(`已保存 ${savedCount} 条绑定`);
});

savedListEl.addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  if (target.dataset.type !== "del_saved") return;

  const index = Number(target.dataset.index);
  const systems = await loadSystems();
  if (Number.isNaN(index) || index < 0 || index >= systems.length) return;

  const removedName = systems[index].name;
  systems.splice(index, 1);
  await saveSystems(systems);

  const overrides = await loadOverrides();
  delete overrides[removedName];
  await saveOverrides(overrides);

  await renderSaved();
  setMsg("已删除绑定");
});

(async function init() {
  renderPending();
  await renderSaved();
})();
