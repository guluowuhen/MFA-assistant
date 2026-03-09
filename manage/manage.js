const MFA_SYSTEMS_KEY = "mfaSystems";
const OVERRIDES_STORAGE_KEY = "mfaSecretOverrides";

const qrFilesInput = document.getElementById("qrFilesInput");
const clearPendingBtn = document.getElementById("clearPendingBtn");
const saveSelectedBtn = document.getElementById("saveSelectedBtn");
const manualAddBtn = document.getElementById("manualAddBtn");
const importBtn = document.getElementById("importBtn");
const exportBtn = document.getElementById("exportBtn");
const importFileInput = document.getElementById("importFileInput");
const importConflictPanel = document.getElementById("importConflictPanel");
const importConflictTitle = document.getElementById("importConflictTitle");
const importPreviewStats = document.getElementById("importPreviewStats");
const conflictKeyHeader = document.getElementById("conflictKeyHeader");
const conflictExistingHeader = document.getElementById("conflictExistingHeader");
const conflictIncomingHeader = document.getElementById("conflictIncomingHeader");
const conflictActionHeader = document.getElementById("conflictActionHeader");
const importConflictBody = document.getElementById("importConflictBody");
const keepImportAllBtn = document.getElementById("keepImportAllBtn");
const keepExistingAllBtn = document.getElementById("keepExistingAllBtn");
const cancelImportReviewBtn = document.getElementById("cancelImportReviewBtn");
const applyImportReviewBtn = document.getElementById("applyImportReviewBtn");
const savedSearchInput = document.getElementById("savedSearchInput");
const pendingTableBody = document.getElementById("pendingTableBody");
const savedListEl = document.getElementById("savedList");
const msgEl = document.getElementById("msg");

let pendingItems = [];
let importReviewState = null;
let savedSearchKeyword = "";
let editingSavedIndex = -1;

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

function getDateStamp() {
  const now = new Date();
  const yyyy = now.getFullYear();
  const mm = String(now.getMonth() + 1).padStart(2, "0");
  const dd = String(now.getDate()).padStart(2, "0");
  return `${yyyy}${mm}${dd}`;
}

function sanitizeName(raw, fallback = "") {
  const value = String(raw || "").trim();
  return value || fallback;
}

function escapeHtml(raw) {
  return String(raw)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function buildExportPayload(systems, overrides) {
  const items = systems.map((system) => {
    const name = sanitizeName(system?.name, "mfa");
    const mfa_url = normalizeUrl(String(system?.mfa_url || ""));
    const secret = overrides[name];
    return {
      name,
      mfa_url,
      ...(secret ? { secret } : {})
    };
  });

  return {
    schema: "mfa-helper-export",
    version: 1,
    exportedAt: new Date().toISOString(),
    items
  };
}

function downloadJsonFile(fileName, payload) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const objectUrl = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = objectUrl;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(objectUrl);
}

function parseImportPayload(payload) {
  if (!payload || typeof payload !== "object") {
    throw new Error("导入文件格式不正确");
  }

  let sourceItems = [];
  if (Array.isArray(payload.items)) {
    sourceItems = payload.items;
  } else if (Array.isArray(payload.systems)) {
    sourceItems = payload.systems;
  } else {
    throw new Error("导入文件缺少 items/systems");
  }

  const normalizedItems = [];
  const seenUrls = new Set();
  for (const rawItem of sourceItems) {
    const name = sanitizeName(rawItem?.name || "");
    const rawUrl = String(rawItem?.mfa_url || rawItem?.url || "").trim();
    if (!name || !rawUrl) {
      throw new Error("导入项缺少 name 或 mfa_url");
    }
    let mfa_url = "";
    try {
      mfa_url = normalizeUrl(rawUrl);
    } catch {
      throw new Error(`导入项 mfa_url 非法：${rawUrl}`);
    }
    if (seenUrls.has(mfa_url)) {
      throw new Error(`导入文件存在重复 mfa_url：${mfa_url}`);
    }
    seenUrls.add(mfa_url);

    let secret = "";
    const rawSecret = rawItem?.secret ?? rawItem?.secretText ?? "";
    if (String(rawSecret).trim()) {
      try {
        secret = parseSecret(String(rawSecret));
      } catch (error) {
        throw new Error(`${name} 的密钥格式错误：${error.message}`);
      }
    }

    normalizedItems.push({ name, mfa_url, secret });
  }

  return normalizedItems;
}

function findSystemIndexByUrl(systems, mfaUrl) {
  return systems.findIndex((x) => {
    try {
      return normalizeUrl(String(x?.mfa_url || "")) === mfaUrl;
    } catch {
      return String(x?.mfa_url || "").trim() === mfaUrl;
    }
  });
}

function clearImportReview() {
  importReviewState = null;
  importConflictPanel.hidden = true;
  importConflictTitle.textContent = "冲突处理";
  keepImportAllBtn.textContent = "全部采用新项";
  keepExistingAllBtn.textContent = "全部保持现有";
  applyImportReviewBtn.textContent = "应用";
  conflictKeyHeader.textContent = "冲突键";
  conflictExistingHeader.textContent = "现有项";
  conflictIncomingHeader.textContent = "新项";
  conflictActionHeader.textContent = "处理方式";
  importPreviewStats.textContent = "";
  importConflictBody.innerHTML = "";
}

function maskSecret(secret) {
  const text = String(secret || "").trim();
  if (!text) return "";
  if (text.length <= 8) return `${text.slice(0, 2)}***${text.slice(-2)}`;
  return `${text.slice(0, 4)}***${text.slice(-4)}`;
}

function collectSecretOwnerMap(overrides, systems) {
  const owners = new Map();

  systems.forEach((system) => {
    const name = sanitizeName(system?.name || "", "未命名");
    let secret = "";
    try {
      secret = parseSecret(String(overrides[name] || ""));
    } catch {
      secret = "";
    }
    if (!secret || owners.has(secret)) return;
    owners.set(secret, `已绑定：${name}`);
  });

  Object.entries(overrides).forEach(([name, rawSecret]) => {
    let secret = "";
    try {
      secret = parseSecret(String(rawSecret || ""));
    } catch {
      secret = "";
    }
    if (!secret || owners.has(secret)) return;
    owners.set(secret, `已绑定：${sanitizeName(name, "未命名")}`);
  });

  pendingItems.forEach((item) => {
    let secret = "";
    try {
      secret = parseSecret(item.secretText || "");
    } catch {
      secret = "";
    }
    if (!secret || owners.has(secret)) return;
    owners.set(secret, `待保存：${sanitizeName(item.name, "未命名")}`);
  });

  return owners;
}

function buildConflictDecisionMap() {
  if (!importReviewState) return new Map();
  return new Map(importReviewState.conflicts.map((item) => [item.key, item.decision]));
}

function calculateImportPlan(importItems, baseSystems, conflictDecisionMap = new Map()) {
  const systems = baseSystems.map((item) => ({ ...item }));
  let createCount = 0;
  let updateCount = 0;
  let keepExistingCount = 0;

  for (const item of importItems) {
    const existingByUrlIndex = findSystemIndexByUrl(systems, item.mfa_url);
    if (existingByUrlIndex >= 0) {
      const decision = conflictDecisionMap.get(item.mfa_url) || "import";
      if (decision === "existing") {
        keepExistingCount += 1;
      } else {
        systems[existingByUrlIndex] = { name: item.name, mfa_url: item.mfa_url };
        updateCount += 1;
      }
      continue;
    }

    const indexByName = systems.findIndex((x) => x.name === item.name);
    if (indexByName >= 0) {
      systems[indexByName] = { name: item.name, mfa_url: item.mfa_url };
      updateCount += 1;
    } else {
      systems.push({ name: item.name, mfa_url: item.mfa_url });
      createCount += 1;
    }
  }

  return { createCount, updateCount, keepExistingCount };
}

function refreshImportPreviewStats() {
  if (!importReviewState) {
    importPreviewStats.textContent = "";
    return;
  }

  if (importReviewState.mode === "qr") {
    const importSelected = importReviewState.conflicts.filter((item) => item.decision === "import").length;
    const skipSelected = importReviewState.conflicts.length - importSelected;
    const keepNewCount = importReviewState.autoAddedCount + importSelected;
    importReviewState.previewCounts = { createCount: keepNewCount, updateCount: 0, keepExistingCount: skipSelected };
    importPreviewStats.textContent = `预览：采用新项 ${keepNewCount}，保持现有 ${skipSelected}`;
    return;
  }

  const counts = calculateImportPlan(importReviewState.importItems, importReviewState.baseSystems, buildConflictDecisionMap());
  importReviewState.previewCounts = counts;
  importPreviewStats.textContent =
    `预览：采用新项 ${counts.createCount + counts.updateCount}，保持现有 ${counts.keepExistingCount}`;
}

function renderImportConflicts() {
  if (!importReviewState) {
    clearImportReview();
    return;
  }

  const { conflicts } = importReviewState;
  const isQrMode = importReviewState.mode === "qr";
  importConflictTitle.textContent = "冲突处理";
  keepImportAllBtn.textContent = "全部采用新项";
  keepExistingAllBtn.textContent = "全部保持现有";
  applyImportReviewBtn.textContent = "应用";
  conflictKeyHeader.textContent = "冲突键";
  conflictExistingHeader.textContent = "现有项";
  conflictIncomingHeader.textContent = "新项";
  conflictActionHeader.textContent = "处理方式";

  refreshImportPreviewStats();
  importConflictBody.innerHTML = "";

  if (!conflicts.length) {
    importConflictBody.innerHTML = '<tr><td colspan="4" class="muted">无冲突项。</td></tr>';
    importConflictPanel.hidden = false;
    return;
  }

  conflicts.forEach((conflict, index) => {
    const tr = document.createElement("tr");

    const urlTd = document.createElement("td");
    urlTd.className = "item-file";
    urlTd.textContent = isQrMode ? maskSecret(conflict.key) : conflict.mfa_url;
    tr.appendChild(urlTd);

    const existingTd = document.createElement("td");
    existingTd.textContent = conflict.existing.name;
    tr.appendChild(existingTd);

    const importTd = document.createElement("td");
    importTd.textContent = conflict.imported.name;
    tr.appendChild(importTd);

    const actionTd = document.createElement("td");
    const select = document.createElement("select");
    select.className = "choice-select";
    select.dataset.type = "conflict_choice";
    select.dataset.index = String(index);

    const keepImportedOption = document.createElement("option");
    keepImportedOption.value = "import";
    keepImportedOption.textContent = "采用新项";
    select.appendChild(keepImportedOption);

    const keepExistingOption = document.createElement("option");
    keepExistingOption.value = "existing";
    keepExistingOption.textContent = "保持现有";
    select.appendChild(keepExistingOption);

    select.value = conflict.decision;
    actionTd.appendChild(select);
    tr.appendChild(actionTd);

    importConflictBody.appendChild(tr);
  });

  importConflictPanel.hidden = false;
}

function setAllConflictDecision(decision) {
  if (!importReviewState) return;
  importReviewState.conflicts.forEach((item) => {
    item.decision = decision;
  });
  renderImportConflicts();
}

function prepareImportReview(importItems, systems) {
  const conflicts = [];
  let nonConflictCount = 0;

  for (const item of importItems) {
    const existingIndex = findSystemIndexByUrl(systems, item.mfa_url);
    if (existingIndex >= 0) {
      conflicts.push({
        key: item.mfa_url,
        mfa_url: item.mfa_url,
        existing: systems[existingIndex],
        imported: item,
        decision: "import"
      });
    } else {
      nonConflictCount += 1;
    }
  }

  importReviewState = {
    mode: "import",
    importItems,
    baseSystems: systems.map((item) => ({ ...item })),
    conflicts,
    nonConflictCount,
    previewCounts: { createCount: 0, updateCount: 0, keepExistingCount: 0 }
  };
}

async function applyImportItems(importItems, conflictDecisionMap) {
  const systems = await loadSystems();
  const overrides = await loadOverrides();
  let createCount = 0;
  let updateCount = 0;
  let keepExistingCount = 0;

  for (const item of importItems) {
    const existingByUrlIndex = findSystemIndexByUrl(systems, item.mfa_url);
    let imported = true;

    if (existingByUrlIndex >= 0) {
      const decision = conflictDecisionMap.get(item.mfa_url) || "import";
      if (decision === "existing") {
        keepExistingCount += 1;
        imported = false;
      } else {
        const oldName = systems[existingByUrlIndex].name;
        systems[existingByUrlIndex] = { name: item.name, mfa_url: item.mfa_url };
        if (oldName !== item.name && !systems.some((x) => x.name === oldName)) {
          delete overrides[oldName];
        }
        updateCount += 1;
      }
    } else {
      const indexByName = systems.findIndex((x) => x.name === item.name);
      if (indexByName >= 0) {
        systems[indexByName] = { name: item.name, mfa_url: item.mfa_url };
        updateCount += 1;
      } else {
        systems.push({ name: item.name, mfa_url: item.mfa_url });
        createCount += 1;
      }
    }

    if (imported && item.secret) {
      overrides[item.name] = item.secret;
    }
  }

  await saveSystems(systems);
  await saveOverrides(overrides);
  await renderSaved();
  clearImportReview();
  setMsg(`导入完成：新增 ${createCount}，覆盖 ${updateCount}，保留已绑定 ${keepExistingCount}`);
}

async function applyQrConflictSelections() {
  if (!importReviewState || importReviewState.mode !== "qr") return;
  const overrides = await loadOverrides();
  const existingSecrets = collectExistingSecretSet(overrides);
  let importCount = 0;
  let skipCount = 0;

  importReviewState.conflicts.forEach((conflict) => {
    if (conflict.decision !== "import") {
      skipCount += 1;
      return;
    }

    let secret = "";
    try {
      secret = parseSecret(conflict.pendingItem?.secretText || "");
    } catch {
      skipCount += 1;
      return;
    }

    if (!secret || existingSecrets.has(secret)) {
      skipCount += 1;
      return;
    }

    existingSecrets.add(secret);
    pendingItems.push({
      name: sanitizeName(conflict.pendingItem?.name || "", "mfa"),
      mfa_url: "",
      secretText: secret
    });
    importCount += 1;
  });

  renderPending();
  const totalAdded = importReviewState.autoAddedCount + importCount;
  const failedCount = importReviewState.parseFailedCount || 0;
  clearImportReview();
  setMsg(`二维码处理完成：新增待保存 ${totalAdded}，跳过重复 ${skipCount}${failedCount ? `，解析失败 ${failedCount}` : ""}`);
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

  const keyword = savedSearchKeyword.trim().toLowerCase();
  const filteredItems = systems
    .map((item, index) => ({ item, index }))
    .filter(({ item }) => {
      if (!keyword) return true;
      const nameText = String(item?.name || "").toLowerCase();
      const urlText = String(item?.mfa_url || "").toLowerCase();
      return nameText.includes(keyword) || urlText.includes(keyword);
    });

  if (!filteredItems.length) {
    savedListEl.innerHTML = '<div class="muted">没有匹配项。</div>';
    return;
  }

  filteredItems.forEach(({ item, index }) => {
    const row = document.createElement("div");
    row.className = "item";
    if (editingSavedIndex === index) {
      row.innerHTML = `
        <div class="item-head">
          <div class="item-name">编辑中</div>
          <div class="item-actions">
            <button data-type="cancel_edit_saved" data-index="${index}" type="button">取消</button>
            <button data-type="save_edit_saved" data-index="${index}" type="button" class="primary">保存</button>
          </div>
        </div>
        <div class="item-edit">
          <input
            data-type="edit_saved_name"
            data-index="${index}"
            value="${escapeHtml(item.name)}"
            placeholder="系统名称"
          />
          <input
            data-type="edit_saved_url"
            data-index="${index}"
            value="${escapeHtml(item.mfa_url)}"
            placeholder="mfa_url"
          />
        </div>
      `;
    } else {
      row.innerHTML = `
        <div class="item-head">
          <div class="item-name">${escapeHtml(item.name)}</div>
          <div class="item-actions">
            <button data-type="edit_saved" data-index="${index}" type="button">编辑</button>
            <button class="btn-del" data-type="del_saved" data-index="${index}" type="button">删除</button>
          </div>
        </div>
        <div class="item-file">${escapeHtml(item.mfa_url)}</div>
      `;
    }
    savedListEl.appendChild(row);
  });
}

async function appendFiles(files) {
  if (!files.length) return;
  clearImportReview();
  const overrides = await loadOverrides();
  const systems = await loadSystems();
  const secretOwnerMap = collectSecretOwnerMap(overrides, systems);

  const tasks = Array.from(files).map(async (file) => {
    try {
      const raw = await decodeQrFromFile(file);
      const parsed = parseOtpAuthDetails(raw);
      return {
        ok: true,
        fileName: file.name,
        name: parsed.defaultName,
        secret: parsed.secret
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
  const parsedOk = results.filter((x) => x.ok);
  const failed = results.filter((x) => !x.ok);
  const immediateAdds = [];
  const conflicts = [];

  parsedOk.forEach((item) => {
    const ownerLabel = secretOwnerMap.get(item.secret);
    const pendingItem = {
      name: item.name,
      mfa_url: "",
      secretText: item.secret
    };
    if (ownerLabel) {
      conflicts.push({
        key: item.secret,
        existing: { name: ownerLabel },
        imported: { name: `${item.name}（${item.fileName}）` },
        decision: "import",
        pendingItem
      });
      return;
    }

    immediateAdds.push(pendingItem);
    secretOwnerMap.set(item.secret, `本次上传：${item.fileName}`);
  });

  if (immediateAdds.length) {
    pendingItems = pendingItems.concat(immediateAdds);
    renderPending();
  }

  if (conflicts.length) {
    importReviewState = {
      mode: "qr",
      conflicts,
      autoAddedCount: immediateAdds.length,
      parseFailedCount: failed.length
    };
    renderImportConflicts();
    setMsg(
      `已解析 ${parsedOk.length} 张，其中冲突 ${conflicts.length} 张${failed.length ? `，解析失败 ${failed.length} 张` : ""}，请在弹窗中完成处理`
    );
    return;
  }

  if (failed.length) {
    setMsg(`已新增待保存 ${immediateAdds.length} 条，解析失败 ${failed.length} 条：${failed[0].fileName}（${failed[0].error}）`, true);
    return;
  }

  setMsg(`成功解析并新增 ${immediateAdds.length} 张二维码`);
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

exportBtn.addEventListener("click", async () => {
  const systems = await loadSystems();
  if (!systems.length) {
    setMsg("暂无已绑定系统可导出", true);
    return;
  }

  const overrides = await loadOverrides();
  let payload;
  try {
    payload = buildExportPayload(systems, overrides);
  } catch (error) {
    setMsg(`导出失败：${error.message || "数据格式异常"}`, true);
    return;
  }

  const fileName = `mfa-systems-${getDateStamp()}.json`;
  downloadJsonFile(fileName, payload);
  setMsg(`已导出 ${systems.length} 条绑定`);
});

importBtn.addEventListener("click", () => {
  importFileInput.click();
});

importFileInput.addEventListener("change", async () => {
  const file = importFileInput.files?.[0];
  importFileInput.value = "";
  if (!file) return;
  clearImportReview();

  let text = "";
  try {
    text = await file.text();
  } catch {
    setMsg("读取导入文件失败", true);
    return;
  }

  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    setMsg("导入文件不是合法 JSON", true);
    return;
  }

  let importItems = [];
  try {
    importItems = parseImportPayload(payload);
  } catch (error) {
    setMsg(`导入失败：${error.message || "格式不正确"}`, true);
    return;
  }

  const systems = await loadSystems();
  prepareImportReview(importItems, systems);
  if (!importReviewState.conflicts.length) {
    await applyImportItems(importItems, new Map());
    return;
  }

  renderImportConflicts();
  setMsg(`已生成冲突处理：冲突 ${importReviewState.conflicts.length} 条，请在弹窗中完成处理`);
});

importConflictBody.addEventListener("change", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLSelectElement)) return;
  if (target.dataset.type !== "conflict_choice") return;
  if (!importReviewState) return;

  const index = Number(target.dataset.index);
  if (Number.isNaN(index) || index < 0 || index >= importReviewState.conflicts.length) return;
  importReviewState.conflicts[index].decision = target.value === "existing" ? "existing" : "import";
  refreshImportPreviewStats();
});

keepImportAllBtn.addEventListener("click", () => {
  setAllConflictDecision("import");
});

keepExistingAllBtn.addEventListener("click", () => {
  setAllConflictDecision("existing");
});

cancelImportReviewBtn.addEventListener("click", () => {
  clearImportReview();
  setMsg("已取消本次冲突处理");
});

applyImportReviewBtn.addEventListener("click", async () => {
  if (!importReviewState) {
    setMsg("暂无待处理项", true);
    return;
  }

  if (importReviewState.mode === "qr") {
    await applyQrConflictSelections();
    return;
  }

  const conflictDecisionMap = new Map(
    importReviewState.conflicts.map((item) => [item.key, item.decision])
  );
  await applyImportItems(importReviewState.importItems, conflictDecisionMap);
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
  const type = target.dataset.type;
  const index = Number(target.dataset.index);

  if (type === "edit_saved") {
    if (Number.isNaN(index) || index < 0) return;
    editingSavedIndex = index;
    await renderSaved();
    return;
  }

  if (type === "cancel_edit_saved") {
    editingSavedIndex = -1;
    await renderSaved();
    return;
  }

  if (type === "save_edit_saved") {
    const nameInput = savedListEl.querySelector(`input[data-type="edit_saved_name"][data-index="${index}"]`);
    const urlInput = savedListEl.querySelector(`input[data-type="edit_saved_url"][data-index="${index}"]`);
    if (!(nameInput instanceof HTMLInputElement) || !(urlInput instanceof HTMLInputElement)) return;

    const name = nameInput.value.trim();
    const rawUrl = urlInput.value.trim();
    if (!name || !rawUrl) {
      setMsg("系统名称和 mfa_url 不能为空", true);
      return;
    }

    let normalizedUrl = "";
    try {
      normalizedUrl = normalizeUrl(rawUrl);
    } catch {
      setMsg(`mfa_url 非法：${rawUrl}`, true);
      return;
    }

    const systems = await loadSystems();
    if (Number.isNaN(index) || index < 0 || index >= systems.length) return;

    if (systems.some((item, i) => i !== index && item.name === name)) {
      setMsg(`已存在同名系统：${name}`, true);
      return;
    }

    if (systems.some((item, i) => i !== index && findSystemIndexByUrl([item], normalizedUrl) >= 0)) {
      setMsg(`已存在相同 mfa_url：${normalizedUrl}`, true);
      return;
    }

    const oldName = systems[index].name;
    systems[index] = { name, mfa_url: normalizedUrl };
    await saveSystems(systems);

    if (oldName !== name) {
      const overrides = await loadOverrides();
      if (Object.prototype.hasOwnProperty.call(overrides, oldName)) {
        overrides[name] = overrides[oldName];
        delete overrides[oldName];
        await saveOverrides(overrides);
      }
    }

    editingSavedIndex = -1;
    await renderSaved();
    setMsg("已保存编辑");
    return;
  }

  if (type !== "del_saved") return;

  const systems = await loadSystems();
  if (Number.isNaN(index) || index < 0 || index >= systems.length) return;

  const removedName = systems[index].name;
  systems.splice(index, 1);
  await saveSystems(systems);

  const overrides = await loadOverrides();
  delete overrides[removedName];
  await saveOverrides(overrides);

  editingSavedIndex = -1;
  await renderSaved();
  setMsg("已删除绑定");
});

savedSearchInput.addEventListener("input", async () => {
  savedSearchKeyword = savedSearchInput.value || "";
  await renderSaved();
});

importConflictPanel.addEventListener("click", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  if (target.dataset.type !== "close_import_modal") return;
  clearImportReview();
  setMsg("已取消本次冲突处理");
});

document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;
  if (importConflictPanel.hidden) return;
  clearImportReview();
  setMsg("已取消本次冲突处理");
});

(async function init() {
  renderPending();
  await renderSaved();
})();
