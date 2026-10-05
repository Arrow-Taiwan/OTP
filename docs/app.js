function $(id) { return document.getElementById(id); }
function b32decode(secret) {
  const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const s = String(secret || "").toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = 0, value = 0;
  const out = [];
  for (const ch of s) {
    const idx = alpha.indexOf(ch);
    if (idx < 0) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}
async function totpAt(secret, period, digits, unix) {
  const key = b32decode(secret);
  const counter = Math.floor(unix / Math.max(1, period || 60));
  const buf = new ArrayBuffer(8);
  new DataView(buf).setUint32(4, counter);
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, buf));
  const offset = hmac[hmac.length - 1] & 0x0f;
  const bin = ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
  const mod = 10 ** (digits || 6);
  return String(bin % mod).padStart(digits || 6, "0");
}
function fmtCode(code) {
  const s = String(code || "");
  if (s.length === 8) return s.slice(0, 4) + " " + s.slice(4);
  if (s.length === 6) return s.slice(0, 3) + " " + s.slice(3);
  if (s.length === 7) return s.slice(0, 3) + " " + s.slice(3);
  return s;
}
function parseLabel(label, acc) {
  const parts = String(label || "").split(/[:/\-_| ]+/).filter(Boolean);
  parts.forEach(function (p) {
    if (/^\d{8}$/.test(p) && !acc.tax) acc.tax = p;
    else if (/^\d{6}$/.test(p) && !acc.vendor) acc.vendor = p;
    else if (/[\u4e00-\u9fff]/.test(p) && !acc.person) acc.person = p;
  });
}
function parseQrText(text) {
  const compact = String(text || "").replace(/\s+/g, "").trim();
  if (!compact) throw new Error("QR 是空的");
  const acc = { secret: "", period: 60, digits: 6, tax: "", vendor: "", person: "", label: "momo OTP" };
  if (/^otpauth:\/\/totp\//i.test(compact)) {
    const u = new URL(compact);
    acc.secret = (u.searchParams.get("secret") || "").toUpperCase().replace(/[^A-Z2-7]/g, "");
    const p = parseInt(u.searchParams.get("period") || "60", 10);
    const d = parseInt(u.searchParams.get("digits") || "6", 10);
    if (p > 0) acc.period = p;
    if (d > 0) acc.digits = d;
    acc.label = decodeURIComponent(u.pathname.replace(/^\//, "") || "momo OTP");
    parseLabel(acc.label, acc);
    parseLabel(u.searchParams.get("issuer") || "", acc);
    if (acc.secret.length < 16) throw new Error("QR 裡沒有金鑰");
    return acc;
  }
  if (compact.charAt(0) === "{" || compact.charAt(0) === "[") {
    const obj = JSON.parse(text);
    const walk = function (o) {
      if (!o || typeof o !== "object") return "";
      const keys = ["secret", "key", "seed", "otpKey", "otp_key", "otpSecret", "totpSecret", "sKey", "skey", "bindKey", "otpkey", "SECRET", "otpCd"];
      for (const k of keys) {
        if (o[k]) {
          const v = String(o[k]).toUpperCase().replace(/[^A-Z2-7]/g, "");
          if (v.length >= 16) return v;
        }
      }
      for (const k of Object.keys(o)) {
        const hit = walk(o[k]);
        if (hit) return hit;
      }
      return "";
    };
    acc.secret = walk(obj);
    if (acc.secret.length < 16) throw new Error("這張 QR 的 JSON 沒有金鑰");
    return acc;
  }
  if (/^otpauth-migration:\/\//i.test(compact)) throw new Error("這是 Google Authenticator 匯出，請改截 SCM／A101 綁定 QR。");
  const b32 = compact.toUpperCase().replace(/[^A-Z2-7]/g, "");
  if (b32.length >= 16) {
    acc.secret = b32;
    return acc;
  }
  throw new Error("讀到的不是金鑰 QR。請上傳 SCM 綁定當下那張截圖。");
}
async function decodeImageFile(file) {
  const url = URL.createObjectURL(file);
  try {
    const img = await new Promise(function (resolve, reject) {
      const el = new Image();
      el.onload = function () { resolve(el); };
      el.onerror = function () { reject(new Error("圖片打不開")); };
      el.src = url;
    });
    const canvas = document.createElement("canvas");
    canvas.width = img.naturalWidth || img.width;
    canvas.height = img.naturalHeight || img.height;
    const ctx = canvas.getContext("2d");
    ctx.drawImage(img, 0, 0);
    const pix = ctx.getImageData(0, 0, canvas.width, canvas.height);
    if (typeof jsQR === "function") {
      const r = jsQR(pix.data, pix.width, pix.height);
      if (r && r.data) return r.data;
    }
    if ("BarcodeDetector" in window) {
      const det = new BarcodeDetector({ formats: ["qr_code"] });
      const codes = await det.detect(canvas);
      if (codes && codes[0] && codes[0].rawValue) return codes[0].rawValue;
    }
    throw new Error("圖片裡找不到 QR，請截清楚一點再傳。");
  } finally {
    URL.revokeObjectURL(url);
  }
}

let pack = { selected: "", accounts: [] };
let pending = null;
let gh = { owner: "", repo: "scm-otp", branch: "main", vaultPath: "docs/vault.json", token: "" };
let timer = null;
let timeOffsetMs = 0;
let savedOnGithub = false;
function nowSec() {
  return Math.floor((Date.now() + timeOffsetMs) / 1000);
}

function guessOwner() {
  const h = location.hostname;
  if (h.endsWith(".github.io")) return h.replace(".github.io", "");
  return "";
}
function guessRepo() {
  const parts = location.pathname.split("/").filter(Boolean);
  if (parts.length && location.hostname.endsWith(".github.io")) return parts[0];
  return "scm-otp";
}
function setSaveState(ok, msg) {
  savedOnGithub = !!ok;
  const warn = $("saveWarn");
  const retry = $("btnRetry");
  const st = $("status");
  if (ok) {
    warn.classList.add("hidden");
    retry.classList.add("hidden");
    st.className = "status";
    st.textContent = msg || ("倉庫已保存 " + (pack.accounts || []).length + " 筆，換電腦或清快取都不必再傳 QR。");
  } else {
    const n = (pack.accounts || []).length;
    if (n > 0) {
      warn.classList.remove("hidden");
      retry.classList.remove("hidden");
      st.className = "status warn";
      st.textContent = msg || "這 " + n + " 筆還沒寫進 GitHub，關掉分頁就會不見。";
    } else {
      warn.classList.add("hidden");
      retry.classList.add("hidden");
      st.className = "status warn";
      st.textContent = msg || "倉庫還沒有 OTP。請先 ⚙ 填 Token，再 ＋ 上傳綁定 QR。";
    }
  }
}

async function loadGhConfig() {
  try {
    const j = await (await fetch("./gh-config.json", { cache: "no-store" })).json();
    gh.owner = j.owner || guessOwner() || gh.owner;
    gh.repo = j.repo || guessRepo() || gh.repo;
    gh.branch = j.branch || "main";
    gh.vaultPath = j.vaultPath || "docs/vault.json";
  } catch (e) {
    gh.owner = guessOwner();
  }
  $("fOwner").value = gh.owner;
  $("fRepo").value = gh.repo;
  $("fBranch").value = gh.branch;
  $("fVaultPath").value = gh.vaultPath;
}

async function loadVaultFile() {
  const r = await fetch("./vault.json", { cache: "no-store" });
  if (!r.ok) throw new Error("讀不到 vault.json");
  const j = await r.json();
  if (j && Array.isArray(j.accounts)) pack = { selected: j.selected || "", accounts: j.accounts };
  else pack = { selected: "", accounts: [] };
}

function paint(rows) {
  const host = $("list");
  const hint = $("hint");
  if (!rows || !rows.length) {
    host.innerHTML = "";
    return;
  }
  host.innerHTML = rows.map(function (r) {
    return (
      "<article class=\"row\" data-id=\"" + r.id + "\">" +
      "<div class=\"strip\"></div>" +
      "<div class=\"body\">" +
      "<p class=\"code\">" + fmtCode(r.code) + "</p>" +
      "<div class=\"meta\">" +
      "<div>統編<b>" + (r.tax || "") + "</b></div>" +
      "<div>廠編<b>" + (r.vendor || "") + "</b></div>" +
      "<div>使用人<b>" + (r.person || "") + "</b></div>" +
      "</div></div>" +
      "<div class=\"pick\"><span class=\"dot" + (r.selected ? " on" : "") + "\"></span></div>" +
      "</article>"
    );
  }).join("");
}

async function refresh() {
  const accs = pack.accounts || [];
  const now = nowSec();
  const rows = [];
  for (const a of accs) {
    const code = await totpAt(a.secret, a.period || 60, a.digits || 6, now);
    rows.push({
      id: a.id,
      code: code,
      tax: a.tax || "",
      vendor: a.vendor || "",
      person: a.person || "",
      selected: pack.selected === a.id
    });
  }
  paint(rows);
}

function hasToken() {
  gh.token = gh.token || ($("fToken") && $("fToken").value.trim()) || "";
  gh.owner = gh.owner || ($("fOwner") && $("fOwner").value.trim()) || guessOwner();
  gh.repo = gh.repo || ($("fRepo") && $("fRepo").value.trim()) || guessRepo();
  return !!(gh.token && gh.owner && gh.repo);
}
async function persist() {
  const payload = { selected: pack.selected || "", accounts: pack.accounts || [] };
  const text = JSON.stringify(payload);
  if (!hasToken()) {
    setSaveState(false, "請先按 ⚙ 填 GitHub Token，否則 QR 金鑰不會進倉庫。");
    $("dlgGh").showModal();
    throw new Error("請先填 GitHub Token，金鑰必須寫進倉庫。");
  }
  const path = gh.vaultPath || "docs/vault.json";
  const api = "https://api.github.com/repos/" + encodeURIComponent(gh.owner) + "/" + encodeURIComponent(gh.repo) + "/contents/" + path.split("/").map(encodeURIComponent).join("/");
  const hdrs = { Authorization: "Bearer " + gh.token, Accept: "application/vnd.github+json" };
  const get = await fetch(api + "?ref=" + encodeURIComponent(gh.branch || "main"), { headers: hdrs });
  let sha = "";
  if (get.ok) {
    const cur = await get.json();
    sha = cur.sha || "";
  }
  const body = {
    message: "save otp vault",
    content: btoa(unescape(encodeURIComponent(text))),
    branch: gh.branch || "main"
  };
  if (sha) body.sha = sha;
  const put = await fetch(api, {
    method: "PUT",
    headers: Object.assign({ "Content-Type": "application/json" }, hdrs),
    body: JSON.stringify(body)
  });
  if (!put.ok) {
    const err = await put.text();
    setSaveState(false, "寫回 GitHub 失敗。");
    throw new Error("寫回 GitHub 失敗：" + err.slice(0, 180));
  }
  const check = await fetch(api + "?ref=" + encodeURIComponent(gh.branch || "main"), { headers: hdrs });
  if (!check.ok) throw new Error("寫入後讀回失敗，請再按「再存進 GitHub」。");
  const checked = await check.json();
  const decoded = JSON.parse(decodeURIComponent(escape(atob(checked.content.replace(/\n/g, "")))));
  if (!decoded.accounts || decoded.accounts.length !== payload.accounts.length) {
    setSaveState(false, "倉庫筆數不對，請再存一次。");
    throw new Error("倉庫確認失敗，請再按「再存進 GitHub」。");
  }
  setSaveState(true);
  $("hint").textContent = "已寫進 GitHub。約一分鐘後換電腦開同一網址即可，不必再傳 QR。";
  $("hint").style.color = "";
}

$("list").addEventListener("click", function (ev) {
  const row = ev.target.closest(".row");
  if (!row) return;
  pack.selected = row.getAttribute("data-id");
  refresh();
});

$("btnDel").addEventListener("click", async function () {
  if (!pack.selected) { $("hint").textContent = "請先點一筆再刪。"; return; }
  if (!confirm("刪除目前選取的這組 OTP？")) return;
  pack.accounts = (pack.accounts || []).filter(function (a) { return a.id !== pack.selected; });
  pack.selected = pack.accounts[0] ? pack.accounts[0].id : "";
  try { await persist(); } catch (e) { $("hint").textContent = e.message; $("hint").style.color = "#8a1c1c"; }
  await refresh();
});

async function syncTime() {
  $("hint").textContent = "校時中…";
  $("hint").style.color = "";
  const t0 = Date.now();
  try {
    const r = await fetch("./vault.json?ts=" + Date.now(), { cache: "no-store" });
    const t1 = Date.now();
    const hdr = r.headers.get("Date");
    if (!hdr) throw new Error("伺服器沒有提供時間");
    const mid = (t0 + t1) / 2;
    timeOffsetMs = new Date(hdr).getTime() - mid;
    const sec = Math.round(timeOffsetMs / 1000);
    $("hint").textContent = sec === 0
      ? "校時完成，與網路時間一致。"
      : ("校時完成，已校正 " + (sec > 0 ? "+" : "") + sec + " 秒。");
    await refresh();
  } catch (e) {
    $("hint").textContent = "校時失敗：" + (e.message || "請確認有網路。");
    $("hint").style.color = "#8a1c1c";
  }
}
$("btnSync").addEventListener("click", function () { syncTime(); });
$("btnGear").addEventListener("click", function () {
  $("ghMsg").textContent = "";
  $("dlgGh").showModal();
});
$("ghCancel").addEventListener("click", function () { $("dlgGh").close(); });
$("ghForm").addEventListener("submit", function (ev) {
  ev.preventDefault();
  gh.owner = $("fOwner").value.trim();
  gh.repo = $("fRepo").value.trim();
  gh.branch = $("fBranch").value.trim() || "main";
  gh.vaultPath = $("fVaultPath").value.trim() || "docs/vault.json";
  gh.token = $("fToken").value.trim();
  $("dlgGh").close();
});

$("fileQr").addEventListener("change", async function () {
  const file = this.files && this.files[0];
  this.value = "";
  if (!file) return;
  $("hint").textContent = "讀取 QR…";
  try {
    const raw = await decodeImageFile(file);
    pending = parseQrText(raw);
    $("fTax").value = pending.tax || "";
    $("fVendor").value = pending.vendor || "";
    $("fPerson").value = pending.person || "";
    $("dlgMsg").textContent = "已讀到金鑰，請確認統編／廠編／使用人。";
    $("dlg").showModal();
  } catch (e) {
    $("hint").textContent = e.message || "讀取失敗";
    $("hint").style.color = "#8a1c1c";
  }
});
$("dlgCancel").addEventListener("click", function () { $("dlg").close(); pending = null; });
$("dlgForm").addEventListener("submit", async function (ev) {
  ev.preventDefault();
  if (!pending) { $("dlg").close(); return; }
  const row = {
    id: (Date.now().toString(36) + Math.random().toString(36).slice(2, 8)),
    secret: pending.secret,
    period: pending.period,
    digits: pending.digits,
    tax: $("fTax").value.trim(),
    vendor: $("fVendor").value.trim(),
    person: $("fPerson").value.trim()
  };
  pack.accounts = pack.accounts || [];
  if (pack.accounts.some(function (a) { return a.secret === row.secret; })) {
    $("dlgMsg").textContent = "這組 QR 已經在倉庫裡。";
    return;
  }
  pack.accounts.push(row);
  pack.selected = row.id;
  try {
    await persist();
    $("dlg").close();
    pending = null;
    await refresh();
  } catch (e) {
    $("dlgMsg").textContent = e.message || "儲存失敗";
  }
});

$("btnRetry").addEventListener("click", async function () {
  try { await persist(); await refresh(); } catch (e) {
    $("hint").textContent = e.message;
    $("hint").style.color = "#8a1c1c";
  }
});
window.addEventListener("beforeunload", function (ev) {
  if (!savedOnGithub && pack.accounts && pack.accounts.length) {
    ev.preventDefault();
    ev.returnValue = "";
  }
});

$("saveWarn").textContent = "QR 金鑰還在這個分頁，尚未寫進 GitHub。關掉或換電腦就會遺失，請按 ⚙ 填 Token 後按「再存進 GitHub」。";
$("ghHint").textContent = "第一次用 ＋ 上傳 QR 後，要用 Token 把 vault.json 寫回倉庫。之後換電腦或清快取直接開網址就能看 OTP。Token 只留在這個分頁。";

(async function boot() {
  await loadGhConfig();
  try {
    await loadVaultFile();
    setSaveState((pack.accounts || []).length > 0);
  } catch (e) {
    pack = { selected: "", accounts: [] };
    setSaveState(false, "讀不到 vault.json，請確認已開 GitHub Pages。");
  }
  if (!timer) timer = setInterval(refresh, 1000);
  await refresh();
  syncTime();
})();
