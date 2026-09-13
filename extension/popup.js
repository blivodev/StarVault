/**
 * StarVault Browser Companion - Popup Controller
 * Manages zero-knowledge credentials, multi-dimensional search & filtering,
 * key/cert studio, crypto helpers, smart auto-organize, and CSV export.
 */

const BRIDGE_URL = "http://127.0.0.1:8088";
const THEMES = ["dark", "blue", "console", "cyberpunk", "light"];

let currentTabUrl = "";
let currentTabDomain = "";
let activeFilterType = "all";
let activeFilterStatus = "all";
let currentSortBy = "natural";
let currentSortReverse = false;
let genMode = "password";

document.addEventListener("DOMContentLoaded", async () => {
  initTheme();
  setupEventListeners();
  await detectActiveTab();
  await checkBridgeStatus();
});

// =============================================================================
// Theme Management
// =============================================================================

function initTheme() {
  const saved = localStorage.getItem("starvault_theme") || "dark";
  document.documentElement.setAttribute("data-theme", saved);
}

function cycleTheme() {
  const curr = document.documentElement.getAttribute("data-theme") || "dark";
  const nextIdx = (THEMES.indexOf(curr) + 1) % THEMES.length;
  const nextTheme = THEMES[nextIdx];
  document.documentElement.setAttribute("data-theme", nextTheme);
  localStorage.setItem("starvault_theme", nextTheme);
  showToast(`Theme: ${nextTheme.toUpperCase()}`);
}

// =============================================================================
// Event Handlers Setup
// =============================================================================

function setupEventListeners() {
  // Header Actions
  document.getElementById("themeToggleBtn").addEventListener("click", cycleTheme);
  document.getElementById("lockBtn").addEventListener("click", lockVault);
  document.getElementById("retryBtn").addEventListener("click", checkBridgeStatus);
  document.getElementById("connectRetryBtn").addEventListener("click", checkBridgeStatus);

  // Search & Filter
  const searchInput = document.getElementById("searchInput");
  const clearSearchBtn = document.getElementById("clearSearchBtn");

  searchInput.addEventListener("input", () => {
    if (searchInput.value) {
      clearSearchBtn.classList.remove("hidden");
    } else {
      clearSearchBtn.classList.add("hidden");
    }
    triggerSearch();
  });

  clearSearchBtn.addEventListener("click", () => {
    searchInput.value = "";
    clearSearchBtn.classList.add("hidden");
    triggerSearch();
  });

  // Filter Chips
  const chipContainer = document.getElementById("filterChips");
  chipContainer.addEventListener("click", (e) => {
    const chip = e.target.closest(".chip");
    if (!chip) return;

    chipContainer.querySelectorAll(".chip").forEach((c) => c.classList.remove("active"));
    chip.classList.add("active");

    const f = chip.getAttribute("data-filter");
    if (f === "expiring" || f === "weak" || f === "totp") {
      activeFilterStatus = f;
      activeFilterType = "all";
    } else if (f === "favorite") {
      activeFilterStatus = "favorite";
      activeFilterType = "all";
    } else {
      activeFilterType = f;
      activeFilterStatus = "all";
    }
    triggerSearch();
  });

  // Sorting
  const sortSelect = document.getElementById("sortSelect");
  const sortDirBtn = document.getElementById("sortDirBtn");

  sortSelect.addEventListener("change", () => {
    currentSortBy = sortSelect.value;
    triggerSearch();
  });

  sortDirBtn.addEventListener("click", () => {
    currentSortReverse = !currentSortReverse;
    sortDirBtn.textContent = currentSortReverse ? "▼" : "▲";
    triggerSearch();
  });

  // Auto Fill Active Tab
  document.getElementById("tabFillBtn").addEventListener("click", () => {
    const firstFill = document.querySelector(".btn-fill");
    if (firstFill) {
      firstFill.click();
    } else {
      showToast("No credentials found for this page");
    }
  });

  // Generator / Key Studio Drawer
  setupGeneratorDrawer();

  // Crypto / TLS Studio Drawer
  setupCryptoDrawer();

  // Smart Auto-Organize Drawer
  setupOrganizeDrawer();

  // CSV Export Modal
  setupExportModal();

  // Save Login Drawer
  setupSaveDrawer();
}

// =============================================================================
// Drawer Setups
// =============================================================================

function closeAllDrawers() {
  document.getElementById("genDrawer").classList.add("hidden");
  document.getElementById("cryptoDrawer").classList.add("hidden");
  document.getElementById("organizeDrawer").classList.add("hidden");
  document.getElementById("exportModal").classList.add("hidden");
  document.getElementById("saveDrawer").classList.add("hidden");
}

function setupGeneratorDrawer() {
  const openGenBtn = document.getElementById("openGenBtn");
  const genDrawer = document.getElementById("genDrawer");
  const closeGenBtn = document.getElementById("closeGenBtn");

  const modePass = document.getElementById("genModePass");
  const modeKey = document.getElementById("genModeKey");
  const modeSsh = document.getElementById("genModeSsh");

  const passSection = document.getElementById("passSection");
  const keySection = document.getElementById("keySection");
  const sshSection = document.getElementById("sshSection");

  openGenBtn.addEventListener("click", () => {
    closeAllDrawers();
    genDrawer.classList.remove("hidden");
    triggerKeyGen();
  });
  closeGenBtn.addEventListener("click", () => genDrawer.classList.add("hidden"));

  modePass.addEventListener("click", () => {
    genMode = "password";
    modePass.classList.add("active");
    modeKey.classList.remove("active");
    modeSsh.classList.remove("active");
    passSection.classList.remove("hidden");
    keySection.classList.add("hidden");
    sshSection.classList.add("hidden");
    triggerKeyGen();
  });

  modeKey.addEventListener("click", () => {
    genMode = "key";
    modeKey.classList.add("active");
    modePass.classList.remove("active");
    modeSsh.classList.remove("active");
    keySection.classList.remove("hidden");
    passSection.classList.add("hidden");
    sshSection.classList.add("hidden");
    triggerKeyGen();
  });

  modeSsh.addEventListener("click", () => {
    genMode = "ssh";
    modeSsh.classList.add("active");
    modePass.classList.remove("active");
    modeKey.classList.remove("active");
    sshSection.classList.remove("hidden");
    passSection.classList.add("hidden");
    keySection.classList.add("hidden");
  });

  // Password Options
  const lengthSlider = document.getElementById("lengthSlider");
  const lengthVal = document.getElementById("lengthVal");
  lengthSlider.addEventListener("input", (e) => {
    lengthVal.textContent = e.target.value;
    generatePassword();
  });
  document.getElementById("refreshGenBtn").addEventListener("click", generatePassword);
  document.getElementById("copyGenBtn").addEventListener("click", () => {
    const val = document.getElementById("genPasswordInput").value;
    if (val) {
      navigator.clipboard.writeText(val);
      showToast("Password copied!");
    }
  });

  // API Key Options
  document.getElementById("keyFormatSelect").addEventListener("change", generateApiKey);
  document.getElementById("refreshApiKeyBtn").addEventListener("click", generateApiKey);
  document.getElementById("copyApiKeyBtn").addEventListener("click", () => {
    const val = document.getElementById("genApiKeyInput").value;
    if (val) {
      navigator.clipboard.writeText(val);
      showToast("API Key copied!");
    }
  });

  // SSH / WG Keygen
  document.getElementById("runKeygenBtn").addEventListener("click", generateKeypair);
  document.getElementById("copyPubKeyBtn").addEventListener("click", () => {
    const v = document.getElementById("sshPublicKeyOutput").value;
    if (v) {
      navigator.clipboard.writeText(v);
      showToast("Public key copied!");
    }
  });
  document.getElementById("copyPrivKeyBtn").addEventListener("click", () => {
    const v = document.getElementById("sshPrivateKeyOutput").value;
    if (v) {
      navigator.clipboard.writeText(v);
      showToast("Private key copied!");
    }
  });
}

function setupCryptoDrawer() {
  const openCryptoBtn = document.getElementById("openCryptoBtn");
  const cryptoDrawer = document.getElementById("cryptoDrawer");
  const closeCryptoBtn = document.getElementById("closeCryptoBtn");
  const cryptoOpSelect = document.getElementById("cryptoOpSelect");
  const cryptoKeyInput = document.getElementById("cryptoKeyInput");
  const tlsOptions = document.getElementById("tlsOptions");

  openCryptoBtn.addEventListener("click", () => {
    closeAllDrawers();
    cryptoDrawer.classList.remove("hidden");
  });
  closeCryptoBtn.addEventListener("click", () => cryptoDrawer.classList.add("hidden"));

  cryptoOpSelect.addEventListener("change", () => {
    const op = cryptoOpSelect.value;
    if (op === "encrypt" || op === "decrypt" || op === "hmac") {
      cryptoKeyInput.classList.remove("hidden");
      tlsOptions.classList.add("hidden");
    } else if (op === "tls_cert") {
      cryptoKeyInput.classList.add("hidden");
      tlsOptions.classList.remove("hidden");
    } else {
      cryptoKeyInput.classList.add("hidden");
      tlsOptions.classList.add("hidden");
    }
  });

  document.getElementById("runCryptoBtn").addEventListener("click", runCryptoTool);
  document.getElementById("copyCryptoBtn").addEventListener("click", () => {
    const out = document.getElementById("cryptoOutput").value;
    if (out) {
      navigator.clipboard.writeText(out);
      showToast("Result copied!");
    }
  });
}

function setupOrganizeDrawer() {
  const openOrganizeBtn = document.getElementById("openOrganizeBtn");
  const organizeDrawer = document.getElementById("organizeDrawer");
  const closeOrganizeBtn = document.getElementById("closeOrganizeBtn");

  openOrganizeBtn.addEventListener("click", () => {
    closeAllDrawers();
    organizeDrawer.classList.remove("hidden");
  });
  closeOrganizeBtn.addEventListener("click", () => organizeDrawer.classList.add("hidden"));

  document.getElementById("btnAutoOrganize").addEventListener("click", async () => {
    const box = document.getElementById("organizeStatusBox");
    box.classList.remove("hidden");
    box.textContent = "⏳ Running smart classification & auto-tagging...";
    try {
      const res = await fetch(`${BRIDGE_URL}/api/auto_organize`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ override_categories: false, dry_run: false }),
      });
      const data = await res.json();
      if (data.success) {
        box.innerHTML = `
          <strong>✓ Vault Organized!</strong><br>
          • Categories Updated: ${data.categories_updated}<br>
          • Tags Added: ${data.tags_added}<br>
          • Titles Normalized: ${data.titles_normalized}
        `;
        showToast("Auto-organize complete!");
        triggerSearch();
      } else {
        box.textContent = `Error: ${data.error}`;
      }
    } catch (e) {
      box.textContent = "Error: Desktop bridge offline";
    }
  });

  document.getElementById("btnDeduplicate").addEventListener("click", async () => {
    const box = document.getElementById("organizeStatusBox");
    box.classList.remove("hidden");
    box.textContent = "⏳ Scanning for duplicate entries...";
    try {
      const res = await fetch(`${BRIDGE_URL}/api/deduplicate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ auto_merge: true }),
      });
      const data = await res.json();
      if (data.success) {
        box.innerHTML = `<strong>✓ Deduplication Complete!</strong><br>• Merged Duplicates: ${data.merged_count}`;
        showToast("Deduplication complete!");
        triggerSearch();
      } else {
        box.textContent = `Error: ${data.error}`;
      }
    } catch (e) {
      box.textContent = "Error: Desktop bridge offline";
    }
  });
}

function setupExportModal() {
  const exportCsvBtn = document.getElementById("exportCsvBtn");
  const exportModal = document.getElementById("exportModal");
  const closeExportBtn = document.getElementById("closeExportBtn");
  const submitExportBtn = document.getElementById("submitExportBtn");

  exportCsvBtn.addEventListener("click", () => {
    closeAllDrawers();
    exportModal.classList.remove("hidden");
    document.getElementById("exportMasterPassword").focus();
  });
  closeExportBtn.addEventListener("click", () => exportModal.classList.add("hidden"));

  submitExportBtn.addEventListener("click", async () => {
    const pwd = document.getElementById("exportMasterPassword").value;
    const kf = document.getElementById("exportKeyfileToken").value.trim() || null;
    const statusBox = document.getElementById("exportStatus");

    if (!pwd) {
      statusBox.classList.remove("hidden");
      statusBox.style.color = "#EF4444";
      statusBox.textContent = "Master password is required.";
      return;
    }

    statusBox.classList.remove("hidden");
    statusBox.style.color = "#00E5FF";
    statusBox.textContent = "Authenticating & generating CSV...";

    try {
      const res = await fetch(`${BRIDGE_URL}/api/export_csv`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ master_password: pwd, keyfile_secret: kf }),
      });
      const data = await res.json();

      if (data.success && data.csv) {
        const blob = new Blob([data.csv], { type: "text/csv;charset=utf-8;" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `starvault_credentials_${new Date().toISOString().slice(0, 10)}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        statusBox.style.color = "#10B981";
        statusBox.textContent = `✓ Exported ${data.count} credentials!`;
        showToast("CSV Downloaded!");
        setTimeout(() => {
          exportModal.classList.add("hidden");
          document.getElementById("exportMasterPassword").value = "";
        }, 1500);
      } else {
        statusBox.style.color = "#EF4444";
        statusBox.textContent = `Export failed: ${data.error || "Incorrect password"}`;
      }
    } catch (e) {
      statusBox.style.color = "#EF4444";
      statusBox.textContent = "Export error: Bridge offline";
    }
  });
}

function setupSaveDrawer() {
  const openSaveBtn = document.getElementById("openSaveBtn");
  const saveDrawer = document.getElementById("saveDrawer");
  const closeSaveBtn = document.getElementById("closeSaveBtn");
  const submitSaveBtn = document.getElementById("submitSaveBtn");

  openSaveBtn.addEventListener("click", () => {
    closeAllDrawers();
    saveDrawer.classList.remove("hidden");
    document.getElementById("saveUrlInput").value = currentTabUrl;
    document.getElementById("saveTitleInput").value = currentTabDomain;
  });
  closeSaveBtn.addEventListener("click", () => saveDrawer.classList.add("hidden"));
  submitSaveBtn.addEventListener("click", saveNewLogin);
}

// =============================================================================
// Bridge & Vault Status
// =============================================================================

async function detectActiveTab() {
  try {
    if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.query) {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs && tabs[0] && tabs[0].url) {
        currentTabUrl = tabs[0].url;
        try {
          const u = new URL(currentTabUrl);
          currentTabDomain = u.hostname;
          document.getElementById("searchInput").placeholder = `Search (${currentTabDomain})...`;
        } catch (e) {}
      }
    }
  } catch (e) {
    console.error("Tab detection failed:", e);
  }
}

async function checkBridgeStatus() {
  const badge = document.getElementById("statusBadge");
  const lockedView = document.getElementById("lockedView");
  const disconnectedView = document.getElementById("disconnectedView");
  const loginsView = document.getElementById("loginsView");

  try {
    const res = await fetch(`${BRIDGE_URL}/api/status`);
    if (!res.ok) throw new Error("Bridge offline");
    const data = await res.json();

    if (data.unlocked) {
      badge.textContent = "Unlocked";
      badge.className = "badge badge-online";
      lockedView.classList.add("hidden");
      disconnectedView.classList.add("hidden");
      loginsView.classList.remove("hidden");
      triggerSearch();
    } else {
      badge.textContent = "Locked";
      badge.className = "badge badge-locked";
      lockedView.classList.remove("hidden");
      disconnectedView.classList.add("hidden");
      loginsView.classList.add("hidden");
    }
  } catch (e) {
    badge.textContent = "Offline";
    badge.className = "badge badge-offline";
    disconnectedView.classList.remove("hidden");
    lockedView.classList.add("hidden");
    loginsView.classList.add("hidden");
  }
}

// =============================================================================
// Search, Filter & Render Logins
// =============================================================================

function triggerSearch() {
  const query = document.getElementById("searchInput").value.trim();
  searchVault(query);
}

async function searchVault(query) {
  const loginsView = document.getElementById("loginsView");
  const countBadge = document.getElementById("itemsCountBadge");

  try {
    const res = await fetch(`${BRIDGE_URL}/api/search`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        query: query || "",
        url: currentTabUrl,
        filter_type: activeFilterType,
        filter_status: activeFilterStatus,
        sort_by: currentSortBy,
        sort_reverse: currentSortReverse,
      }),
    });

    if (!res.ok) return;
    const data = await res.json();
    const items = data.matches || [];
    countBadge.textContent = `${items.length} item${items.length === 1 ? "" : "s"}`;
    renderLogins(items);
  } catch (e) {
    console.error("Search error:", e);
  }
}

function renderLogins(items) {
  const loginsView = document.getElementById("loginsView");
  loginsView.innerHTML = "";

  if (!items || items.length === 0) {
    loginsView.innerHTML = `
      <div class="empty-state" style="text-align: center; padding: 40px 10px; color: var(--text-muted);">
        <p style="font-size: 12px; margin-bottom: 8px;">No matching credentials found.</p>
        <button class="btn btn-secondary" id="emptyAddBtn">+ Add for this site</button>
      </div>
    `;
    const btn = document.getElementById("emptyAddBtn");
    if (btn) {
      btn.addEventListener("click", () => {
        document.getElementById("openSaveBtn").click();
      });
    }
    return;
  }

  items.forEach((item) => {
    const card = document.createElement("div");
    card.className = "login-card";

    // Type styling
    let typeClass = "type-service";
    let typeText = "SERVICE";
    if (item.type === "server") {
      typeClass = "type-server";
      typeText = "SERVER";
    } else if (item.type === "apikey") {
      typeClass = "type-apikey";
      typeText = "API KEY";
    } else if (item.type === "keypair") {
      typeClass = "type-keypair";
      typeText = "KEY";
    }

    // Mini status badges
    let statusBadgesHtml = "";
    if (item.is_expiring) {
      statusBadgesHtml += '<span class="mini-badge mini-badge-warn">⏳ Expiring</span>';
    }
    if (item.is_weak) {
      statusBadgesHtml += '<span class="mini-badge mini-badge-danger">⚠️ Weak</span>';
    }
    if (item.has_totp) {
      statusBadgesHtml += '<span class="mini-badge mini-badge-totp">📱 2FA</span>';
    }

    card.innerHTML = `
      <div class="card-top-row">
        <div class="card-title-group">
          <span class="fav-star ${item.is_favorite ? "active" : ""}" title="Toggle Favorite">★</span>
          <span class="type-pill ${typeClass}">${typeText}</span>
          <span class="login-title" title="${escapeHtml(item.title)}">${escapeHtml(item.title)}</span>
        </div>
        <div class="card-status-badges">
          ${statusBadgesHtml}
        </div>
      </div>
      <div class="card-sub-row">
        <span class="card-user" title="${escapeHtml(item.username || item.url || "")}">
          ${escapeHtml(item.username || item.url || item.hostname || "No user")}
        </span>
        <span class="card-category">${escapeHtml(item.category || "")}</span>
      </div>
      <div class="login-actions">
        ${item.username ? '<button class="btn-action btn-copy-user" title="Copy Username">👤 User</button>' : ""}
        ${item.has_password ? '<button class="btn-action btn-copy-pass" title="Copy Password">🔑 Pass</button>' : ""}
        ${item.type === "apikey" ? '<button class="btn-action btn-copy-key" title="Copy API Key">🎟️ Key</button>' : ""}
        ${item.type === "keypair" ? '<button class="btn-action btn-copy-pub" title="Copy Public Key">📋 Pub</button>' : ""}
        ${item.has_totp ? '<button class="btn-action btn-copy-totp" title="Copy 2FA TOTP Code">⏱️ 2FA</button>' : ""}
        <button class="btn-action btn-fill" title="Auto-fill login fields">⚡ Fill</button>
      </div>
    `;

    // Bind Favorite Click
    card.querySelector(".fav-star").addEventListener("click", async (e) => {
      e.stopPropagation();
      await toggleFavorite(item.id);
    });

    // Action clicks
    card.querySelector(".btn-fill").addEventListener("click", () => fillCredentials(item.id));
    const uBtn = card.querySelector(".btn-copy-user");
    if (uBtn) uBtn.addEventListener("click", () => copyCredential(item.id, "username"));
    const pBtn = card.querySelector(".btn-copy-pass");
    if (pBtn) pBtn.addEventListener("click", () => copyCredential(item.id, "password"));
    const kBtn = card.querySelector(".btn-copy-key");
    if (kBtn) kBtn.addEventListener("click", () => copyCredential(item.id, "api_token"));
    const pubBtn = card.querySelector(".btn-copy-pub");
    if (pubBtn) pubBtn.addEventListener("click", () => copyCredential(item.id, "public_key"));
    const totpBtn = card.querySelector(".btn-copy-totp");
    if (totpBtn) totpBtn.addEventListener("click", () => copyCredential(item.id, "totp"));

    loginsView.appendChild(card);
  });
}

// =============================================================================
// Actions: Fill, Copy & Favorites
// =============================================================================

async function toggleFavorite(entryId) {
  try {
    const res = await fetch(`${BRIDGE_URL}/api/toggle_favorite`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ entry_id: entryId }),
    });
    if (res.ok) {
      triggerSearch();
    }
  } catch (e) {}
}

async function fillCredentials(entryId) {
  try {
    const res = await fetch(`${BRIDGE_URL}/api/get_credentials`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ entry_id: entryId }),
    });

    if (!res.ok) throw new Error("Fetch failed");
    const creds = await res.json();

    if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.sendMessage) {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs && tabs[0]) {
        chrome.tabs.sendMessage(tabs[0].id, {
          action: "FILL_CREDENTIALS",
          username: creds.username,
          password: creds.password,
        });
        showToast("Injected credentials into active page!");
      }
    }
  } catch (e) {
    showToast("Auto-fill failed");
  }
}

async function copyCredential(entryId, field) {
  try {
    const res = await fetch(`${BRIDGE_URL}/api/get_credentials`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ entry_id: entryId }),
    });

    if (!res.ok) throw new Error("Fetch failed");
    const creds = await res.json();

    let val = "";
    if (field === "username") val = creds.username;
    else if (field === "password") val = creds.password;
    else if (field === "api_token") val = creds.api_token;
    else if (field === "public_key") val = creds.public_key;
    else if (field === "totp") val = creds.totp_code;

    if (val) {
      navigator.clipboard.writeText(val);
      showToast(`${field.toUpperCase()} copied!`);
    } else {
      showToast(`${field.toUpperCase()} is empty`);
    }
  } catch (e) {
    showToast("Copy failed");
  }
}

// =============================================================================
// Generation Engines
// =============================================================================

function triggerKeyGen() {
  if (genMode === "password") generatePassword();
  else if (genMode === "key") generateApiKey();
}

async function generatePassword() {
  const len = document.getElementById("lengthSlider").value;
  try {
    const res = await fetch(`${BRIDGE_URL}/api/generate_password`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ length: parseInt(len, 10) }),
    });
    const data = await res.json();
    document.getElementById("genPasswordInput").value = data.password;
  } catch (e) {
    // Local fallback
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()_+";
    let p = "";
    const arr = new Uint8Array(parseInt(len, 10));
    window.crypto.getRandomValues(arr);
    for (let i = 0; i < arr.length; i++) {
      p += chars[arr[i] % chars.length];
    }
    document.getElementById("genPasswordInput").value = p;
  }
}

async function generateApiKey() {
  const fmt = document.getElementById("keyFormatSelect").value;
  try {
    const res = await fetch(`${BRIDGE_URL}/api/generate_api_key`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ format: fmt }),
    });
    const data = await res.json();
    document.getElementById("genApiKeyInput").value = data.key;
  } catch (e) {
    showToast("Key generator offline");
  }
}

async function generateKeypair() {
  const keyType = document.getElementById("keypairTypeSelect").value;
  const comment = document.getElementById("keyCommentInput").value.trim();
  const saveToVault = document.getElementById("saveKeyToVaultCheck").checked;

  try {
    const res = await fetch(`${BRIDGE_URL}/api/generate_key`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        type: keyType,
        comment: comment || "browser-ext@starvault",
        title: comment || `${keyType.toUpperCase()} Keypair`,
        save_to_vault: saveToVault,
      }),
    });
    const data = await res.json();
    if (data.success) {
      document.getElementById("sshPublicKeyOutput").value = data.public_key;
      document.getElementById("sshPrivateKeyOutput").value = data.private_key;
      showToast(saveToVault ? "Keypair generated & saved to StarVault!" : "Keypair generated!");
      if (saveToVault) triggerSearch();
    }
  } catch (e) {
    showToast("Keypair generation failed");
  }
}

// =============================================================================
// Crypto & TLS Tool
// =============================================================================

async function runCryptoTool() {
  const op = document.getElementById("cryptoOpSelect").value;
  const text = document.getElementById("cryptoTextInput").value;
  const key = document.getElementById("cryptoKeyInput").value;
  const out = document.getElementById("cryptoOutput");

  if (op === "tls_cert") {
    const cn = document.getElementById("tlsCommonName").value.trim() || "localhost";
    const sans = document.getElementById("tlsSans").value.split(",").map((s) => s.trim()).filter(Boolean);

    try {
      const res = await fetch(`${BRIDGE_URL}/api/generate_key`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type: "tls_cert", common_name: cn, san_list: sans, validity_days: 365 }),
      });
      const data = await res.json();
      if (data.success) {
        out.value = `${data.public_key}\n\n${data.private_key}`;
        showToast("TLS Certificate Generated!");
      } else {
        out.value = `Error: ${data.error}`;
      }
    } catch (e) {
      out.value = "Error: Bridge offline";
    }
    return;
  }

  if (!text) {
    showToast("Please enter input text");
    return;
  }

  try {
    let operation = op;
    let algo = "SHA-256";

    if (op === "hash512") { operation = "hash"; algo = "SHA-512"; }
    else if (op === "md5") { operation = "hash"; algo = "MD5"; }
    else if (op.startsWith("encode_")) { operation = "encode"; algo = op.replace("encode_", ""); }
    else if (op.startsWith("decode_")) { operation = "decode"; algo = op.replace("decode_", ""); }

    const res = await fetch(`${BRIDGE_URL}/api/crypto_tool`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ operation, text, key, algorithm: algo }),
    });
    const data = await res.json();
    if (data.success) {
      out.value = data.result;
    } else {
      out.value = `Error: ${data.error}`;
    }
  } catch (e) {
    out.value = "Error: Bridge offline";
  }
}

// =============================================================================
// Save New Entry
// =============================================================================

async function saveNewLogin() {
  const title = document.getElementById("saveTitleInput").value.trim();
  const url = document.getElementById("saveUrlInput").value.trim();
  const username = document.getElementById("saveUserInput").value.trim();
  const password = document.getElementById("savePassInput").value;
  const category = document.getElementById("saveCategorySelect").value;
  const tagsStr = document.getElementById("saveTagsInput").value.trim();
  const tags = tagsStr ? tagsStr.split(",").map((t) => t.trim()).filter(Boolean) : ["extension"];

  if (!username && !password) {
    showToast("Please enter username or password");
    return;
  }

  try {
    const res = await fetch(`${BRIDGE_URL}/api/save_entry`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title, url, username, password, category, tags }),
    });
    if (!res.ok) throw new Error("Save failed");
    showToast("Saved to StarVault!");
    document.getElementById("saveDrawer").classList.add("hidden");
    document.getElementById("saveUserInput").value = "";
    document.getElementById("savePassInput").value = "";
    triggerSearch();
  } catch (e) {
    showToast("Failed to save login");
  }
}

// =============================================================================
// Lock & Helper Utilities
// =============================================================================

async function lockVault() {
  try {
    await fetch(`${BRIDGE_URL}/api/lock`, { method: "POST" });
    checkBridgeStatus();
    showToast("Vault locked");
  } catch (e) {}
}

function showToast(msg) {
  const toast = document.getElementById("toast");
  toast.textContent = msg;
  toast.classList.remove("hidden");
  setTimeout(() => toast.classList.add("hidden"), 2500);
}

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
