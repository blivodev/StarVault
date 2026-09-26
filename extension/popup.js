/**
 * StarVault Browser Companion - Popup Controller
 * Manages zero-knowledge credentials, multi-dimensional search & filtering,
 * key/cert studio, crypto helpers, smart auto-organize, and CSV export.
 */

const BRIDGE_URL = "http://127.0.0.1:8088";
const THEMES = [
  "dark",
  "oled",
  "tokyo",
  "catppuccin",
  "gruvbox",
  "one dark",
  "solarized",
  "nord",
  "dracula",
  "console",
  "cyberpunk",
  "light"
];

let currentTabUrl = "";
let currentTabDomain = "";
let activeFilterType = "all";
let activeFilterStatus = "all";
let currentSortBy = "natural";
let currentSortReverse = false;
let genMode = "password";
let searchDebounceTimer = null;

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
  const nextIdx = (THEMES.indexOf(curr.toLowerCase()) + 1) % THEMES.length;
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
  const neuralScanHeaderBtn = document.getElementById("neuralScanHeaderBtn");
  if (neuralScanHeaderBtn) {
    neuralScanHeaderBtn.addEventListener("click", () => {
      closeAllDrawers();
      document.getElementById("organizeDrawer").classList.remove("hidden");
      runNeuralHealthScan();
    });
  }
  document.getElementById("lockBtn").addEventListener("click", lockVault);
  document.getElementById("retryBtn").addEventListener("click", checkBridgeStatus);
  document.getElementById("connectRetryBtn").addEventListener("click", checkBridgeStatus);

  // Search & Filter with Debounce
  const searchInput = document.getElementById("searchInput");
  const clearSearchBtn = document.getElementById("clearSearchBtn");

  searchInput.addEventListener("input", () => {
    if (searchInput.value) {
      clearSearchBtn.classList.remove("hidden");
    } else {
      clearSearchBtn.classList.add("hidden");
    }
    clearTimeout(searchDebounceTimer);
    searchDebounceTimer = setTimeout(triggerSearch, 120);
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

  // Vault Import Modal
  setupImportModal();

  // CSV Export Modal
  setupExportModal();

  // Save Login Drawer
  setupSaveDrawer();

  // Eye Password Toggles
  setupPasswordEyeToggles();
}

function setupPasswordEyeToggles() {
  const pairs = [
    { inputId: "savePassInput", btnId: "toggleSavePassBtn" },
    { inputId: "saveDomainPassInput", btnId: "toggleSaveDomainPassBtn" },
    { inputId: "saveDomainAuthInput", btnId: "toggleSaveDomainAuthBtn" },
    { inputId: "exportMasterPassword", btnId: "toggleExportPassBtn" },
    { inputId: "exportKeyfileToken", btnId: "toggleExportKeyfileBtn" },
    { inputId: "cryptoKeyInput", btnId: "toggleCryptoKeyBtn" },
    { inputId: "importPasswordInput", btnId: "toggleImportPassBtn" },
  ];

  pairs.forEach(({ inputId, btnId }) => {
    const input = document.getElementById(inputId);
    const btn = document.getElementById(btnId);
    if (!input || !btn) return;
    btn.addEventListener("click", () => {
      const isPassword = input.type === "password";
      input.type = isPassword ? "text" : "password";
      btn.textContent = isPassword ? "🔒" : "👁";
    });
  });
}

// =============================================================================
// Drawer Setups
// =============================================================================

function closeAllDrawers() {
  document.getElementById("genDrawer").classList.add("hidden");
  document.getElementById("cryptoDrawer").classList.add("hidden");
  document.getElementById("organizeDrawer").classList.add("hidden");
  document.getElementById("importModal").classList.add("hidden");
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
  const cryptoKeyWrapper = document.getElementById("cryptoKeyWrapper");
  const tlsOptions = document.getElementById("tlsOptions");

  openCryptoBtn.addEventListener("click", () => {
    closeAllDrawers();
    cryptoDrawer.classList.remove("hidden");
  });
  closeCryptoBtn.addEventListener("click", () => cryptoDrawer.classList.add("hidden"));

  cryptoOpSelect.addEventListener("change", () => {
    const op = cryptoOpSelect.value;
    if (op === "encrypt" || op === "decrypt" || op === "chacha20_enc" || op === "chacha20_dec" || op === "hmac") {
      cryptoKeyWrapper.classList.remove("hidden");
      tlsOptions.classList.add("hidden");
    } else if (op === "tls_cert") {
      cryptoKeyWrapper.classList.add("hidden");
      tlsOptions.classList.remove("hidden");
    } else {
      cryptoKeyWrapper.classList.add("hidden");
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

  const importFileBtn = document.getElementById("cryptoImportFileBtn");
  const fileInput = document.getElementById("cryptoFileInput");
  const exportFileBtn = document.getElementById("cryptoExportFileBtn");

  if (importFileBtn && fileInput) {
    importFileBtn.addEventListener("click", () => fileInput.click());
    fileInput.addEventListener("change", () => {
      const file = fileInput.files[0];
      if (file) {
        const reader = new FileReader();
        reader.onload = (e) => {
          document.getElementById("cryptoTextInput").value = e.target.result;
          showToast(`Loaded ${file.name}`);
        };
        reader.readAsText(file);
      }
    });
  }

  if (exportFileBtn) {
    exportFileBtn.addEventListener("click", () => {
      const out = document.getElementById("cryptoOutput").value;
      if (!out) {
        showToast("Output is empty");
        return;
      }
      const op = cryptoOpSelect.value;
      let ext = ".txt";
      if (op.includes("enc") || op === "encrypt") ext = ".enc";
      else if (op === "tls_cert") ext = ".crt";
      const blob = new Blob([out], { type: "text/plain;charset=utf-8;" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `starvault_crypto_output${ext}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      showToast("Saved to file!");
    });
  }
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

  const btnNeural = document.getElementById("btnRunNeuralScan");
  if (btnNeural) {
    btnNeural.addEventListener("click", runNeuralHealthScan);
  }
}

async function runNeuralHealthScan() {
  const box = document.getElementById("neuralResultsBox");
  const gradeBadge = document.getElementById("neuralGradeBadge");
  box.classList.remove("hidden");
  box.innerHTML = '<div style="font-size: 11px; color: var(--text-secondary); text-align: center; padding: 10px;">⏳ Running in-memory local neural inference...</div>';

  try {
    const res = await fetch(`${BRIDGE_URL}/api/neural_health`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    if (!res.ok) throw new Error("Neural scan request failed");
    const data = await res.json();
    if (!data.success) throw new Error(data.error || "Failed");

    const colorMap = {
      "A+": "#10B981",
      "A": "#10B981",
      "B": "#06B6D4",
      "C": "#F59E0B",
      "D": "#EF4444",
      "F": "#DC2626",
    };
    const gradeColor = colorMap[data.letter_grade] || "#10B981";
    if (gradeBadge) {
      gradeBadge.textContent = `Grade ${data.letter_grade} • ${data.safety_index}/100`;
      gradeBadge.style.color = gradeColor;
      gradeBadge.style.background = `${gradeColor}22`;
    }

    let vulnsHtml = "";
    if (data.top_vulnerabilities && data.top_vulnerabilities.length > 0) {
      vulnsHtml = `
        <div class="neural-vulns-list">
          <div style="font-weight: 700; font-size: 11px; margin-bottom: 4px; color: var(--text-primary);">Flagged Risk Items:</div>
          ${data.top_vulnerabilities.map(v => `
            <div class="neural-vuln-item">
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-weight: 600; color: var(--text-primary);">${escapeHtml(v.title)}</span>
                <span class="mini-badge mini-badge-danger">Risk ${v.risk_score}</span>
              </div>
              <div style="color: var(--text-muted); font-size: 9px; margin-top: 2px;">
                ${escapeHtml(v.predicted_class)} ${v.anomalies && v.anomalies.length > 0 ? "• " + escapeHtml(v.anomalies[0]) : ""}
              </div>
            </div>
          `).join("")}
        </div>
      `;
    }

    let recsHtml = "";
    if (data.suggested_optimizations && data.suggested_optimizations.length > 0) {
      recsHtml = `
        <div style="margin-top: 6px; font-size: 10px; color: var(--text-secondary); line-height: 1.3;">
          <strong style="color: var(--text-primary);">Optimization:</strong> ${escapeHtml(data.suggested_optimizations[0])}
        </div>
      `;
    }

    box.innerHTML = `
      <div class="neural-score-row">
        <div class="neural-gauge-large">
          <span class="neural-gauge-num" style="color: ${gradeColor};">${data.safety_index}</span>
          <span class="neural-gauge-label">/ 100</span>
        </div>
        <div class="neural-summary-stats">
          <div>Grade: <strong style="color: ${gradeColor};">${data.letter_grade}</strong></div>
          <div>Anomalies: <strong>${data.anomalies_count}</strong></div>
          <div>High Risk: <strong>${data.high_risk_count}</strong></div>
          <div style="font-size: 9px; color: var(--text-muted);">${data.execution_time_ms}ms • Zero-Knowledge</div>
        </div>
      </div>
      ${vulnsHtml}
      ${recsHtml}
    `;
    showToast(`Neural Scan: Grade ${data.letter_grade} (${data.safety_index}/100)`);
  } catch (e) {
    box.innerHTML = `<div style="color: var(--danger); font-size: 11px; padding: 6px;">Error running neural scan: ${escapeHtml(e.message)}</div>`;
  }
}

function setupImportModal() {
  const importVaultBtn = document.getElementById("importVaultBtn");
  const importModal = document.getElementById("importModal");
  const closeImportBtn = document.getElementById("closeImportBtn");
  const submitImportBtn = document.getElementById("submitImportBtn");
  const importFileInput = document.getElementById("importFileInput");

  if (!importVaultBtn || !importModal) return;

  importVaultBtn.addEventListener("click", () => {
    closeAllDrawers();
    importModal.classList.remove("hidden");
    const statusBox = document.getElementById("importStatus");
    if (statusBox) statusBox.classList.add("hidden");
  });
  closeImportBtn.addEventListener("click", () => importModal.classList.add("hidden"));

  submitImportBtn.addEventListener("click", async () => {
    const file = importFileInput.files[0];
    const statusBox = document.getElementById("importStatus");
    const strategy = document.getElementById("importStrategySelect").value;
    const pwd = document.getElementById("importPasswordInput").value.trim() || null;

    if (!file) {
      statusBox.classList.remove("hidden");
      statusBox.style.color = "#EF4444";
      statusBox.textContent = "Please select a file to import.";
      return;
    }

    statusBox.classList.remove("hidden");
    statusBox.style.color = "#00E5FF";
    statusBox.textContent = `Reading & importing ${file.name}...`;

    try {
      const isBinary = file.name.endsWith(".db") || file.name.endsWith(".sqlite") || file.name.endsWith(".sqlite3") || file.name.endsWith(".sve");
      let contentB64 = "";
      let contentText = "";

      if (isBinary) {
        const buf = await file.arrayBuffer();
        let binaryStr = "";
        const bytes = new Uint8Array(buf);
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
          binaryStr += String.fromCharCode(bytes[i]);
        }
        contentB64 = btoa(binaryStr);
      } else {
        contentText = await file.text();
      }

      const res = await fetch(`${BRIDGE_URL}/api/import_vault`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          filename: file.name,
          content_base64: contentB64,
          content_text: contentText,
          collision_strategy: strategy,
          file_password: pwd,
        }),
      });
      const data = await res.json();

      if (data.success) {
        statusBox.style.color = "#10B981";
        statusBox.textContent = `✓ Import successful! ${data.count || 0} items imported.`;
        showToast("Vault Import Complete!");
        triggerSearch();
        setTimeout(() => {
          importModal.classList.add("hidden");
          importFileInput.value = "";
          document.getElementById("importPasswordInput").value = "";
        }, 2000);
      } else {
        statusBox.style.color = "#EF4444";
        statusBox.textContent = `Import failed: ${data.error || "Unknown error"}`;
      }
    } catch (e) {
      statusBox.style.color = "#EF4444";
      statusBox.textContent = `Import error: ${e.message || "Bridge offline"}`;
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

let saveDrawerMode = "service";

function setupSaveDrawer() {
  const openSaveBtn = document.getElementById("openSaveBtn");
  const saveDrawer = document.getElementById("saveDrawer");
  const closeSaveBtn = document.getElementById("closeSaveBtn");
  const submitSaveBtn = document.getElementById("submitSaveBtn");
  const modeServiceBtn = document.getElementById("saveModeService");
  const modeDomainBtn = document.getElementById("saveModeDomain");
  const serviceFields = document.getElementById("saveServiceFields");
  const domainFields = document.getElementById("saveDomainFields");

  if (modeServiceBtn && modeDomainBtn) {
    modeServiceBtn.addEventListener("click", () => {
      saveDrawerMode = "service";
      modeServiceBtn.classList.add("active");
      modeDomainBtn.classList.remove("active");
      if (serviceFields) serviceFields.classList.remove("hidden");
      if (domainFields) domainFields.classList.add("hidden");
    });

    modeDomainBtn.addEventListener("click", () => {
      saveDrawerMode = "domain";
      modeDomainBtn.classList.add("active");
      modeServiceBtn.classList.remove("active");
      if (domainFields) domainFields.classList.remove("hidden");
      if (serviceFields) serviceFields.classList.add("hidden");
    });
  }

  openSaveBtn.addEventListener("click", async () => {
    closeAllDrawers();
    saveDrawer.classList.remove("hidden");
    document.getElementById("saveUrlInput").value = currentTabUrl;
    document.getElementById("saveTitleInput").value = currentTabDomain;
    const domInput = document.getElementById("saveDomainNameInput");
    if (domInput) domInput.value = currentTabDomain;
    await loadDomainsForSaveDropdown();
  });
  closeSaveBtn.addEventListener("click", () => saveDrawer.classList.add("hidden"));
  submitSaveBtn.addEventListener("click", saveNewLogin);
}

async function loadDomainsForSaveDropdown() {
  const select = document.getElementById("saveParentDomainSelect");
  if (!select) return;
  try {
    const res = await fetch(`${BRIDGE_URL}/api/domains`);
    if (res.ok) {
      const data = await res.json();
      const doms = data.domains || [];
      select.innerHTML = '<option value="">Attach to Domain: None (Standalone)</option>';
      doms.forEach(d => {
        const opt = document.createElement("option");
        opt.value = d.id;
        opt.textContent = `Attached to: ${d.title} (${d.domain_name || d.url})`;
        select.appendChild(opt);
      });
    }
  } catch (e) {}
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

    // Sync theme with desktop if available
    try {
      const themeRes = await fetch(`${BRIDGE_URL}/api/theme`);
      if (themeRes.ok) {
        const themeData = await themeRes.json();
        if (themeData && themeData.theme) {
          const tName = themeData.theme.toLowerCase();
          if (THEMES.includes(tName)) {
            document.documentElement.setAttribute("data-theme", tName);
            localStorage.setItem("starvault_theme", tName);
          }
        }
      }
    } catch (te) {}

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
    } else if (item.type === "domain") {
      typeClass = "type-domain";
      typeText = "DOMAIN";
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

    let subTextUser = item.username || item.url || item.hostname || "No user";
    if (item.type === "domain") {
      subTextUser = item.domain_name || item.url || item.title;
      if (item.registrar) subTextUser += ` • ${item.registrar}`;
      if (item.expires_at) subTextUser += ` • Exp: ${item.expires_at.slice(0, 10)}`;
      if (item.username) subTextUser = `${item.username} @ ${subTextUser}`;
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
        <span class="card-user" title="${escapeHtml(subTextUser)}">
          ${escapeHtml(subTextUser)}
        </span>
        <span class="card-category">${escapeHtml(item.category || "")}</span>
      </div>
      <div class="card-groups-services-row">
        ${(item.groups && item.groups.length > 0) ? item.groups.map(g => `<span class="chip-group">📁 ${escapeHtml(g)}</span>`).join("") : ""}
        ${(item.services && item.services.length > 0) ? item.services.map(s => `<span class="chip-service">🌐 ${escapeHtml(s)}</span>`).join("") : ""}
      </div>
      <div class="login-actions">
        ${item.type === "domain" ? '<button class="btn-action btn-copy-dom" title="Copy Domain Name">🌐 Domain</button>' : ""}
        ${item.username ? '<button class="btn-action btn-copy-user" title="Copy Username">👤 User</button>' : ""}
        ${item.has_password ? '<button class="btn-action btn-copy-pass" title="Copy Password">🔑 Pass</button><button class="btn-action btn-reveal-pass" title="Show/Hide Password">👁</button>' : ""}
        ${item.type === "apikey" ? '<button class="btn-action btn-copy-key" title="Copy API Key">🎟️ Key</button>' : ""}
        ${item.type === "keypair" ? '<button class="btn-action btn-copy-pub" title="Copy Public Key">📋 Pub</button>' : ""}
        ${item.has_totp ? '<button class="btn-action btn-copy-totp" title="Copy 2FA TOTP Code">⏱️ 2FA</button>' : ""}
        <button class="btn-action btn-neural-eval" title="Local Neural Security Evaluation">🧠 Risk</button>
        <button class="btn-action btn-fill" title="Auto-fill login fields">⚡ Fill</button>
      </div>
      <div class="revealed-pass-box hidden"></div>
      <div class="neural-entry-box hidden"></div>
    `;

    // Bind Favorite Click
    card.querySelector(".fav-star").addEventListener("click", async (e) => {
      e.stopPropagation();
      await toggleFavorite(item.id);
    });

    // Action clicks
    card.querySelector(".btn-fill").addEventListener("click", () => fillCredentials(item.id));
    const domBtn = card.querySelector(".btn-copy-dom");
    if (domBtn) domBtn.addEventListener("click", () => copyCredential(item.id, "domain_name"));
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

    const neuralBtn = card.querySelector(".btn-neural-eval");
    if (neuralBtn) {
      neuralBtn.addEventListener("click", async () => {
        const nBox = card.querySelector(".neural-entry-box");
        if (!nBox.classList.contains("hidden")) {
          nBox.classList.add("hidden");
          nBox.innerHTML = "";
          return;
        }
        nBox.classList.remove("hidden");
        nBox.innerHTML = '<div style="font-size: 9px; color: var(--text-muted); padding: 4px;">🧠 Analyzing neural vector...</div>';
        try {
          const res = await fetch(`${BRIDGE_URL}/api/neural_analyze_entry`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ entry_id: item.id }),
          });
          if (!res.ok) throw new Error("Assessment failed");
          const nData = await res.json();
          const isHighRisk = nData.risk_score >= 60;
          const riskBadgeClass = isHighRisk ? "mini-badge-danger" : (nData.risk_score >= 35 ? "mini-badge-warn" : "badge-online");
          let recs = "";
          if (nData.recommendations && nData.recommendations.length > 0) {
            recs = `<div style="margin-top: 3px; color: var(--text-secondary); font-size: 9px;">• ${escapeHtml(nData.recommendations[0])}</div>`;
          }
          let groupsRec = "";
          if (nData.recommended_groups && nData.recommended_groups.length > 0) {
            groupsRec = `<div style="margin-top: 2px; color: #06B6D4; font-size: 9px;">Suggested Group: ${escapeHtml(nData.recommended_groups.join(", "))}</div>`;
          }
          nBox.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2px;">
              <span style="font-weight: 700; font-size: 10px; color: var(--text-primary);">🧠 Safety: ${nData.safety_score}/100</span>
              <span class="mini-badge ${riskBadgeClass}">Risk ${nData.risk_score} • ${escapeHtml(nData.predicted_class)}</span>
            </div>
            ${recs}
            ${groupsRec}
          `;
        } catch (e) {
          nBox.innerHTML = `<div style="color: var(--danger); font-size: 9px;">Neural assessment offline</div>`;
        }
      });
    }

    const revealBtn = card.querySelector(".btn-reveal-pass");
    if (revealBtn) {
      let hideTimer = null;
      revealBtn.addEventListener("click", async () => {
        const box = card.querySelector(".revealed-pass-box");
        if (!box.classList.contains("hidden")) {
          box.classList.add("hidden");
          box.textContent = "";
          revealBtn.textContent = "👁";
          if (hideTimer) clearTimeout(hideTimer);
          return;
        }
        try {
          const res = await fetch(`${BRIDGE_URL}/api/get_credentials`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ entry_id: item.id }),
          });
          if (!res.ok) return;
          const creds = await res.json();
          if (creds.password) {
            box.textContent = `Password: ${creds.password}`;
            box.classList.remove("hidden");
            revealBtn.textContent = "🔒";
            hideTimer = setTimeout(() => {
              box.classList.add("hidden");
              box.textContent = "";
              revealBtn.textContent = "👁";
            }, 15000);
          } else {
            showToast("No password stored");
          }
        } catch (e) {
          showToast("Failed to fetch password");
        }
      });
    }

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
    else if (field === "domain_name") val = creds.domain_name || creds.url;
    else if (field === "auth_code") val = creds.auth_code;
    else if (field === "registrar") val = creds.registrar;

    if (val) {
      navigator.clipboard.writeText(val);
      showToast(`${field.replace("_", " ").toUpperCase()} copied!`);
    } else {
      showToast(`${field.replace("_", " ").toUpperCase()} is empty`);
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
    else if (op === "sha384") { operation = "hash"; algo = "SHA-384"; }
    else if (op === "sha3_256") { operation = "hash"; algo = "sha3_256"; }
    else if (op === "blake2b") { operation = "hash"; algo = "blake2b"; }
    else if (op === "md5") { operation = "hash"; algo = "MD5"; }
    else if (op === "encrypt") { operation = "encrypt"; algo = "AES-256-GCM"; }
    else if (op === "decrypt") { operation = "decrypt"; algo = "AES-256-GCM"; }
    else if (op === "chacha20_enc") { operation = "encrypt"; algo = "CHACHA20-POLY1305"; }
    else if (op === "chacha20_dec") { operation = "decrypt"; algo = "CHACHA20-POLY1305"; }
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

  if (saveDrawerMode === "domain") {
    const domainName = document.getElementById("saveDomainNameInput").value.trim();
    const registrar = document.getElementById("saveRegistrarSelect").value;
    const expiresAt = document.getElementById("saveDomainExpiresInput").value.trim();
    const username = document.getElementById("saveDomainUserInput").value.trim();
    const password = document.getElementById("saveDomainPassInput").value;
    const authCode = document.getElementById("saveDomainAuthInput").value.trim();
    const autoRenew = document.getElementById("saveDomainAutoRenew").checked;

    if (!domainName && !title) {
      showToast("Domain name or title required");
      return;
    }

    try {
      const res = await fetch(`${BRIDGE_URL}/api/save_entry`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          type: "domain",
          title: title || domainName,
          domain_name: domainName,
          url: domainName,
          registrar,
          expires_at: expiresAt,
          username,
          password,
          auth_code: authCode,
          auto_renew: autoRenew,
          category: "Domains",
          tags: ["domain", "browser-extension"],
        }),
      });
      if (!res.ok) throw new Error("Save failed");
      showToast("Domain saved to StarVault!");
      document.getElementById("saveDrawer").classList.add("hidden");
      document.getElementById("saveDomainNameInput").value = "";
      document.getElementById("saveDomainPassInput").value = "";
      document.getElementById("saveDomainAuthInput").value = "";
      triggerSearch();
    } catch (e) {
      showToast("Failed to save domain");
    }
    return;
  }

  // Service / Web Login Mode
  const url = document.getElementById("saveUrlInput").value.trim();
  const username = document.getElementById("saveUserInput").value.trim();
  const password = document.getElementById("savePassInput").value;
  const parentDomainSelect = document.getElementById("saveParentDomainSelect");
  const parentDomainId = parentDomainSelect ? parentDomainSelect.value : "";
  const category = document.getElementById("saveCategorySelect").value;
  const tagsStr = document.getElementById("saveTagsInput").value.trim();
  const tags = tagsStr ? tagsStr.split(",").map((t) => t.trim()).filter(Boolean) : ["extension"];
  const groupsStr = document.getElementById("saveGroupsInput") ? document.getElementById("saveGroupsInput").value.trim() : "";
  const servicesStr = document.getElementById("saveServicesInput") ? document.getElementById("saveServicesInput").value.trim() : "";
  const groups = groupsStr ? groupsStr.split(",").map((g) => g.trim()).filter(Boolean) : [];
  const services = servicesStr ? servicesStr.split(",").map((s) => s.trim()).filter(Boolean) : [];

  if (!username && !password) {
    showToast("Please enter username or password");
    return;
  }

  try {
    const res = await fetch(`${BRIDGE_URL}/api/save_entry`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        type: "service",
        title,
        url,
        username,
        password,
        parent_domain_id: parentDomainId || null,
        category,
        tags,
        groups,
        services,
      }),
    });
    if (!res.ok) throw new Error("Save failed");
    showToast("Saved to StarVault!");
    document.getElementById("saveDrawer").classList.add("hidden");
    document.getElementById("saveUserInput").value = "";
    document.getElementById("savePassInput").value = "";
    if (document.getElementById("saveGroupsInput")) document.getElementById("saveGroupsInput").value = "";
    if (document.getElementById("saveServicesInput")) document.getElementById("saveServicesInput").value = "";
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
