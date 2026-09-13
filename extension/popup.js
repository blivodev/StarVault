const BRIDGE_URL = "http://127.0.0.1:8088";

let currentTabUrl = "";
let currentTabDomain = "";
let genMode = "password";

document.addEventListener("DOMContentLoaded", async () => {
  setupEventListeners();
  await detectActiveTab();
  await checkBridgeStatus();
});

function setupEventListeners() {
  document.getElementById("lockBtn").addEventListener("click", lockVault);
  document.getElementById("retryBtn").addEventListener("click", checkBridgeStatus);
  document.getElementById("connectRetryBtn").addEventListener("click", checkBridgeStatus);

  const searchInput = document.getElementById("searchInput");
  searchInput.addEventListener("input", () => {
    searchVault(searchInput.value);
  });

  // Generator drawer
  const openGenBtn = document.getElementById("openGenBtn");
  const genDrawer = document.getElementById("genDrawer");
  const closeGenBtn = document.getElementById("closeGenBtn");
  const refreshGenBtn = document.getElementById("refreshGenBtn");
  const copyGenBtn = document.getElementById("copyGenBtn");
  const lengthSlider = document.getElementById("lengthSlider");
  const lengthVal = document.getElementById("lengthVal");
  const genModePass = document.getElementById("genModePass");
  const genModeKey = document.getElementById("genModeKey");
  const passOptions = document.getElementById("passOptions");
  const keyOptions = document.getElementById("keyOptions");
  const keyFormatSelect = document.getElementById("keyFormatSelect");

  openGenBtn.addEventListener("click", () => {
    genDrawer.classList.remove("hidden");
    cryptoDrawer.classList.add("hidden");
    saveDrawer.classList.add("hidden");
    triggerGeneration();
  });
  closeGenBtn.addEventListener("click", () => genDrawer.classList.add("hidden"));
  refreshGenBtn.addEventListener("click", triggerGeneration);

  genModePass.addEventListener("click", () => {
    genMode = "password";
    genModePass.classList.add("active");
    genModeKey.classList.remove("active");
    passOptions.classList.remove("hidden");
    keyOptions.classList.add("hidden");
    document.getElementById("genTitle").textContent = "Generate Password";
    triggerGeneration();
  });

  genModeKey.addEventListener("click", () => {
    genMode = "key";
    genModeKey.classList.add("active");
    genModePass.classList.remove("active");
    keyOptions.classList.remove("hidden");
    passOptions.classList.add("hidden");
    document.getElementById("genTitle").textContent = "Generate API Key";
    triggerGeneration();
  });

  keyFormatSelect.addEventListener("change", triggerGeneration);

  lengthSlider.addEventListener("input", (e) => {
    lengthVal.textContent = e.target.value;
    triggerGeneration();
  });

  copyGenBtn.addEventListener("click", () => {
    const val = document.getElementById("genPasswordInput").value;
    if (val) {
      navigator.clipboard.writeText(val);
      showToast(genMode === "password" ? "Password copied!" : "API Key copied!");
    }
  });

  // Crypto drawer
  const openCryptoBtn = document.getElementById("openCryptoBtn");
  const cryptoDrawer = document.getElementById("cryptoDrawer");
  const closeCryptoBtn = document.getElementById("closeCryptoBtn");
  const cryptoOpSelect = document.getElementById("cryptoOpSelect");
  const cryptoKeyInput = document.getElementById("cryptoKeyInput");
  const runCryptoBtn = document.getElementById("runCryptoBtn");
  const copyCryptoBtn = document.getElementById("copyCryptoBtn");

  openCryptoBtn.addEventListener("click", () => {
    cryptoDrawer.classList.remove("hidden");
    genDrawer.classList.add("hidden");
    saveDrawer.classList.add("hidden");
  });
  closeCryptoBtn.addEventListener("click", () => cryptoDrawer.classList.add("hidden"));

  cryptoOpSelect.addEventListener("change", () => {
    const op = cryptoOpSelect.value;
    if (op === "encrypt" || op === "decrypt") {
      cryptoKeyInput.classList.remove("hidden");
    } else {
      cryptoKeyInput.classList.add("hidden");
    }
  });

  runCryptoBtn.addEventListener("click", runCryptoTool);
  copyCryptoBtn.addEventListener("click", () => {
    const out = document.getElementById("cryptoOutput").value;
    if (out) {
      navigator.clipboard.writeText(out);
      showToast("Result copied!");
    }
  });

  // Save login drawer
  const openSaveBtn = document.getElementById("openSaveBtn");
  const saveDrawer = document.getElementById("saveDrawer");
  const closeSaveBtn = document.getElementById("closeSaveBtn");
  const submitSaveBtn = document.getElementById("submitSaveBtn");

  openSaveBtn.addEventListener("click", () => {
    saveDrawer.classList.remove("hidden");
    genDrawer.classList.add("hidden");
    cryptoDrawer.classList.add("hidden");
    document.getElementById("saveUrlInput").value = currentTabUrl;
    document.getElementById("saveTitleInput").value = currentTabDomain;
  });
  closeSaveBtn.addEventListener("click", () => saveDrawer.classList.add("hidden"));
  submitSaveBtn.addEventListener("click", saveNewLogin);

  // Auto fill page
  document.getElementById("tabFillBtn").addEventListener("click", () => {
    const firstCard = document.querySelector(".btn-fill");
    if (firstCard) {
      firstCard.click();
    } else {
      showToast("No credentials found for this page");
    }
  });
}

async function detectActiveTab() {
  try {
    if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.query) {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs && tabs[0] && tabs[0].url) {
        currentTabUrl = tabs[0].url;
        try {
          const u = new URL(currentTabUrl);
          currentTabDomain = u.hostname;
          document.getElementById("searchInput").placeholder = `Search (e.g. ${currentTabDomain})...`;
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
      badge.textContent = "Vault Unlocked";
      badge.className = "badge badge-online";
      lockedView.classList.add("hidden");
      disconnectedView.classList.add("hidden");
      loginsView.classList.remove("hidden");
      searchVault(currentTabDomain);
    } else {
      badge.textContent = "Vault Locked";
      badge.className = "badge badge-locked";
      lockedView.classList.remove("hidden");
      disconnectedView.classList.add("hidden");
      loginsView.classList.add("hidden");
    }
  } catch (e) {
    badge.textContent = "Bridge Offline";
    badge.className = "badge badge-offline";
    disconnectedView.classList.remove("hidden");
    lockedView.classList.add("hidden");
    loginsView.classList.add("hidden");
  }
}

async function searchVault(query) {
  const loginsView = document.getElementById("loginsView");
  try {
    const res = await fetch(`${BRIDGE_URL}/api/search`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: query || "", url: currentTabUrl }),
    });

    if (!res.ok) return;
    const data = await res.json();
    renderLogins(data.matches || []);
  } catch (e) {
    console.error("Search error:", e);
  }
}

function renderLogins(items) {
  const loginsView = document.getElementById("loginsView");
  loginsView.innerHTML = "";

  if (!items || items.length === 0) {
    loginsView.innerHTML = `
      <div class="empty-state">
        <p>No matching credentials found.</p>
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

    card.innerHTML = `
      <div class="login-info">
        <div class="login-title">${escapeHtml(item.title)}</div>
        <div class="login-user">${escapeHtml(item.username || item.url || "No username")}</div>
      </div>
      <div class="login-actions">
        <button class="btn-icon btn-copy-user" title="Copy Username">👤</button>
        <button class="btn-icon btn-copy-pass" title="Copy Password">🔑</button>
        ${item.has_totp ? '<button class="btn-icon btn-totp" title="Copy 2FA TOTP">⏱️</button>' : ""}
        <button class="btn btn-primary btn-fill" title="Auto-fill form">Fill</button>
      </div>
    `;

    card.querySelector(".btn-fill").addEventListener("click", () => fillCredentials(item.id));
    card.querySelector(".btn-copy-user").addEventListener("click", () => copyCredential(item.id, "username"));
    card.querySelector(".btn-copy-pass").addEventListener("click", () => copyCredential(item.id, "password"));
    const totpBtn = card.querySelector(".btn-totp");
    if (totpBtn) {
      totpBtn.addEventListener("click", () => copyCredential(item.id, "totp"));
    }

    loginsView.appendChild(card);
  });
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
        showToast("Injected credentials into page!");
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

function triggerGeneration() {
  if (genMode === "password") {
    generatePassword();
  } else {
    generateApiKey();
  }
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
    // Local fallback generator
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
    document.getElementById("genPasswordInput").value = data.key;
  } catch (e) {
    showToast("Key generator offline");
  }
}

async function runCryptoTool() {
  const op = document.getElementById("cryptoOpSelect").value;
  const text = document.getElementById("cryptoTextInput").value;
  const key = document.getElementById("cryptoKeyInput").value;
  const out = document.getElementById("cryptoOutput");

  if (!text) {
    showToast("Please enter input text");
    return;
  }

  try {
    const res = await fetch(`${BRIDGE_URL}/api/crypto_tool`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ operation: op, text, key, algorithm: op === "hash" ? "SHA-256" : "AES-256-GCM" }),
    });
    const data = await res.json();
    if (data.success) {
      out.value = data.result;
    } else {
      out.value = `Error: ${data.error}`;
    }
  } catch (e) {
    out.value = `Error: Bridge offline`;
  }
}

async function saveNewLogin() {
  const title = document.getElementById("saveTitleInput").value.trim();
  const url = document.getElementById("saveUrlInput").value.trim();
  const username = document.getElementById("saveUserInput").value.trim();
  const password = document.getElementById("savePassInput").value;

  if (!username && !password) {
    showToast("Please enter username or password");
    return;
  }

  try {
    const res = await fetch(`${BRIDGE_URL}/api/save_entry`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title, url, username, password }),
    });
    if (!res.ok) throw new Error("Save failed");
    showToast("Saved to StarVault!");
    document.getElementById("saveDrawer").classList.add("hidden");
    document.getElementById("saveUserInput").value = "";
    document.getElementById("savePassInput").value = "";
    searchVault(title || currentTabDomain);
  } catch (e) {
    showToast("Failed to save login");
  }
}

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
