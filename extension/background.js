// Background Service Worker for the StarVault browser companion.
//
// Responsibilities:
//  - Poll the local StarVault bridge and reflect lock state on the toolbar badge.
//  - Context menus (right-click) to fill the current page or add a login.
//  - Route messages between the popup, the content script, and the bridge.
//  - Detect a successful login (form submit with a password) and offer to save.
//
// All credential material stays on the local bridge at 127.0.0.1:8088; this
// worker never persists secrets.

const BRIDGE_URL = "http://127.0.0.1:8088";

// ---------------------------------------------------------------------------
// Bridge helpers
// ---------------------------------------------------------------------------
async function bridgeGet(path) {
  const res = await fetch(`${BRIDGE_URL}${path}`);
  if (!res.ok) throw new Error(`bridge ${res.status}`);
  return res.json();
}

async function bridgePost(path, body) {
  const res = await fetch(`${BRIDGE_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  if (!res.ok) throw new Error(`bridge ${res.status}`);
  return res.json();
}

// ---------------------------------------------------------------------------
// Toolbar badge reflects lock state
// ---------------------------------------------------------------------------
async function pollBridgeStatus() {
  try {
    const data = await bridgeGet("/api/status");
    if (data.unlocked) {
      // Chrome toolbar badges are text-only (no SVG); use an ASCII marker.
      chrome.action.setBadgeText({ text: "ON" });
      chrome.action.setBadgeBackgroundColor({ color: "#10B981" });
    } else {
      chrome.action.setBadgeText({ text: "!" });
      chrome.action.setBadgeBackgroundColor({ color: "#F59E0B" });
    }
    chrome.action.setTitle({ title: `StarVault — ${data.unlocked ? "unlocked" : "locked"}` });
  } catch (e) {
    chrome.action.setBadgeText({ text: "" });
    chrome.action.setTitle({ title: "StarVault — desktop bridge offline" });
  }
}

setInterval(pollBridgeStatus, 15000);
pollBridgeStatus();

// ---------------------------------------------------------------------------
// Context menus (Bitwarden-style right-click actions)
// ---------------------------------------------------------------------------
const MENU_FILL = "starvault-fill";
const MENU_ADD = "starvault-add";
const MENU_GEN = "starvault-gen";

function createMenus() {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: MENU_FILL,
      title: "StarVault: Fill credentials on this page",
      contexts: ["page", "editable"],
    });
    chrome.contextMenus.create({
      id: MENU_ADD,
      title: "StarVault: Add a login for this site",
      contexts: ["page", "editable"],
    });
    chrome.contextMenus.create({
      id: MENU_GEN,
      title: "StarVault: Generate password",
      contexts: ["editable"],
    });
  });
}

chrome.runtime.onInstalled.addListener(() => {
  createMenus();
  pollBridgeStatus();
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (!tab || !tab.id) return;
  if (info.menuItemId === MENU_FILL) {
    chrome.tabs.sendMessage(tab.id, { action: "starvault_fill_page" });
  } else if (info.menuItemId === MENU_ADD) {
    chrome.tabs.sendMessage(tab.id, { action: "starvault_open_save" });
  } else if (info.menuItemId === MENU_GEN) {
    try {
      const data = await bridgePost("/api/generate_password", { length: 20 });
      chrome.tabs.sendMessage(tab.id, { action: "starvault_insert_password", password: data.password });
    } catch (e) {
      /* bridge offline — ignore */
    }
  }
});

// ---------------------------------------------------------------------------
// Message routing
// ---------------------------------------------------------------------------
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (!request || !request.action) return false;

  if (request.action === "starvault_status") {
    bridgeGet("/api/status").then(sendResponse).catch(() => sendResponse({ unlocked: false, offline: true }));
    return true;
  }

  if (request.action === "starvault_lookup") {
    bridgePost("/api/search", { query: request.query || "", url: request.url || "" })
      .then(sendResponse)
      .catch(() => sendResponse({ matches: [] }));
    return true;
  }

  if (request.action === "starvault_credentials") {
    bridgePost("/api/get_credentials", { entry_id: request.entry_id })
      .then(sendResponse)
      .catch(() => sendResponse({ error: "offline" }));
    return true;
  }

  if (request.action === "starvault_save_login") {
    bridgePost("/api/save_entry", request.payload || {})
      .then(sendResponse)
      .catch(() => sendResponse({ success: false, error: "offline" }));
    return true;
  }

  if (request.action === "starvault_generate") {
    bridgePost("/api/generate_password", { length: request.length || 20 })
      .then(sendResponse)
      .catch(() => sendResponse({ password: "" }));
    return true;
  }

  return false;
});

// ---------------------------------------------------------------------------
// Login-capture: when a content script reports a submitted login form with a
// password the vault doesn't know, remember it as a pending save.
// ---------------------------------------------------------------------------
chrome.runtime.onMessage.addListener((msg, sender) => {
  if (msg && msg.action === "starvault_capture_login" && sender.tab) {
    chrome.storage.session.set({
      [`pending_${sender.tab.id}`]: {
        url: msg.url,
        username: msg.username,
        password: msg.password,
        ts: Date.now(),
      },
    });
  }
  return false;
});
