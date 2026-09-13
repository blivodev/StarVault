// Background Service Worker for StarVault Extension

chrome.runtime.onInstalled.addListener(() => {
  console.log("StarVault extension installed successfully.");
});

// Periodic heartbeat to verify local StarVault bridge
async function pollBridgeStatus() {
  try {
    const res = await fetch("http://127.0.0.1:8088/api/status");
    if (res.ok) {
      const data = await res.json();
      if (data.unlocked) {
        chrome.action.setBadgeText({ text: "✓" });
        chrome.action.setBadgeBackgroundColor({ color: "#00E676" });
      } else {
        chrome.action.setBadgeText({ text: "🔒" });
        chrome.action.setBadgeBackgroundColor({ color: "#FFB300" });
      }
    } else {
      chrome.action.setBadgeText({ text: "" });
    }
  } catch (e) {
    chrome.action.setBadgeText({ text: "" });
  }
}

setInterval(pollBridgeStatus, 15000);
pollBridgeStatus();
