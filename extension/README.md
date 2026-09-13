# StarVault Chromium Browser Companion Extension
### Supports Chrome, Brave, Edge, and all Chromium browsers

This extension bridges your local StarVault application with your web browser, allowing zero-knowledge auto-fill, credential lookup, and password generation.

---

## Installation in 3 Easy Steps

1. Open your browser's extensions management page:
   - **Brave**: `brave://extensions`
   - **Chrome**: `chrome://extensions`
   - **Edge**: `edge://extensions`
2. Enable **Developer mode** (toggle switch in the top-right corner).
3. Click **Load unpacked** and select the `D:\Projects\StarVault\extension` folder.

---

## Features
- **Instant Domain Matching**: Automatically searches your vault for the active tab's domain or IP address.
- **1-Click Auto-Fill**: Injects username and password directly into web forms.
- **Secure Password Generator**: Generates high-entropy passwords directly in the browser toolbar.
- **Save New Logins**: Save freshly created credentials straight to your StarVault database.
- **Remote Lock**: Lock your desktop StarVault instantly from any browser tab.
- **Local Loopback Security**: Communicates strictly with `127.0.0.1:8088` on your local machine; credentials never leave your system.
