# StarVault Chromium Browser Companion Extension
### Supports Chrome, Brave, Edge, Opera, and all Chromium browsers

The StarVault Companion extension securely bridges your local desktop StarVault application with your web browser, delivering zero-knowledge auto-fill, credential lookup, natural/numeric sorting, key generation, crypto tools, and automated vault management directly in your browser.

---

## 🚀 Installation in 3 Easy Steps

1. Open your browser's extensions management page:
   - **Brave**: `brave://extensions`
   - **Chrome**: `chrome://extensions`
   - **Edge**: `edge://extensions`
2. Enable **Developer mode** (toggle switch in the top-right corner).
3. Click **Load unpacked** and select the `extension/` directory within this repository (`D:\Projects\StarVault\extension`).

---

## 🌟 Companion Features

- **⚡ Instant Domain Matching & 1-Click Auto-Fill**: Automatically identifies the active tab's domain or IP address and injects decrypted credentials cleanly into login forms.
- **🔍 Multi-Dimensional Sorting & Quick Filters**:
  - Filter chips: `All`, `🖥️ Servers`, `🌐 Services`, `🔑 API Keys`, `🛡️ Keys`, `⭐ Favorites`, `⏳ Expiring`, `⚠️ Weak`, `📱 TOTP`.
  - Sorting: Natural Numeric (`vps1, vps2, vps10...`), Alphabetical (A → Z / Z → A), Date Created (Newest/Oldest), Date Modified, Category, and Security Risk with instant ascending/descending toggle.
- **🔑 Key & Secret Studio**:
  - High-entropy password generator (8–64 chars with symbols & digits).
  - API Key generator with format presets (`sv_hex64`, OpenAI `sk-proj`, Stripe `sk_live`, AWS, UUID v4).
  - SSH Ed25519 & WireGuard (X25519) VPN keypair generator with optional direct saving to StarVault.
- **🛠️ Crypto & TLS Certificate Workbench**:
  - Symmetric Encryption: AES-256-GCM Encrypt & Decrypt.
  - Cryptographic Hashes: SHA-256, SHA-512, MD5, HMAC-SHA256.
  - Data Encoders: Base64 Encode/Decode, Hex Encode/Decode, URL Encode/Decode.
  - Self-Signed X.509 TLS/SSL Certificate generator with Subject Alternative Names (SANs).
- **✨ Smart Auto-Organize & Deduplicate**: Run automated categorization, title normalization, and duplicate merging straight from your browser toolbar.
- **📤 Master Password Protected CSV Export**: Download a full, sanitized CSV spreadsheet of your decrypted vault credentials directly from the extension upon master password verification.
- **🎨 Multi-Theme Switcher**: Cycle dynamically between **Modern Dark**, **Midnight Blue**, **Matrix Console Green**, **Cyberpunk Neon**, and **Clean Light**.
- **🔒 Zero-Knowledge Local Loopback Security**: Communicates strictly over `127.0.0.1:8088` on loopback. Credentials are never sent over external networks or stored in third-party clouds.
