// StarVault content script.
//
// Injected into every page. Provides Bitwarden-style in-page behaviour:
//  - Detects login forms (username + password fields) on the current site.
//  - Shows a small inline "StarVault" badge inside password fields that opens
//    a dropdown of matching credentials for the site.
//  - Fills credentials on request (from the badge, the popup, or the context menu).
//  - Detects a submitted login form and offers to save it to the vault.
//
// Everything talks to the background worker, which proxies to the local
// StarVault bridge; this script never stores secrets.

(function () {
  if (window.__starvaultInjected) return;
  window.__starvaultInjected = true;

  const STYLE_ID = "starvault-inline-styles";
  const ACCENT = "#38bdf8";

  // -----------------------------------------------------------------------
  // Field discovery
  // -----------------------------------------------------------------------
  function visible(el) {
    if (!el) return false;
    const r = el.getBoundingClientRect();
    if (r.width === 0 && r.height === 0) return false;
    const s = getComputedStyle(el);
    return s.visibility !== "hidden" && s.display !== "none" && s.opacity !== "0";
  }

  function passwordFields() {
    return Array.from(document.querySelectorAll('input[type="password"]')).filter(visible);
  }

  function usernameFieldFor(passField) {
    // Walk backwards through inputs before the password field, then fall back
    // to common selectors anywhere in the same form/document.
    const form = passField.form || document;
    const inputs = Array.from(form.querySelectorAll("input")).filter(visible);
    const idx = inputs.indexOf(passField);
    for (let i = idx - 1; i >= 0; i--) {
      const t = (inputs[i].type || "text").toLowerCase();
      if (["text", "email", "tel", "username"].includes(t) || inputs[i].autocomplete === "username") {
        return inputs[i];
      }
    }
    const sels = [
      'input[autocomplete="username"]',
      'input[autocomplete="email"]',
      'input[type="email"]',
      'input[name*="user" i]',
      'input[name*="email" i]',
      'input[name*="login" i]',
      'input[id*="user" i]',
      'input[id*="email" i]',
      'input[id*="login" i]',
    ];
    for (const s of sels) {
      const el = form.querySelector(s);
      if (el && visible(el) && el.type !== "password") return el;
    }
    return null;
  }

  // -----------------------------------------------------------------------
  // Styling
  // -----------------------------------------------------------------------
  function injectStyles() {
    if (document.getElementById(STYLE_ID)) return;
    const st = document.createElement("style");
    st.id = STYLE_ID;
    st.textContent = `
      .sv-badge {
        position: absolute; z-index: 2147483000; width: 20px; height: 20px;
        border-radius: 5px; background: ${ACCENT}; color: #06121f; cursor: pointer;
        display: flex; align-items: center; justify-content: center;
        font: bold 12px/1 "Segoe UI", system-ui, sans-serif;
        box-shadow: 0 1px 4px rgba(0,0,0,.4); user-select: none;
      }
      .sv-badge:hover { background: #7dd3fc; }
      .sv-menu {
        position: absolute; z-index: 2147483001; min-width: 240px; max-width: 320px;
        background: #0e1526; color: #f8fafc; border: 1px solid #243452;
        border-radius: 10px; box-shadow: 0 12px 32px rgba(0,0,0,.55);
        font: 13px/1.4 "Segoe UI", system-ui, sans-serif; overflow: hidden;
        padding: 6px;
      }
      .sv-menu .sv-hdr {
        font-size: 11px; text-transform: uppercase; letter-spacing: .06em;
        color: #94a3b8; padding: 6px 8px 4px;
      }
      .sv-item {
        display: flex; align-items: center; gap: 8px; padding: 8px;
        border-radius: 7px; cursor: pointer;
      }
      .sv-item:hover { background: #1e2c4a; }
      .sv-item .sv-ic {
        width: 22px; height: 22px; border-radius: 5px; background: #172138;
        display: flex; align-items: center; justify-content: center;
        font-size: 11px; color: ${ACCENT}; flex: none;
      }
      .sv-item .sv-t { font-weight: 600; }
      .sv-item .sv-s { color: #94a3b8; font-size: 11px; }
      .sv-empty { padding: 10px 8px; color: #94a3b8; font-size: 12px; }
      .sv-save {
        position: fixed; z-index: 2147483002; right: 18px; bottom: 18px;
        width: 300px; background: #0e1526; color: #f8fafc; border: 1px solid #243452;
        border-radius: 12px; box-shadow: 0 14px 36px rgba(0,0,0,.6);
        font: 13px/1.45 "Segoe UI", system-ui, sans-serif; padding: 14px;
      }
      .sv-save h4 { margin: 0 0 4px; font-size: 14px; }
      .sv-save p { margin: 0 0 10px; color: #94a3b8; font-size: 12px; }
      .sv-save .sv-row { display: flex; gap: 8px; }
      .sv-btn {
        flex: 1; padding: 7px 10px; border-radius: 7px; border: 0; cursor: pointer;
        font: 600 12px "Segoe UI", system-ui, sans-serif;
      }
      .sv-btn.primary { background: ${ACCENT}; color: #06121f; }
      .sv-btn.ghost { background: #172138; color: #cbd5e1; }
    `;
    document.documentElement.appendChild(st);
  }

  // -----------------------------------------------------------------------
  // Inline badge + credential dropdown
  // -----------------------------------------------------------------------
  let activeBadge = null;
  let activeMenu = null;

  function removeMenu() {
    if (activeMenu && activeMenu.parentNode) activeMenu.parentNode.removeChild(activeMenu);
    activeMenu = null;
  }

  function closeAll() {
    removeMenu();
    if (activeBadge && activeBadge.parentNode) activeBadge.parentNode.removeChild(activeBadge);
    activeBadge = null;
  }

  function attachBadge(passField) {
    if (!visible(passField)) return;
    injectStyles();

    const badge = document.createElement("div");
    badge.className = "sv-badge";
    badge.textContent = "SV";
    badge.title = "StarVault: fill credentials";
    document.body.appendChild(badge);

    const place = () => {
      const r = passField.getBoundingClientRect();
      if (r.width === 0) { badge.style.display = "none"; return; }
      badge.style.display = "flex";
      badge.style.top = `${window.scrollY + r.top + r.height / 2 - 10}px`;
      badge.style.left = `${window.scrollX + r.right - 26}px`;
    };
    place();
    window.addEventListener("scroll", place, true);
    window.addEventListener("resize", place);

    badge.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      openMenu(passField, badge);
    });
    activeBadge = badge;
  }

  function openMenu(passField, anchor) {
    removeMenu();
    injectStyles();

    const menu = document.createElement("div");
    menu.className = "sv-menu";
    menu.innerHTML = `<div class="sv-hdr">StarVault</div><div class="sv-empty">Loading…</div>`;
    document.body.appendChild(menu);

    const r = anchor.getBoundingClientRect();
    menu.style.top = `${window.scrollY + r.bottom + 6}px`;
    menu.style.left = `${Math.max(8, window.scrollX + r.left - 220)}px`;
    activeMenu = menu;

    chrome.runtime.sendMessage(
      { action: "starvault_lookup", url: location.href, query: "" },
      (resp) => {
        const items = (resp && resp.matches) || [];
        menu.innerHTML = `<div class="sv-hdr">Matches for ${location.hostname}</div>`;
        if (!items.length) {
          const d = document.createElement("div");
          d.className = "sv-empty";
          d.textContent = "No saved logins for this site.";
          menu.appendChild(d);
          return;
        }
        items.slice(0, 8).forEach((it) => {
          const row = document.createElement("div");
          row.className = "sv-item";
          const ic = document.createElement("div");
          ic.className = "sv-ic";
          ic.textContent = (it.type || "s").slice(0, 2).toUpperCase();
          const box = document.createElement("div");
          const t = document.createElement("div");
          t.className = "sv-t";
          t.textContent = it.title || it.username || "Entry";
          const s = document.createElement("div");
          s.className = "sv-s";
          s.textContent = it.username || it.url || "";
          box.appendChild(t);
          box.appendChild(s);
          row.appendChild(ic);
          row.appendChild(box);
          row.addEventListener("click", (e) => {
            e.preventDefault();
            fillFromEntry(it.id, passField);
            closeAll();
          });
          menu.appendChild(row);
        });
      }
    );
  }

  function fillFromEntry(entryId, passField) {
    chrome.runtime.sendMessage({ action: "starvault_credentials", entry_id: entryId }, (creds) => {
      if (!creds || creds.error) return;
      const userField = usernameFieldFor(passField);
      if (userField && creds.username) setValue(userField, creds.username);
      if (creds.password) setValue(passField, creds.password);
    });
  }

  function setValue(el, value) {
    el.focus();
    el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  // -----------------------------------------------------------------------
  // Save prompt after a submitted login
  // -----------------------------------------------------------------------
  function offerSave(username, password) {
    injectStyles();
    const old = document.querySelector(".sv-save");
    if (old) old.remove();

    const box = document.createElement("div");
    box.className = "sv-save";
    box.innerHTML = `
      <h4>Save login to StarVault?</h4>
      <p>${location.hostname}${username ? " • " + username : ""}</p>
    `;
    const row = document.createElement("div");
    row.className = "sv-row";

    const save = document.createElement("button");
    save.className = "sv-btn primary";
    save.textContent = "Save";
    save.addEventListener("click", () => {
      chrome.runtime.sendMessage(
        {
          action: "starvault_save_login",
          payload: {
            title: document.title || location.hostname,
            url: location.href,
            username,
            password,
            type: "service",
            tags: ["browser-extension"],
          },
        },
        () => box.remove()
      );
    });

    const never = document.createElement("button");
    never.className = "sv-btn ghost";
    never.textContent = "Not now";
    never.addEventListener("click", () => box.remove());

    row.appendChild(save);
    row.appendChild(never);
    box.appendChild(row);
    document.body.appendChild(box);
    setTimeout(() => { if (box.parentNode) box.remove(); }, 25000);
  }

  function hookFormSubmit() {
    document.addEventListener(
      "submit",
      (e) => {
        try {
          const form = e.target;
          if (!form || !form.querySelectorAll) return;
          const pass = form.querySelector('input[type="password"]');
          if (!pass || !pass.value) return;
          const userField = usernameFieldFor(pass);
          const username = userField ? userField.value : "";
          chrome.runtime.sendMessage({
            action: "starvault_capture_login",
            url: location.href,
            username,
            password: pass.value,
          });
          offerSave(username, pass.value);
        } catch (err) {
          /* ignore */
        }
      },
      true
    );
  }

  // -----------------------------------------------------------------------
  // Messages from the popup / context menu / background
  // -----------------------------------------------------------------------
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (!request || !request.action) return false;

    if (request.action === "starvault_fill_page" || request.action === "autofill" || request.action === "FILL_CREDENTIALS") {
      const pass = passwordFields()[0];
      if (pass) {
        // Ask the background for the top match for this URL, then fill.
        chrome.runtime.sendMessage({ action: "starvault_lookup", url: location.href, query: "" }, (resp) => {
          const items = (resp && resp.matches) || [];
          if (items.length) {
            fillFromEntry(items[0].id, pass);
            sendResponse({ success: true });
          } else {
            sendResponse({ success: false });
          }
        });
        return true;
      }
      if (request.username || request.password) {
        const ok = performAutofill(request.username, request.password);
        sendResponse({ success: ok });
        return true;
      }
      sendResponse({ success: false });
      return true;
    }

    if (request.action === "starvault_open_save") {
      const pass = passwordFields()[0];
      const userField = pass ? usernameFieldFor(pass) : null;
      offerSave(userField ? userField.value : "", pass ? pass.value : "");
      sendResponse({ success: true });
      return true;
    }

    if (request.action === "starvault_insert_password") {
      const pass = passwordFields()[0];
      if (pass && request.password) {
        setValue(pass, request.password);
        sendResponse({ success: true });
      } else {
        sendResponse({ success: false });
      }
      return true;
    }

    return false;
  });

  // -----------------------------------------------------------------------
  // Legacy direct fill (kept for popup compatibility)
  // -----------------------------------------------------------------------
  function performAutofill(username, password) {
    let filledPass = false;
    let filledUser = false;
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    if (passwordInputs.length > 0 && password) {
      setValue(passwordInputs[0], password);
      filledPass = true;
    }
    if (username) {
      const userSelectors = [
        'input[autocomplete="username"]',
        'input[autocomplete="email"]',
        'input[name*="user" i]',
        'input[name*="email" i]',
        'input[name*="login" i]',
        'input[id*="user" i]',
        'input[id*="email" i]',
        'input[id*="login" i]',
        'input[type="email"]',
        'input[type="text"]',
      ];
      for (const selector of userSelectors) {
        const candidates = document.querySelectorAll(selector);
        for (const input of candidates) {
          if (input.type !== "hidden" && input.type !== "password" && !input.disabled && input.offsetParent !== null) {
            setValue(input, username);
            filledUser = true;
            break;
          }
        }
        if (filledUser) break;
      }
    }
    return filledPass || filledUser;
  }

  // -----------------------------------------------------------------------
  // Boot: attach badges to login forms as they appear
  // -----------------------------------------------------------------------
  function scan() {
    closeAll();
    const fields = passwordFields();
    if (fields.length) attachBadge(fields[0]);
  }

  hookFormSubmit();

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => setTimeout(scan, 400));
  } else {
    setTimeout(scan, 400);
  }

  // Re-scan when the DOM changes (SPAs navigate without a reload)
  let rescanTimer = null;
  const mo = new MutationObserver(() => {
    clearTimeout(rescanTimer);
    rescanTimer = setTimeout(scan, 600);
  });
  mo.observe(document.documentElement, { childList: true, subtree: true });

  window.addEventListener("pagehide", closeAll);
})();
