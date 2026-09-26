// Content script for StarVault Autofill

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "autofill" || request.action === "FILL_CREDENTIALS") {
    const success = performAutofill(request.username, request.password);
    sendResponse({ success });
  }
  return true;
});

function performAutofill(username, password) {
  let filledPass = false;
  let filledUser = false;

  // Find password inputs
  const passwordInputs = document.querySelectorAll('input[type="password"]');
  if (passwordInputs.length > 0 && password) {
    const passField = passwordInputs[0];
    setInputValue(passField, password);
    filledPass = true;
  }

  // Find username / email inputs
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
          setInputValue(input, username);
          filledUser = true;
          break;
        }
      }
      if (filledUser) break;
    }
  }

  return filledPass || filledUser;
}

function setInputValue(element, value) {
  element.value = value;
  element.dispatchEvent(new Event("input", { bubbles: true }));
  element.dispatchEvent(new Event("change", { bubbles: true }));
}
