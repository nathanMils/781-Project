// content.js
chrome.runtime.sendMessage({
    action: "sendURL",
    url: window.location.href // Send the current page URL to background
  });
  