// background.js
chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
    if (message.action === "sendURL") {
      const url = message.url;
      const html = message.html;
      fetch('http://127.0.0.1:5000/receive_url', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url: url, html: html })
      })
      .then(response => response.json())
      .then(data => {
        console.log("URL successfully sent to Flask server", data);
      })
      .catch(error => {
        console.log("Error sending URL to Flask server", error);
      });
    }
  });
  