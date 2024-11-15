// background.js
chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
  if (message.action === "sendURL") {
    const url = message.url;
    const html = message.html;
    const startTime = Date.now();
    fetch('http://127.0.0.1:5000/collect', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ url: url, html: html })
    }).then(
      response => response.json()
    ).then(data => {
      const endTime = Date.now();
      const timeTaken = endTime - startTime;
      console.log("URL successfully sent to Flask server", data);
      console.log("Time taken for response: " + timeTaken + "ms");
    }).catch(error => {
      const endTime = Date.now();
      const timeTaken = endTime - startTime;
      console.log("Error sending URL to Flask server", error);
      console.log("Time taken for response: " + timeTaken + "ms");
    });
  }
});
  