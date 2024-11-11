document.getElementById('sendRequest').addEventListener('click', function() {
    chrome.runtime.sendMessage({ action: 'fetchData' });
});