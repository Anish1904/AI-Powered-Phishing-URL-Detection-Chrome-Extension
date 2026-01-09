const API_URL = "http://127.0.0.1:5000/predict";

const urlElement = document.getElementById("url");
const resultElement = document.getElementById("result");
const confidenceElement = document.getElementById("confidence");
const checkBtn = document.getElementById("checkBtn");

// Get active tab URL
function getCurrentTabUrl(callback) {
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    callback(tabs[0].url);
  });
}

// Call Flask API
function checkPhishing(url) {
  fetch(API_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ url: url })
  })
    .then(response => response.json())
    .then(data => {
      if (data.error) {
        resultElement.textContent = "Error checking URL";
        return;
      }

      if (data.prediction === "phishing") {
        resultElement.textContent = "⚠ Phishing Website";
        resultElement.className = "phishing";
      } else {
        resultElement.textContent = "✔ Legitimate Website";
        resultElement.className = "safe";
      }

      confidenceElement.textContent =
        "Confidence: " + (data.confidence * 100).toFixed(1) + "%";
    })
    .catch(err => {
      resultElement.textContent = "API not reachable";
      console.error(err);
    });
}

// Button click
checkBtn.addEventListener("click", () => {
  getCurrentTabUrl(url => {
    urlElement.textContent = url;
    checkPhishing(url);
  });
});

// Auto-check on popup open
getCurrentTabUrl(url => {
  urlElement.textContent = url;
});
