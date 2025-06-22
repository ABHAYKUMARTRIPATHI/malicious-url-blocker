document.getElementById("saveKey").addEventListener("click", () => {
  const key = document.getElementById("apiKey").value;
  chrome.runtime.sendMessage({ type: "setApiKey", key });
  alert("API Key saved successfully!");
});