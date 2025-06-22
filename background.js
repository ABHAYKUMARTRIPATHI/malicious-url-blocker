let apiKey = "";

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "setApiKey") {
    apiKey = message.key;
    chrome.storage.local.set({ apiKey: apiKey });
  }
});

chrome.webRequest.onBeforeRequest.addListener(
  async (details) => {
    const url = details.url;
    const storedKey = await chrome.storage.local.get("apiKey");
    const key = storedKey.apiKey || apiKey;

    if (!key) return;

    const res = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": key,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: `url=${encodeURIComponent(url)}`
    });

    const data = await res.json();
    const analysisId = data.data.id;

    const resultRes = await fetch(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      {
        method: "GET",
        headers: {
          "x-apikey": key
        }
      }
    );

    const result = await resultRes.json();
    const stats = result.data.attributes.stats;

    if (stats.malicious > 0 || stats.suspicious > 0) {
      chrome.tabs.update(details.tabId, { url: chrome.runtime.getURL("warning.html") });
      return { cancel: true };
    }
  },
  { urls: ["<all_urls>"] },
  ["blocking"]
);