// background.js
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "GET_RISK_DATA") {
        const url = sender.tab.url;
        
        // 1. Basic validation
        if (!url || !url.startsWith('http')) {
            sendResponse({ risk_score: 0, reasons: ["Internal Page"] });
            return true;
        }

        // 2. Fetch data from your Flask Backend
        fetch('http://127.0.0.1:5000/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url }),
            priority: 'high' // <--- This helps speed up the network request
        })
        .then(response => response.json())
        .then(data => {
            // Save to local storage for history/popup use
            const domain = new URL(url).hostname;
            chrome.storage.local.set({ [domain]: data });
            
            // 3. Send the REAL backend data back to content.js
            sendResponse(data); 
        })
        .catch(error => {
            console.error("Backend Error:", error);
            sendResponse({ risk_score: 0, error: "Backend offline" });
        });

        return true; // CRITICAL: Keeps the message channel open for async fetch
    }
});