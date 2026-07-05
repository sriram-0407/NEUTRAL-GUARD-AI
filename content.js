// content.js
(function() {
    chrome.runtime.sendMessage({ action: "GET_RISK_DATA" }, (data) => {
        // Adapt to backend field name: risk_score
        if (!data || data.risk_score === undefined) return;

        const score = data.risk_score;
        let color = "#00ff88"; // Green (Safe)
        let msg = "Website is Safe";

        // Determine category based on score
        if (score >= 70) { 
            color = "#ff004c"; // Red
            msg = "Website is Dangerous"; 
        } else if (score >= 30) { 
            color = "#ff9500"; // Orange
            msg = "Website is Suspicious"; 
        }

        const card = document.createElement('div');
        card.style.cssText = `
            position: fixed; top: 20px; left: 20px; width: 260px;
            background: #010a12; color: white; border-left: 5px solid ${color};
            border-radius: 10px; padding: 15px; z-index: 2147483647;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5); font-family: sans-serif;
            transition: all 0.6s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            transform: translateX(-150%); opacity: 0;
        `;

        // Logic Update: We now map through ALL reasons instead of just picking the first one [0]
        const reasonsHTML = data.reasons && data.reasons.length > 0 
            ? data.reasons.map(reason => `
                <div style="font-size: 10px; color: #aaa; margin-top: 5px; display: flex; gap: 5px;">
                    <span>⚠️</span> <span>${reason}</span>
                </div>
            `).join('') 
            : '';

        card.innerHTML = `
            <div style="font-size: 9px; color: ${color}; font-weight: 900; letter-spacing: 1px; margin-bottom: 5px;">NEUTRAL GUARD AI</div>
            <div style="font-size: 13px; font-weight: bold; margin-top: 3px;">${msg}</div>
            <div id="reasons-container">${reasonsHTML}</div>
        `;

        document.body.appendChild(card);

        // Slide In Animation
        setTimeout(() => {
            card.style.transform = "translateX(0)";
            card.style.opacity = "1";
        }, 300);

        // Slide Out Animation after 4 seconds
        setTimeout(() => {
            card.style.transform = "translateX(-150%)";
            card.style.opacity = "0";
            setTimeout(() => card.remove(), 600);
        }, 4000);
    });
})();