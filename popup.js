document.addEventListener('DOMContentLoaded', async () => {
    // 1. Get current tab URL
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url || !tab.url.startsWith('http')) {
        document.getElementById('banner').innerText = "INVALID PAGE";
        return;
    }

    const currentUrl = tab.url;
    const domain = new URL(currentUrl).hostname;
    
    // UI Elements
    const banner = document.getElementById('banner');
    const ring = document.getElementById('riskRing');
    const scoreNum = document.getElementById('scoreNum');
    const secureBtn = document.getElementById('secure-btn');
    const historyBtn = document.getElementById('history-btn');
    const advancedAnalysisBtn = document.getElementById('advanced-analysis-btn');
    const drawer = document.getElementById('forensic-drawer');
    const closeDrawerBtn = document.getElementById('close-drawer');
    const reasonsList = document.getElementById('reasons-list');
    const openSettingsBtn = document.getElementById('openSettings');
    const loadingView = document.getElementById('loading-view');
    const resultView = document.getElementById('result-view');
    const homeView = document.getElementById('home-view');
    const mainHeader = document.getElementById('main-header');
    const startScanBtn = document.getElementById('start-scan-btn');
    const stopScanBtn = document.getElementById('stop-scan-btn');

    let currentAbortController = null;

    // Show "Home" state by default
    if (homeView) homeView.style.display = 'block';
    if (loadingView) loadingView.style.display = 'none';
    if (resultView) resultView.style.display = 'none';

    // Setup Settings listeners
    chrome.storage.local.get(['settings'], (res) => {
        const s = res.settings || {};
        const chkAuto = document.getElementById('popupAutoProtect');
        const chkNotify = document.getElementById('popupNotifications');
        const chkClickjacking = document.getElementById('popupCheckClickjacking');
        const chkDomainAge = document.getElementById('popupCheckDomainAge');
        
        if (chkAuto) chkAuto.checked = s.autoProtect !== false;
        if (chkNotify) chkNotify.checked = s.notifications !== false;
        if (chkClickjacking) chkClickjacking.checked = s.checkClickjacking !== false;
        if (chkDomainAge) chkDomainAge.checked = s.checkDomainAge !== false;

        const saveSettings = () => {
            chrome.storage.local.set({ settings: {
                autoProtect: chkAuto ? chkAuto.checked : true,
                notifications: chkNotify ? chkNotify.checked : true,
                checkClickjacking: chkClickjacking ? chkClickjacking.checked : true,
                checkDomainAge: chkDomainAge ? chkDomainAge.checked : true
            }});
        };

        if (chkAuto) chkAuto.onchange = saveSettings;
        if (chkNotify) chkNotify.onchange = saveSettings;
        if (chkClickjacking) chkClickjacking.onchange = saveSettings;
        if (chkDomainAge) chkDomainAge.onchange = saveSettings;
    });

    // Settings Overlays
    const settingsOverlay = document.getElementById('settings-overlay');
    const closeSettingsOverlay = document.getElementById('close-settings-overlay');
    
    const analyticsOverlay = document.getElementById('analytics-overlay');
    const openAnalyticsBtn = document.getElementById('openAnalyticsBtn');
    const closeAnalyticsOverlay = document.getElementById('close-analytics-overlay');

    if (openSettingsBtn && settingsOverlay) {
        openSettingsBtn.onclick = (e) => {
            e.stopPropagation();
            settingsOverlay.classList.add('active');
        };
    }

    if (closeSettingsOverlay) {
        closeSettingsOverlay.onclick = () => {
            settingsOverlay.classList.remove('active');
        };
    }

    if (openAnalyticsBtn && analyticsOverlay) {
        openAnalyticsBtn.onclick = () => {
            analyticsOverlay.classList.add('active');
            renderChart();
        };
    }

    if (closeAnalyticsOverlay) {
        closeAnalyticsOverlay.onclick = () => {
            analyticsOverlay.classList.remove('active');
        };
    }

    function renderChart() {
        chrome.storage.local.get(['scanHistory'], (result) => {
            const history = result.scanHistory || [];
            const chartContainer = document.getElementById('chartContainer');
            const statTotal = document.getElementById('stat-total');
            const statRisky = document.getElementById('stat-risky');
            
            if(!chartContainer) return;
            chartContainer.innerHTML = '';
            
            statTotal.innerText = history.length;
            const riskyCount = history.filter(h => h.score >= 30).length;
            statRisky.innerText = riskyCount;

            // Group by Day (Last 7 Days)
            const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
            const today = new Date();
            const last7Days = [];
            for(let i=6; i>=0; i--) {
                const d = new Date(today);
                d.setDate(d.getDate() - i);
                last7Days.push({
                    label: days[d.getDay()],
                    dateStr: d.toLocaleDateString(),
                    safe: 0,
                    caution: 0,
                    danger: 0,
                    total: 0
                });
            }

            // Populate data
            history.forEach(item => {
                const itemDate = new Date(item.date).toLocaleDateString();
                const dayObj = last7Days.find(d => d.dateStr === itemDate);
                if (dayObj) {
                    dayObj.total++;
                    if (item.score < 30) dayObj.safe++;
                    else if (item.score < 70) dayObj.caution++;
                    else dayObj.danger++;
                }
            });

            // Find max for scaling
            const maxVal = Math.max(...last7Days.map(d => d.total), 1);

            // Render bars
            last7Days.forEach(day => {
                const wrapper = document.createElement('div');
                wrapper.className = 'bar-wrapper';

                const countLabel = document.createElement('div');
                countLabel.className = 'bar-count';
                countLabel.innerText = day.total > 0 ? day.total : '';

                const heightPct = (day.total / maxVal) * 100;
                
                const bar = document.createElement('div');
                bar.className = 'bar';
                // Determine dominant risk for the day's bar color
                if (day.danger > 0) bar.classList.add('danger');
                else if (day.caution > 0) bar.classList.add('warning');
                else if (day.safe > 0) bar.classList.add('safe');

                bar.style.height = '0%'; // Start at 0 for animation
                setTimeout(() => {
                    bar.style.height = Math.max(heightPct, 5) + '%';
                }, 100);

                const dayLabel = document.createElement('div');
                dayLabel.className = 'bar-label';
                dayLabel.innerText = day.label;

                wrapper.appendChild(countLabel);
                wrapper.appendChild(bar);
                wrapper.appendChild(dayLabel);
                chartContainer.appendChild(wrapper);
            });
        });
    }

    if (stopScanBtn) {
        stopScanBtn.onclick = () => {
            if (currentAbortController) {
                currentAbortController.abort();
            }
            loadingView.style.display = 'none';
            if (mainHeader) mainHeader.style.display = 'flex';
            if (homeView) homeView.style.display = 'block';
            document.body.className = 'home-state';
            const statusTxt = document.getElementById('header-status-text');
            if (statusTxt) statusTxt.innerText = 'READY TO SCAN';
        };
    }

    if (!startScanBtn) return;
    
    startScanBtn.onclick = async () => {
        // Show "Analyzing" state
        if (homeView) homeView.style.display = 'none';
        if (mainHeader) mainHeader.style.display = 'none';
        loadingView.style.display = 'flex';
        resultView.style.display = 'none';
        document.body.className = 'analyzing';

        currentAbortController = new AbortController();

        // Load heuristic preferences from storage before calling backend
        const storageResult = await chrome.storage.local.get(['settings']);
        const settings = storageResult.settings || { 
            autoProtect: true, 
            notifications: true,
            checkClickjacking: true,
            checkDomainAge: true
        };

        try {
            // 2. FETCH NEW DATA FROM BACKEND
            const response = await fetch('http://127.0.0.1:5000/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    url: currentUrl,
                    heuristics: {
                        clickjacking: settings.checkClickjacking !== false,
                        domainAge: settings.checkDomainAge !== false
                    }
                }),
                signal: currentAbortController.signal
            });

            const backendData = await response.json();
            if (mainHeader) mainHeader.style.display = 'flex'; // Restore header for results
            
            const statusTxt = document.getElementById('header-status-text');
            if (statusTxt) statusTxt.innerText = 'LIVE SCAN';

        const score = backendData.risk_score;
        const checks = backendData.checks || [];
        const reasons = backendData.reasons || [];

        // 3. Determine Colors and Labels based on Backend Score
        let color, bannerText, glow;

        if (score > 70) {
            document.body.className = 'high-risk';
            color = "#ff004c"; // Red
            bannerText = "DANGEROUS SITE";
            glow = "0 0 20px rgba(255, 0, 76, 0.7)";
        } else if (score >= 30) {
            document.body.className = 'mid-risk';
            color = "#ff9500"; // Orange
            bannerText = "CAUTION: UNKNOWN";
            glow = "0 0 20px rgba(255, 149, 0, 0.7)";
        } else {
            document.body.className = 'low-risk';
            color = "#00ff88"; // Green
            bannerText = "SITE VERIFIED SAFE";
            glow = "0 0 20px rgba(0, 255, 136, 0.7)";
        }

        // 4. Apply UI Updates
        loadingView.style.display = 'none';
        resultView.style.display = 'block';

        if (scoreNum) scoreNum.innerText = score;
        if (banner) {
            banner.innerText = bannerText;
            banner.style.backgroundColor = color;
            banner.style.boxShadow = glow;
        }
        
        if (ring) {
            ring.style.stroke = color;
            ring.style.filter = `drop-shadow(0 0 5px ${color})`;
            // Allow DOM to process 'display: block' before triggering the animation
            setTimeout(() => {
                ring.style.strokeDasharray = `${score}, 100`;
            }, 50);
        }

        if (openSettingsBtn) {
            openSettingsBtn.style.borderColor = color;
            openSettingsBtn.style.color = color;
            openSettingsBtn.style.boxShadow = glow;
        }

        // 5. Update Secure Session Button
        if (secureBtn) {
            secureBtn.style.backgroundColor = color;
            secureBtn.style.boxShadow = glow;

            if (score > 70) {
                secureBtn.innerText = "TERMINATE SESSION";
                secureBtn.classList.add('blink-active'); 
                secureBtn.onclick = () => chrome.tabs.remove(tab.id);
            } else {
                secureBtn.innerText = "SECURE SESSION";
                secureBtn.classList.remove('blink-active');
                secureBtn.onclick = () => alert("Security Active: " + domain + " is protected.");
            }
        }

       if (historyBtn) {
            // Only update the border color dynamically based on score
            historyBtn.style.borderColor = color; 
            
            // Set text to white explicitly here as well
            historyBtn.style.color = "white"; 
            
            // Remove the hardcoded glow from JS so the CSS :hover can take over
            historyBtn.style.boxShadow = "none"; 

            // Handle the dynamic hover glow using listeners
            historyBtn.onmouseenter = () => {
                historyBtn.style.boxShadow = `0 0 8px ${color}80`; // Added '80' for 50% opacity
            };
            historyBtn.onmouseleave = () => {
                historyBtn.style.boxShadow = "none";
            };

            historyBtn.onclick = () => chrome.tabs.create({ url: 'history/history.html' });
        }

        if (advancedAnalysisBtn) {
            advancedAnalysisBtn.style.borderColor = color; 
            advancedAnalysisBtn.style.color = "white"; 
            advancedAnalysisBtn.style.boxShadow = "none"; 

            advancedAnalysisBtn.onmouseenter = () => {
                advancedAnalysisBtn.style.boxShadow = `0 0 8px ${color}80`;
            };
            advancedAnalysisBtn.onmouseleave = () => {
                advancedAnalysisBtn.style.boxShadow = "none";
            };

            advancedAnalysisBtn.onclick = () => {
                if (drawer.classList.contains('open')) {
                    drawer.classList.remove('open');
                    return;
                }
                
                reasonsList.innerHTML = '';
                
                const drawerHeader = document.querySelector('.drawer-header');
                if (drawerHeader) {
                    drawerHeader.style.borderBottom = `2px solid ${color}`;
                }

                if (!checks || checks.length === 0) {
                    const li = document.createElement('li');
                    li.innerText = "NO SECURITY DATA AVAILABLE.";
                    li.style.borderColor = "#00ff88"; // Green
                    li.style.color = "#00ff88";
                    li.style.backgroundColor = "rgba(0, 255, 136, 0.1)";
                    reasonsList.appendChild(li);
                } else {
                    checks.forEach((check, index) => {
                        const li = document.createElement('li');
                        li.classList.add('check-item');
                        // Staggered animation delay (slowed down)
                        li.style.animationDelay = `${index * 0.2}s`;
                        li.style.display = 'flex';
                        li.style.flexDirection = 'column';
                        li.style.gap = '4px';

                        const headerRow = document.createElement('div');
                        headerRow.style.display = 'flex';
                        headerRow.style.justifyContent = 'space-between';
                        headerRow.style.alignItems = 'center';

                        const title = document.createElement('span');
                        title.innerText = check.name.toUpperCase();
                        title.style.fontWeight = '800';
                        title.style.fontSize = '11px';
                        title.style.letterSpacing = '0.5px';

                        const penaltyBadge = document.createElement('span');
                        penaltyBadge.style.fontWeight = '900';
                        penaltyBadge.style.fontSize = '9px';
                        penaltyBadge.style.padding = '2px 6px';
                        penaltyBadge.style.borderRadius = '4px';

                        const desc = document.createElement('span');
                        desc.innerText = check.message;
                        desc.style.fontSize = '10px';

                        headerRow.appendChild(title);
                        headerRow.appendChild(penaltyBadge);

                        li.appendChild(headerRow);
                        li.appendChild(desc);

                        if (check.status === 'pass') {
                            li.style.borderColor = "#00ff88";
                            title.style.color = "white";
                            desc.style.color = "#00ff88";
                            li.style.backgroundColor = "rgba(0, 255, 136, 0.05)";
                            penaltyBadge.style.backgroundColor = "rgba(0, 255, 136, 0.15)";
                            penaltyBadge.style.color = "#00ff88";
                            penaltyBadge.innerText = `+0 RISK`;
                        } else if (check.status === 'warning') {
                            li.style.borderColor = "#ff9500";
                            title.style.color = "white";
                            desc.style.color = "#ff9500";
                            li.style.backgroundColor = "rgba(255, 149, 0, 0.05)";
                            penaltyBadge.style.backgroundColor = "rgba(255, 149, 0, 0.15)";
                            penaltyBadge.style.color = "#ff9500";
                            penaltyBadge.innerText = `+${check.penalty || 0} RISK`;
                        } else {
                            li.style.borderColor = "#ff004c";
                            title.style.color = "white";
                            desc.style.color = "#ffb3c6";
                            li.style.backgroundColor = "rgba(255, 0, 76, 0.05)";
                            penaltyBadge.style.backgroundColor = "rgba(255, 0, 76, 0.15)";
                            penaltyBadge.style.color = "#ff8da1"; 
                            penaltyBadge.innerText = `+${check.penalty || 0} RISK`;
                        }

                        reasonsList.appendChild(li);
                    });
                }
                drawer.classList.add('open');

                // Smoothly scroll down to focus perfectly on the advanced analysis section
                setTimeout(() => {
                    drawer.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }, 200);
            };
        }

        if (closeDrawerBtn) {
            closeDrawerBtn.onclick = () => {
                drawer.classList.remove('open');
            };
        }

        // 6. SAVE NEW RESULTS TO HISTORY
        const historyEntry = {
            domain: domain,
            score: score,
            reasons: reasons,
            date: new Date().toLocaleString([], { 
                year: 'numeric', month: 'numeric', day: 'numeric', 
                hour: '2-digit', minute: '2-digit' 
            })
        };

        chrome.storage.local.get(['scanHistory'], (result) => {
            let history = result.scanHistory || [];
            // Remove previous entry for same domain to keep history clean
            history = history.filter(item => item.domain !== domain);
            history.unshift(historyEntry);
            chrome.storage.local.set({ 'scanHistory': history.slice(0, 50) });
        });

    } catch (error) {
        if (error.name === 'AbortError') {
            console.log('Analysis aborted by user.');
            document.body.className = 'home-state';
            const statusTxt = document.getElementById('header-status-text');
            if (statusTxt) statusTxt.innerText = 'READY TO SCAN';
            return;
        }
        console.error("Backend offline:", error);
        document.body.className = 'offline';
        loadingView.style.display = 'none';
        if (mainHeader) mainHeader.style.display = 'flex';
        resultView.style.display = 'block';
        if (banner) {
            banner.innerText = "API OFFLINE";
            banner.style.backgroundColor = "#555";
        }
        const statusTxt = document.getElementById('header-status-text');
        if (statusTxt) statusTxt.innerText = 'OFFLINE';
    }
    }; // Close startScanBtn.onclick
});