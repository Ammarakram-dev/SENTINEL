/* =========================================================
   SENTINEL — FRONTEND APPLICATION
   Complete Frontend / FastAPI Integration
   ========================================================= */

"use strict";


/* =========================================================
   CONFIGURATION
   ========================================================= */
const API_BASE =
    "https://sentinel-api.fastapicloud.dev";


/* =========================================================
   APPLICATION STATE
   ========================================================= */

const state = {

    currentSection: "overview",

    targetType: "url",

    scanning: false,

    backendOnline: false,

    scans: [],

    historyFilter: "all",

    historySearch: ""

};


/* =========================================================
   DOM HELPERS
   ========================================================= */

function $(selector) {

    return document.querySelector(selector);

}


function $$(selector) {

    return document.querySelectorAll(selector);

}


function setText(selector, value) {

    const element = $(selector);

    if (element) {

        element.textContent =
            value ?? "";

    }

}


function createElement(
    tag,
    className = "",
    text = ""
) {

    const element =
        document.createElement(tag);

    if (className) {

        element.className =
            className;

    }

    if (text) {

        element.textContent =
            text;

    }

    return element;

}


/* =========================================================
   INITIALIZATION
   ========================================================= */

document.addEventListener(
    "DOMContentLoaded",
    initializeApp
);


async function initializeApp() {

    console.log(
        "SENTINEL frontend initializing..."
    );

    setupNavigation();

    setupTargetTypes();

    setupScanner();

    setupKeyboard();

    setupHistoryControls();

    setupMobileNavigation();

    setupRefresh();

    updatePlaceholder();

    await checkBackend();

    await loadScanHistory();

    updateDashboard();

    console.log(
        "SENTINEL frontend ready."
    );

}


/* =========================================================
   NAVIGATION
   ========================================================= */

function setupNavigation() {

    $$(".nav-item").forEach(
        button => {

            button.addEventListener(
                "click",
                () => {

                    const section =
                        button.dataset.section;

                    if (section) {

                        showSection(
                            section
                        );

                    }

                }
            );

        }
    );

}


function showSection(sectionName) {

    const section =
        document.getElementById(
            sectionName
        );

    if (!section) {

        return;

    }


    $$(".page-section").forEach(
        item => {

            item.classList.remove(
                "active-section"
            );

        }
    );


    $$(".nav-item").forEach(
        item => {

            item.classList.remove(
                "active"
            );

        }
    );


    section.classList.add(
        "active-section"
    );


    const nav =
        document.querySelector(
            `.nav-item[data-section="${sectionName}"]`
        );


    if (nav) {

        nav.classList.add(
            "active"
        );

    }


    state.currentSection =
        sectionName;


    updatePageTitle(
        sectionName
    );


    closeMobileNavigation();


    window.scrollTo({
        top: 0,
        behavior: "smooth"
    });


    if (
        sectionName === "history"
    ) {

        renderHistory();

    }


    if (
        sectionName === "overview"
    ) {

        updateDashboard();

    }

}


window.showSection =
    showSection;


function updatePageTitle(section) {

    const titles = {

        overview:
            "Overview",

        scanner:
            "Threat Scanner",

        history:
            "Scan History",

        intelligence:
            "Intelligence Center"

    };


    setText(
        "#page-title",
        titles[section]
        || "Overview"
    );

}


/* =========================================================
   TARGET TYPE
   ========================================================= */

function setupTargetTypes() {

    $$(".type-btn").forEach(
        button => {

            button.addEventListener(
                "click",
                () => {

                    $$(".type-btn").forEach(
                        item => {

                            item.classList.remove(
                                "active"
                            );

                        }
                    );


                    button.classList.add(
                        "active"
                    );


                    state.targetType =
                        button.dataset.type
                        || "url";


                    updatePlaceholder();

                    clearScannerMessage();

                }
            );

        }
    );

}


function updatePlaceholder() {

    const input =
        $("#target-input");

    if (!input) {

        return;

    }


    const placeholders = {

        url:
            "https://example.com",

        domain:
            "example.com",

        ip:
            "8.8.8.8"

    };


    input.placeholder =
        placeholders[
            state.targetType
        ]
        || "Enter target";

}


/* =========================================================
   SCANNER
   ========================================================= */

function setupScanner() {

    const button =
        $("#scan-button");

    if (button) {

        button.addEventListener(
            "click",
            performScan
        );

    }

}


function setupKeyboard() {

    const input =
        $("#target-input");

    if (!input) {

        return;

    }


    input.addEventListener(
        "keydown",
        event => {

            if (
                event.key === "Enter"
            ) {

                event.preventDefault();

                performScan();

            }

        }
    );

}


async function performScan() {

    if (state.scanning) {

        return;

    }


    const input =
        $("#target-input");


    if (!input) {

        return;

    }


    const target =
        input.value.trim();


    if (!target) {

        showScannerMessage(
            "Please enter a target before starting the analysis.",
            "error"
        );

        input.focus();

        return;

    }


    if (
        !isValidTarget(
            target,
            state.targetType
        )
    ) {

        showScannerMessage(
            getValidationMessage(
                state.targetType
            ),
            "error"
        );

        input.focus();

        return;

    }


    if (!state.backendOnline) {

        const online =
            await checkBackend();

        if (!online) {

            showScannerMessage(
                "SENTINEL backend is offline. Start FastAPI on port 8000.",
                "error"
            );

            return;

        }

    }


    state.scanning =
        true;


    setScanButtonLoading(
        true
    );


    hideResult();


    showScannerMessage(
        "SENTINEL is analyzing the target...",
        "loading"
    );


    try {

        const response =
            await fetch(
                `${API_BASE}/analyze/threat`,
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({

                        target: target,

                        target_type:
                            state.targetType

                    }),

                    cache: "no-store"
                }
            );


        let data;


        try {

            data =
                await response.json();

        }

        catch {

            throw new Error(
                "Backend returned an invalid response."
            );

        }


        if (!response.ok) {

            throw new Error(
                data?.detail
                || "Scan request failed."
            );

        }


        console.log(
            "SENTINEL result:",
            data
        );


        displayScanResult(
            data
        );


        showScannerMessage(
            "Analysis completed successfully.",
            "success"
        );


        await loadScanHistory();

        updateDashboard();


    }

    catch (error) {

        console.error(
            "SENTINEL scan error:",
            error
        );


        showScannerMessage(
            getFriendlyErrorMessage(
                error
            ),
            "error"
        );

    }

    finally {

        state.scanning =
            false;

        setScanButtonLoading(
            false
        );

    }

}


/* =========================================================
   VALIDATION
   ========================================================= */

function isValidTarget(
    target,
    type
) {

    if (
        type === "url"
    ) {

        try {

            const url =
                new URL(target);

            return (
                url.protocol === "http:"
                ||
                url.protocol === "https:"
            );

        }

        catch {

            return false;

        }

    }


    if (
        type === "domain"
    ) {

        return isDomain(
            target
        );

    }


    if (
        type === "ip"
    ) {

        return isIPv4(
            target
        );

    }


    return false;

}


function isIPv4(value) {

    const parts =
        value.split(".");


    if (
        parts.length !== 4
    ) {

        return false;

    }


    return parts.every(
        part => {

            if (
                !/^\d+$/.test(part)
            ) {

                return false;

            }


            const number =
                Number(part);


            return (
                number >= 0
                &&
                number <= 255
            );

        }
    );

}


function isDomain(value) {

    const domain =
        value
            .trim()
            .toLowerCase();


    if (
        domain.length < 3
        ||
        domain.length > 253
    ) {

        return false;

    }


    if (
        domain.includes(" ")
    ) {

        return false;

    }


    const labels =
        domain.split(".");


    if (
        labels.length < 2
    ) {

        return false;

    }


    return labels.every(
        label => {

            return (
                label.length > 0
                &&
                label.length <= 63
                &&
                !label.startsWith("-")
                &&
                !label.endsWith("-")
                &&
                /^[a-z0-9-]+$/i.test(
                    label
                )
            );

        }
    );

}


function getValidationMessage(type) {

    if (
        type === "url"
    ) {

        return (
            "Enter a valid URL such as https://example.com."
        );

    }


    if (
        type === "domain"
    ) {

        return (
            "Enter a valid domain such as example.com."
        );

    }


    if (
        type === "ip"
    ) {

        return (
            "Enter a valid IPv4 address such as 8.8.8.8."
        );

    }


    return "Enter a valid target.";

}


/* =========================================================
   SCAN BUTTON
   ========================================================= */

function setScanButtonLoading(
    loading
) {

    const button =
        $("#scan-button");

    if (!button) {

        return;

    }


    button.disabled =
        loading;


    if (loading) {

        button.innerHTML = `
            <span class="scan-button-icon">
                ◌
            </span>

            <span>
                Analyzing Target...
            </span>
        `;

    }

    else {

        button.innerHTML = `
            <span class="scan-button-icon">
                ◈
            </span>

            <span>
                Analyze Target
            </span>

            <b>
                →
            </b>
        `;

    }

}


/* =========================================================
   SCANNER MESSAGE
   ========================================================= */

function showScannerMessage(
    message,
    type = ""
) {

    const element =
        $("#scanner-message");

    if (!element) {

        return;

    }


    element.textContent =
        message;


    element.className =
        "scanner-message";


    if (type) {

        element.classList.add(
            type
        );

    }

}


function clearScannerMessage() {

    showScannerMessage(
        ""
    );

}


/* =========================================================
   RESULT
   ========================================================= */

function displayScanResult(
    data
) {

    const result =
        $("#scan-result");

    if (!result) {

        return;

    }


    const analysis =
        data.analysis
        || {};


    const threat =
        data.threat_assessment
        || {};


    const target =
        data.target
        || analysis.url
        || analysis.target
        || "Unknown";


    const score =
        Number(
            threat.risk_score
            ??
            analysis.risk_score
            ??
            0
        );


    const level =
        String(
            threat.risk_level
            ??
            analysis.risk_level
            ??
            "LOW"
        ).toUpperCase();


    const recommendation =
        threat.recommendation
        ||
        "No recommendation available.";


    const indicators =
        Array.isArray(
            threat.indicators
        )
        ?
        threat.indicators
        :
        (
            Array.isArray(
                analysis.indicators
            )
            ?
            analysis.indicators
            :
            []
        );


    setText(
        "#result-target",
        target
    );


    setText(
        "#result-type",
        state.targetType.toUpperCase()
    );


    setText(
        "#risk-score",
        score
    );


    setText(
        "#risk-level",
        level
    );


    setText(
        "#recommendation",
        recommendation
    );


    setText(
        "#result-indicator-count",
        indicators.length
    );


    setText(
        "#result-scan-id",
        data.scan_id
        ?? "—"
    );


    const badge =
        $("#risk-badge");


    if (badge) {

        badge.textContent =
            level;


        badge.className =
            "risk-badge";


        badge.classList.add(
            getRiskClass(level)
        );

    }


    updateScoreVisual(
        score,
        level
    );


    renderIndicators(
        indicators
    );


    result.classList.remove(
        "hidden"
    );


    setTimeout(
        () => {

            result.scrollIntoView({
                behavior: "smooth",
                block: "nearest"
            });

        },
        50
    );

}


function getRiskClass(
    level
) {

    const normalized =
        String(level)
            .toLowerCase();


    if (
        normalized === "critical"
    ) {

        return "risk-critical";

    }


    if (
        normalized === "high"
    ) {

        return "risk-high";

    }


    if (
        normalized === "medium"
    ) {

        return "risk-medium";

    }


    return "risk-low";

}


/* =========================================================
   SCORE VISUAL
   ========================================================= */

function updateScoreVisual(
    score,
    level
) {

    const circle =
        $("#score-circle");


    const scoreElement =
        $("#risk-score");


    const levelElement =
        $("#risk-level");


    let color =
        "var(--accent)";


    const normalized =
        String(level)
            .toUpperCase();


    if (
        normalized === "MEDIUM"
    ) {

        color =
            "var(--warning)";

    }


    if (
        normalized === "HIGH"
        ||
        normalized === "CRITICAL"
    ) {

        color =
            "var(--danger)";

    }


    if (scoreElement) {

        scoreElement.style.color =
            color;

    }


    if (levelElement) {

        levelElement.style.color =
            color;

    }


    if (circle) {

        circle.style.borderColor =
            color;

        circle.style.boxShadow =
            `0 0 35px ${color}22`;

    }

}


/* =========================================================
   INDICATORS
   ========================================================= */

function renderIndicators(
    indicators
) {

    const container =
        $("#indicator-list");

    if (!container) {

        return;

    }


    container.innerHTML =
        "";


    if (
        !Array.isArray(indicators)
        ||
        indicators.length === 0
    ) {

        container.innerHTML = `
            <div class="empty-state">

                <div class="empty-icon">
                    ✓
                </div>

                <h4>
                    No significant indicators detected
                </h4>

                <p>
                    The current SENTINEL analysis rules
                    found no major warning signs.
                </p>

            </div>
        `;

        return;

    }


    indicators.forEach(
        indicator => {

            const severity =
                String(
                    indicator.severity
                    || "low"
                ).toLowerCase();


            const row =
                createElement(
                    "div",
                    "indicator-row"
                );


            const icon =
                createElement(
                    "span",
                    `indicator-icon ${getRiskClass(severity)}`,
                    "!"
                );


            const content =
                createElement(
                    "div",
                    "indicator-content"
                );


            const title =
                createElement(
                    "strong",
                    "",
                    formatSeverity(
                        severity
                    )
                );


            const message =
                createElement(
                    "p",
                    "",
                    indicator.message
                    ||
                    "Security indicator detected."
                );


            content.appendChild(
                title
            );


            content.appendChild(
                message
            );


            if (
                Array.isArray(
                    indicator.keywords
                )
                &&
                indicator.keywords.length
            ) {

                content.appendChild(
                    createElement(
                        "small",
                        "indicator-keywords",
                        `Keywords: ${indicator.keywords.join(", ")}`
                    )
                );

            }


            row.appendChild(
                icon
            );

            row.appendChild(
                content
            );


            container.appendChild(
                row
            );

        }
    );

}


function hideResult() {

    const result =
        $("#scan-result");

    if (result) {

        result.classList.add(
            "hidden"
        );

    }

}


/* =========================================================
   BACKEND
   ========================================================= */

async function checkBackend() {

    try {

        const response =
            await fetch(
                `${API_BASE}/health`,
                {
                    method: "GET",
                    cache: "no-store"
                }
            );


        if (!response.ok) {

            throw new Error(
                `Backend returned ${response.status}`
            );

        }


        const data =
            await response.json();


        state.backendOnline =
            data.status === "healthy";


        updateSystemStatus(
            state.backendOnline
        );


        return true;

    }

    catch (error) {

        state.backendOnline =
            false;


        updateSystemStatus(
            false
        );


        console.error(
            "SENTINEL backend unavailable:",
            error
        );


        return false;

    }

}


function updateSystemStatus(
    online
) {

    const pill =
        $("#backend-pill");


    const pillText =
        $("#backend-pill-text");


    const systemStatus =
        $("#system-status");


    const sidebarStatus =
        $("#sidebar-status");


    const sidebarDetail =
        $("#sidebar-status-detail");


    const diagnostic =
        $("#api-diagnostic");


    if (pill) {

        pill.classList.remove(
            "online",
            "offline"
        );


        pill.classList.add(
            online
            ? "online"
            : "offline"
        );

    }


    setText(
        "#backend-pill-text",
        online
        ? "SYSTEM ONLINE"
        : "OFFLINE"
    );


    setText(
        "#system-status",
        online
        ? "ONLINE"
        : "OFFLINE"
    );


    setText(
        "#sidebar-status",
        online
        ? "System Online"
        : "System Offline"
    );


    setText(
        "#sidebar-status-detail",
        online
        ? "Monitoring active"
        : "Backend unavailable"
    );


    if (systemStatus) {

        systemStatus.style.color =
            online
            ? "var(--accent)"
            : "var(--danger)";

    }


    if (diagnostic) {

        diagnostic.textContent =
            online
            ? "ONLINE"
            : "OFFLINE";


        diagnostic.classList.toggle(
            "online",
            online
        );

    }

}


/* =========================================================
   HISTORY
   ========================================================= */

async function loadScanHistory() {

    try {

        const response =
            await fetch(
                `${API_BASE}/scans`,
                {
                    method: "GET",
                    cache: "no-store"
                }
            );


        if (!response.ok) {

            throw new Error(
                `History request failed: ${response.status}`
            );

        }


        const data =
            await response.json();


        state.scans =
            Array.isArray(
                data.scans
            )
            ?
            data.scans
            :
            [];


        renderHistory();

        renderRecentScans();

        updateDashboard();


    }

    catch (error) {

        console.error(
            "History loading failed:",
            error
        );


        state.scans =
            [];


        renderHistoryError();

        renderRecentScans();

        updateDashboard();

    }

}


/* =========================================================
   HISTORY CONTROLS
   ========================================================= */

function setupHistoryControls() {

    const search =
        $("#history-search");


    if (search) {

        search.addEventListener(
            "input",
            event => {

                state.historySearch =
                    event.target.value
                        .trim()
                        .toLowerCase();


                renderHistory();

            }
        );

    }


    $$(".filter-btn").forEach(
        button => {

            button.addEventListener(
                "click",
                () => {

                    $$(".filter-btn").forEach(
                        item => {

                            item.classList.remove(
                                "active"
                            );

                        }
                    );


                    button.classList.add(
                        "active"
                    );


                    state.historyFilter =
                        button.dataset.filter
                        || "all";


                    renderHistory();

                }
            );

        }
    );

}


/* =========================================================
   FILTER HISTORY
   ========================================================= */

function getFilteredScans() {

    return state.scans.filter(
        scan => {

            const target =
                String(
                    scan.target
                    || ""
                ).toLowerCase();


            const level =
                String(
                    scan.risk_level
                    || "low"
                ).toLowerCase();


            const matchesSearch =
                !state.historySearch
                ||
                target.includes(
                    state.historySearch
                );


            const matchesFilter =
                state.historyFilter === "all"
                ||
                level === state.historyFilter;


            return (
                matchesSearch
                &&
                matchesFilter
            );

        }
    );

}


/* =========================================================
   RENDER HISTORY
   ========================================================= */

function renderHistory() {

    const container =
        $("#history-list");

    if (!container) {

        return;

    }


    const scans =
        getFilteredScans();


    container.innerHTML =
        "";


    if (
        scans.length === 0
    ) {

        container.innerHTML = `
            <div class="empty-state">

                <div class="empty-icon">
                    ◌
                </div>

                <h4>
                    ${
                        state.scans.length
                        ?
                        "No matching scans"
                        :
                        "No scan history"
                    }
                </h4>

                <p>
                    ${
                        state.scans.length
                        ?
                        "Try another search or risk filter."
                        :
                        "Completed assessments will appear here."
                    }
                </p>

            </div>
        `;

        return;

    }


    scans.forEach(
        scan => {

            container.appendChild(
                createHistoryItem(
                    scan
                )
            );

        }
    );

}


function createHistoryItem(
    scan
) {

    const item =
        createElement(
            "div",
            "history-item"
        );


    const targetCell =
        createElement(
            "div",
            "history-target"
        );


    const icon =
        createElement(
            "div",
            `history-icon ${getRiskClass(scan.risk_level)}`,
            getTargetIcon(
                scan.target_type
            )
        );


    const targetText =
        createElement(
            "div",
            "history-target-text"
        );


    targetText.appendChild(
        createElement(
            "strong",
            "",
            scan.target
        )
    );


    targetText.appendChild(
        createElement(
            "small",
            "",
            `Scan #${scan.id}`
        )
    );


    targetCell.appendChild(
        icon
    );

    targetCell.appendChild(
        targetText
    );


    const type =
        createElement(
            "div",
            "history-type",
            String(
                scan.target_type
                || "unknown"
            ).toUpperCase()
        );


    const score =
        createElement(
            "div",
            `history-score ${getRiskClass(scan.risk_level)}`,
            `${scan.risk_score}/100`
        );


    const risk =
        createElement(
            "div",
            `history-risk-label ${getRiskClass(scan.risk_level)}`,
            String(
                scan.risk_level
                || "LOW"
            ).toUpperCase()
        );


    const date =
        createElement(
            "div",
            "history-date",
            formatDate(
                scan.created_at
            )
        );


    item.appendChild(
        targetCell
    );

    item.appendChild(
        type
    );

    item.appendChild(
        score
    );

    item.appendChild(
        risk
    );

    item.appendChild(
        date
    );


    return item;

}


/* =========================================================
   RECENT SCANS
   ========================================================= */

function renderRecentScans() {

    const container =
        $("#recent-scans");

    if (!container) {

        return;

    }


    container.innerHTML =
        "";


    const recent =
        state.scans.slice(
            0,
            5
        );


    if (
        recent.length === 0
    ) {

        container.innerHTML = `
            <div class="empty-state">

                <div class="empty-icon">
                    ◌
                </div>

                <h4>
                    No scans recorded yet
                </h4>

                <p>
                    Run your first security assessment
                    to populate the activity stream.
                </p>

            </div>
        `;

        return;

    }


    recent.forEach(
        scan => {

            container.appendChild(
                createRecentScan(
                    scan
                )
            );

        }
    );

}


function createRecentScan(
    scan
) {

    const row =
        createElement(
            "div",
            "recent-scan-row"
        );


    const icon =
        createElement(
            "div",
            `recent-scan-icon ${getRiskClass(scan.risk_level)}`,
            getTargetIcon(
                scan.target_type
            )
        );


    const content =
        createElement(
            "div",
            "recent-scan-content"
        );


    content.appendChild(
        createElement(
            "strong",
            "",
            scan.target
        )
    );


    content.appendChild(
        createElement(
            "small",
            "",
            `${String(scan.target_type || "unknown").toUpperCase()} • ${formatDate(scan.created_at)}`
        )
    );


    const risk =
        createElement(
            "div",
            `recent-scan-risk ${getRiskClass(scan.risk_level)}`,
            `${scan.risk_score}/100`
        );


    row.appendChild(
        icon
    );

    row.appendChild(
        content
    );

    row.appendChild(
        risk
    );


    return row;

}


/* =========================================================
   DASHBOARD ANALYTICS
   ========================================================= */

function updateDashboard() {

    const scans =
        state.scans;


    const total =
        scans.length;


    const low =
        scans.filter(
            scan =>
                String(
                    scan.risk_level
                    || ""
                ).toUpperCase()
                === "LOW"
        ).length;


    const medium =
        scans.filter(
            scan =>
                String(
                    scan.risk_level
                    || ""
                ).toUpperCase()
                === "MEDIUM"
        ).length;


    const high =
        scans.filter(
            scan =>
                String(
                    scan.risk_level
                    || ""
                ).toUpperCase()
                === "HIGH"
        ).length;


    const critical =
        scans.filter(
            scan =>
                String(
                    scan.risk_level
                    || ""
                ).toUpperCase()
                === "CRITICAL"
        ).length;


    setText(
        "#total-scans",
        total
    );


    setText(
        "#high-risk",
        high + critical
    );


    setText(
        "#low-risk",
        low
    );


    setText(
        "#total-threat-count",
        total
    );


    setText(
        "#legend-low",
        low
    );


    setText(
        "#legend-medium",
        medium
    );


    setText(
        "#legend-high",
        high
    );


    setText(
        "#legend-critical",
        critical
    );


    updateDonut(
        low,
        medium,
        high,
        critical,
        total
    );


    updateSystemStatus(
        state.backendOnline
    );

}


/* =========================================================
   DONUT
   ========================================================= */

function updateDonut(
    low,
    medium,
    high,
    critical,
    total
) {

    const donut =
        $(".donut-chart");

    if (!donut) {

        return;

    }


    if (
        total === 0
    ) {

        donut.style.background =
            "conic-gradient(#163029 0deg 360deg)";

        return;

    }


    const lowDeg =
        (low / total) * 360;


    const mediumDeg =
        (medium / total) * 360;


    const highDeg =
        (high / total) * 360;


    const criticalDeg =
        (critical / total) * 360;


    const mediumEnd =
        lowDeg + mediumDeg;


    const highEnd =
        mediumEnd + highDeg;


    const criticalEnd =
        highEnd + criticalDeg;


    donut.style.background = `
        conic-gradient(
            var(--accent) 0deg ${lowDeg}deg,
            var(--warning) ${lowDeg}deg ${mediumEnd}deg,
            var(--danger) ${mediumEnd}deg ${highEnd}deg,
            #b23dff ${highEnd}deg ${criticalEnd}deg,
            #163029 ${criticalEnd}deg 360deg
        )
    `;

}


/* =========================================================
   MOBILE NAVIGATION
   ========================================================= */

function setupMobileNavigation() {

    const menu =
        $("#mobile-menu");


    const sidebar =
        $("#sidebar");


    const overlay =
        $("#sidebar-overlay");


    if (
        !menu
        ||
        !sidebar
        ||
        !overlay
    ) {

        return;

    }


    menu.addEventListener(
        "click",
        () => {

            sidebar.classList.toggle(
                "mobile-open"
            );

            overlay.classList.toggle(
                "active"
            );

        }
    );


    overlay.addEventListener(
        "click",
        closeMobileNavigation
    );

}


function closeMobileNavigation() {

    const sidebar =
        $("#sidebar");


    const overlay =
        $("#sidebar-overlay");


    if (sidebar) {

        sidebar.classList.remove(
            "mobile-open"
        );

    }


    if (overlay) {

        overlay.classList.remove(
            "active"
        );

    }

}


/* =========================================================
   REFRESH
   ========================================================= */

function setupRefresh() {

    const button =
        $("#refresh-button");


    if (button) {

        button.addEventListener(
            "click",
            async () => {

                button.style.transform =
                    "rotate(360deg)";


                await refreshSentinel();


                setTimeout(
                    () => {

                        button.style.transform =
                            "";

                    },
                    350
                );

            }
        );

    }

}


window.refreshSentinel =
    async function () {

        const online =
            await checkBackend();


        await loadScanHistory();


        updateDashboard();


        return online;

    };


/* =========================================================
   AUTO REFRESH
   ========================================================= */

setInterval(
    async () => {

        if (
            document.hidden
        ) {

            return;

        }


        await checkBackend();

        await loadScanHistory();

    },
    30000
);


/* =========================================================
   ERROR HANDLING
   ========================================================= */

function getFriendlyErrorMessage(
    error
) {

    const message =
        String(
            error?.message
            || ""
        );


    if (
        message.includes(
            "Failed to fetch"
        )
    ) {

        return (
            "Scan failed: Unable to reach SENTINEL. " +
            "Make sure FastAPI is running on port 8000."
        );

    }


    if (
        message.includes(
            "NetworkError"
        )
    ) {

        return (
            "Unable to connect to the SENTINEL backend."
        );

    }


    return (
        `Scan failed: ${
            message
            ||
            "Unknown error."
        }`
    );

}


function renderHistoryError() {

    const container =
        $("#history-list");

    if (!container) {

        return;

    }


    container.innerHTML = `
        <div class="empty-state">

            <div class="empty-icon">
                !
            </div>

            <h4>
                Unable to load scan history
            </h4>

            <p>
                Check that SENTINEL's FastAPI backend
                is running on port 8000.
            </p>

        </div>
    `;

}


/* =========================================================
   FORMATTING
   ========================================================= */

function formatSeverity(
    severity
) {

    const value =
        String(
            severity
            || "low"
        );


    return (
        value.charAt(0).toUpperCase()
        +
        value.slice(1)
    );

}


function formatDate(
    value
) {

    if (!value) {

        return "Unknown time";

    }


    const date =
        new Date(value);


    if (
        Number.isNaN(
            date.getTime()
        )
    ) {

        return value;

    }


    return date.toLocaleString(
        undefined,
        {
            dateStyle: "medium",
            timeStyle: "short"
        }
    );

}


function getTargetIcon(
    type
) {

    switch (
        String(type)
            .toLowerCase()
    ) {

        case "url":
            return "⌕";

        case "domain":
            return "◉";

        case "ip":
            return "◎";

        default:
            return "◈";

    }

}


/* =========================================================
   CONSOLE
   ========================================================= */

console.log(
    "%c SENTINEL ",
    "background:#42f5b5;color:#03110b;font-weight:900;padding:6px 10px;border-radius:6px;"
);

console.log(
    "Threat Intelligence Platform initialized."
);