import { fetchData } from './api.js';
import { renderFramework, renderTagFilters } from './ui.js';

(() => {
    'use strict';
    
    const SUCCESS_COLOR = '#00d4ff'; 
    const ERROR_COLOR = '#ef4444';
    const WARNING_COLOR = '#facc15';
    const CSS_CLASSES = {
        DISABLED_LINK: 'disabled-link',
        COPY_SUCCESS: 'is-copied',
        COPY_FAILURE: 'is-failed',
    };
    const PRESETS = {
        PASSIVE: ['01', '02'],
        QUICK: ['02', '03', '05', '12'],
        DEEP: ['01', '02', '03', '04', '05', '06', '09', '12'],
        WEB_VULN: ['02', '03', '06', '09', '12', '13'],
        FULL: ['01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12', '13', '14'],
    };

    const elements = {
        urlInput: document.getElementById('urlInput'),
        setTargetBtn: document.getElementById('setTargetBtn'),
        clearTargetBtn: document.getElementById('clearTargetBtn'),
        statusMessage: document.getElementById('statusMessage'),
        reconGrid: document.getElementById('reconGrid'),
        generateScriptBtn: document.getElementById('generateScriptBtn'),
        copyScriptBtn: document.getElementById('copyScriptBtn'),
        downloadScriptBtn: document.getElementById('downloadScriptBtn'),
        selectAllBtn: document.getElementById('selectAllBtn'),
        deselectAllBtn: document.getElementById('deselectAllBtn'),
        loadPassiveScanBtn: document.getElementById('loadPassiveScanBtn'),
        loadQuickScanBtn: document.getElementById('loadQuickScanBtn'),
        loadDeepScanBtn: document.getElementById('loadDeepScanBtn'),
        loadWebVulnScanBtn: document.getElementById('loadWebVulnScanBtn'),
        loadFullScanBtn: document.getElementById('loadFullScanBtn'),
        resetAllBtn: document.getElementById('resetAllBtn'),
        scriptContainer: document.getElementById('scriptContainer'),
        scriptSection: document.getElementById('scriptSection'),
        targetSection: document.getElementById('targetSection'),
        generatedScript: document.getElementById('generatedScript'),
        scriptFilename: document.getElementById('scriptFilename'),
        scriptStats: document.getElementById('scriptStats'),
        viewDepsBtn: document.getElementById('viewDepsBtn'),
        depsContainer: document.getElementById('depsContainer'),
        copyDepsBtn: document.getElementById('copyDepsBtn'),
        depsList: document.getElementById('depsList'),
        generateInstallerBtn: document.getElementById('generateInstallerBtn'),
        workflowMapContainer: document.getElementById('workflowMapContainer'),
        workflowMap: document.getElementById('workflowMap'),
        searchInput: document.getElementById('searchInput'),
        clearSearchBtn: document.getElementById('clearSearchBtn'),
        noResultsMessage: document.getElementById('noResultsMessage'),
        tagFilterContainer: document.getElementById('tagFilterContainer'),
        expandAllBtn: document.getElementById('expandAllBtn'),
        collapseAllBtn: document.getElementById('collapseAllBtn'),
    };
    
    let targetDomain = '';
    let statusTimeout;
    let generatedScriptContent = '';
    let generatedInstallerContent = '';
    let reconSteps = [];

    const TOOL_INSTALL_COMMANDS = [
            { name: 'Amass Enum', go: 'go install -v github.com/owasp-amass/amass/v4/...@master' },
            { name: 'Aquatone', go: 'go install github.com/michenriksen/aquatone@latest' },
            { name: 'Arjun', pip: 'pip3 install arjun' },
            { name: 'Assetfinder', go: 'go install github.com/tomnomnom/assetfinder@latest' },
            { name: 'Chaos DB', go: 'go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest' },
            { name: 'Cloud_enum', pip: 'pip3 install cloud_enum' },
            { name: 'Dalfox XSS', go: 'go install -v github.com/hahwul/dalfox/v2@latest' },
            { name: 'Dig DNS Records', apt: 'sudo apt-get install -y dnsutils', brew: 'brew install bind', notes: 'Usually pre-installed.' },
            { name: 'DNSRecon', pip: 'pip3 install dnsrecon' },
            { name: 'dnsx Resolution', go: 'go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest' },
            { name: 'ffuf Fuzzer', go: 'go install github.com/ffuf/ffuf/v2@latest' },
            { name: 'Findomain', source: 'Visit https://github.com/findomain/findomain/releases' },
            { name: 'Gau (Get All URLs)', go: 'go install github.com/lc/gau/v2/cmd/gau@latest' },
            { name: 'GF Patterns', go: 'go install github.com/tomnomnom/gf@latest' },
            { name: 'GitLeaks', brew: 'brew install gitleaks', source: 'curl -sSfL https://raw.githubusercontent.com/gitleaks/gitleaks/master/install.sh | sh -s -- -b /usr/local/bin' },
            { name: 'Gobuster Directory', apt: 'sudo apt-get install -y gobuster', brew: 'brew install gobuster' },
            { name: 'Gospider', go: 'go install github.com/jaeles-project/gospider@latest' },
            { name: 'Gowitness', go: 'go install github.com/sensepost/gowitness@latest' },
            { name: 'Httprobe', go: 'go install github.com/tomnomnom/httprobe@latest' },
            { name: 'httpx Probe', go: 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest' },
            { name: 'Katana Crawler', go: 'go install -v github.com/projectdiscovery/katana/cmd/katana@latest' },
            { name: 'LinkFinder', source: 'git clone https://github.com/GerbenJavado/LinkFinder.git && cd LinkFinder && pip3 install -r requirements.txt && python3 setup.py install'},
            { name: 'Naabu Fast Scan', go: 'go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest' },
            { name: 'Nikto Web Scanner', apt: 'sudo apt-get install -y nikto', brew: 'brew install nikto' },
            { name: 'Nmap Service Detection', apt: 'sudo apt-get install -y nmap', brew: 'brew install nmap' },
            { name: 'Nuclei Templates', go: 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest' },
            { name: 'Nuclei CVE Scan', go: 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest' },
            { name: 'ParamSpider', source: 'git clone https://github.com/devanshbatham/ParamSpider && cd ParamSpider && pip3 install .'},
            { name: 'RustScan', brew: 'brew install rustscan', source: 'Visit https://github.com/RustScan/RustScan/releases' },
            { name: 'S3Scanner', pip: 'pip3 install s3scanner' },
            { name: 'SecretFinder', pip: 'pip3 install secretfinder' },
            { name: 'SQLMap', apt: 'sudo apt-get install -y sqlmap', brew: 'brew install sqlmap' },
            { name: 'Subfinder', go: 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest' },
            { name: 'subjs', go: 'go install github.com/lc/subjs@latest' },
            { name: 'testssl.sh', source: 'git clone --depth 1 https://github.com/drwetter/testssl.sh.git' },
            { name: 'TruffleHog', source: 'curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh' },
            { name: 'Waybackurls', go: 'go install github.com/tomnomnom/waybackurls@latest' },
            { name: 'WHOIS Lookup', apt: 'sudo apt-get install -y whois', brew: 'brew install whois' },
            { name: 'WPScan', gem: 'gem install wpscan', notes: 'Requires Ruby.' },
    ].sort((a, b) => a.name.localeCompare(b.name));

    const utils = {
        sanitizeDomain: (url) => url ? url.trim().replace(/^(https?:\/\/)?(www\.)?/i, '').split('/')[0] : '',
        formatBytes: (bytes) => {
            if (bytes === 0) return '0 Bytes';
            const i = Math.floor(Math.log(bytes) / Math.log(1024));
            return `${parseFloat((bytes / Math.pow(1024, i)).toFixed(2))} ${['Bytes','KB','MB','GB'][i]}`;
        },
        async copyToClipboard(text, button) {
            const originalContent = button.innerHTML;
            try {
                await navigator.clipboard.writeText(text);
                button.innerHTML = `<i class="ph-fill ph-check text-green-400"></i><span>Copied!</span>`;
                button.classList.add(CSS_CLASSES.COPY_SUCCESS);
            } catch (err) {
                console.error('Clipboard copy failed:', err);
                button.innerHTML = `<i class="ph-fill ph-x text-red-400"></i><span>Failed!</span>`;
                button.classList.add(CSS_CLASSES.COPY_FAILURE);
            }
            setTimeout(() => {
                button.innerHTML = originalContent;
                button.classList.remove(CSS_CLASSES.COPY_SUCCESS, CSS_CLASSES.COPY_FAILURE);
            }, 2000);
        },
        downloadFile(content, filename, contentType = 'text/plain') {
            const blob = new Blob([content], { type: contentType });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = filename;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
        },
    };

    const ui = {
        toggleVisibility: (element, isVisible) => {
            element.classList.toggle('opacity-0', !isVisible);
            element.classList.toggle('invisible', !isVisible);
        },
        toggleDisabled: (element, isDisabled) => {
            element.disabled = isDisabled;
        },
        showStatusMessage: (message, type = 'success') => {
            clearTimeout(statusTimeout);
            elements.statusMessage.textContent = message;
            const color = type === 'error' ? ERROR_COLOR : (type === 'warning' ? WARNING_COLOR : SUCCESS_COLOR);
            elements.statusMessage.style.color = color;
            elements.statusMessage.classList.replace('opacity-0', 'opacity-100');
            statusTimeout = setTimeout(() => {
                elements.statusMessage.classList.replace('opacity-100', 'opacity-0');
            }, 4000);
        },
        updateAccordion: (itemToToggle) => {
            const isOpening = itemToToggle.button.getAttribute('aria-expanded') === 'false';
            if (isOpening) {
                itemToToggle.button.setAttribute('aria-expanded', 'true');
                itemToToggle.content.style.maxHeight = `${itemToToggle.content.scrollHeight}px`;
            } else {
                itemToToggle.button.setAttribute('aria-expanded', 'false');
                itemToToggle.content.style.maxHeight = null;
            }
        }
    };

    function updateToolsUI() {
        const isTargetSet = !!targetDomain;
        document.querySelectorAll(`a.recon-link`).forEach(link => {
            link.classList.toggle(CSS_CLASSES.DISABLED_LINK, !isTargetSet);
            link.href = isTargetSet ? link.dataset.urlTemplate.replace(/\[TARGET\]/g, encodeURIComponent(targetDomain)) : "#";
        });
        document.querySelectorAll('input.command-input').forEach(input => {
            ui.toggleDisabled(input, !isTargetSet);
            const copyButton = input.closest('.group').querySelector('.copy-btn');
            copyButton.classList.toggle(CSS_CLASSES.DISABLED_LINK, !isTargetSet);
            if(isTargetSet) {
                 input.value = input.dataset.commandTemplate.replace(/\[TARGET\]/g, targetDomain);
            } else {
                input.value = '';
            }
        });
        document.querySelectorAll('.phase-checkbox').forEach(checkbox => {
             ui.toggleDisabled(checkbox, !isTargetSet);
        });
        const controlButtons = [
            elements.generateScriptBtn, elements.viewDepsBtn, elements.selectAllBtn,
            elements.deselectAllBtn, elements.loadPassiveScanBtn, elements.loadQuickScanBtn,
            elements.loadDeepScanBtn, elements.loadWebVulnScanBtn, elements.loadFullScanBtn,
            elements.generateInstallerBtn
        ];
        controlButtons.forEach(btn => ui.toggleDisabled(btn, !isTargetSet));
    }

    function setTarget(newTarget) {
        const sanitized = utils.sanitizeDomain(newTarget);
        if (targetDomain === sanitized) return;
        targetDomain = sanitized;
        elements.urlInput.value = sanitized;
        ui.toggleVisibility(elements.clearTargetBtn, !!sanitized);
        if (sanitized) {
            ui.showStatusMessage(`Target set: ${targetDomain}`);
        } else {
            if (newTarget.trim()) ui.showStatusMessage('Please enter a valid domain', true, 'error');
            ui.toggleDisabled(elements.copyScriptBtn, true);
            ui.toggleDisabled(elements.downloadScriptBtn, true);
        }
        updateToolsUI();
    }
    
    function updateWorkflowMap(selectedSteps) {
        elements.workflowMap.innerHTML = selectedSteps.map((step, index) => `
            <div class="workflow-step" style="animation-delay: ${index * 60}ms">
               <span class="workflow-phase-number">${step.phase}</span>
               <i class="${step.icon} text-lg accent-text"></i>
               <span>${step.workflowName}</span>
            </div>
        `).join('');

        const isVisible = selectedSteps.length > 0;
        elements.workflowMapContainer.classList.toggle('hidden', !isVisible);
    }
    
    function updateGridVisibility() {
        const searchTerm = elements.searchInput.value.toLowerCase().trim();
        const activeTags = Array.from(document.querySelectorAll('.tag-filter-btn.active')).map(btn => btn.dataset.tag);
        
        ui.toggleVisibility(elements.clearSearchBtn, searchTerm.length > 0);
        document.querySelectorAll('.tool-highlight').forEach(el => el.classList.remove('tool-highlight'));

        let visibleCount = 0;
        
        document.querySelectorAll('.phase-card').forEach((card, index) => {
            const stepData = reconSteps[index];
            let phaseMatchesSearch = !searchTerm || stepData.title.toLowerCase().includes(searchTerm) || stepData.description.toLowerCase().includes(searchTerm);
            let hasVisibleTools = false;

            card.querySelectorAll('.tool-container').forEach((toolEl, toolIndex) => {
                const toolData = stepData.tools[toolIndex];
                const toolTags = toolData.tags || [];

                const matchesTags = activeTags.length === 0 || activeTags.some(t => toolTags.includes(t));
                const matchesSearch = !searchTerm || toolData.name.toLowerCase().includes(searchTerm) || toolData.description.toLowerCase().includes(searchTerm);

                if (matchesTags && matchesSearch) {
                    toolEl.style.display = '';
                    hasVisibleTools = true;
                    if (searchTerm) {
                        toolEl.classList.add('tool-highlight');
                    }
                } else {
                    toolEl.style.display = 'none';
                }
            });
            
            const isPhaseVisible = hasVisibleTools || (phaseMatchesSearch && activeTags.length === 0);
            card.style.display = isPhaseVisible ? '' : 'none';
            if (isPhaseVisible) visibleCount++;
        });
        
        elements.noResultsMessage.classList.toggle('hidden', visibleCount > 0);
    }

    function updateDependencyWarnings() {
        const activePhaseIds = new Set(
            Array.from(document.querySelectorAll('.tool-checkbox:checked')).map(cb => cb.dataset.phaseId)
        );

        reconSteps.forEach(step => {
            if (step.isResource) return;
            const warningEl = document.getElementById(`dep-warning-${step.phase}`);
            if (!warningEl) return;
            let unmetDependencies = [];
            if (step.requires && activePhaseIds.has(step.phase)) {
                unmetDependencies = step.requires.filter(reqId => !activePhaseIds.has(reqId));
            }

            if (unmetDependencies.length > 0) {
                const missingPhaseNames = unmetDependencies
                    .map(id => reconSteps.find(s => s.phase === id)?.workflowName || `Phase ${id}`)
                    .join(', ');
                warningEl.querySelector('.dep-tooltip').textContent = `Requires: ${missingPhaseNames}`;
                warningEl.classList.remove('hidden');
            } else {
                warningEl.classList.add('hidden');
            }
        });
    }

    function generateScript() {
        if (!targetDomain) return ui.showStatusMessage('Please set a target domain first', 'error');
        
        const selectedToolCheckboxes = Array.from(document.querySelectorAll('.tool-checkbox:checked'));
        if (selectedToolCheckboxes.length === 0) {
             return ui.showStatusMessage('Please select at least one tool to generate a script', 'error');
        }
        
        const selectedToolsByPhase = selectedToolCheckboxes.reduce((acc, cb) => {
            const phaseId = cb.dataset.phaseId;
            const toolName = cb.dataset.toolName;
            const commandInput = cb.closest('.tool-container').querySelector('.command-input');
            const command = commandInput ? commandInput.value : '';

            if (!acc[phaseId]) acc[phaseId] = [];
            acc[phaseId].push({ name: toolName, command: command });
            return acc;
        }, {});

        const sortedPhaseIds = Object.keys(selectedToolsByPhase).sort((a, b) => parseInt(a) - parseInt(b));
        
        const activePhases = sortedPhaseIds.map(id => reconSteps.find(step => step.phase === id)).filter(Boolean);
        updateWorkflowMap(activePhases);
        
        let finalWarning = '';
        for (const step of activePhases) {
            if (step.requires) {
                const unmet = step.requires.filter(reqId => !sortedPhaseIds.includes(reqId));
                if (unmet.length > 0) {
                    finalWarning = `Warning: Phase ${step.phase} requires input from Phase ${unmet.join(', ')}. Script may fail.`;
                    break; 
                }
            }
        }
       
        let functionDefinitions = '';
        let functionCalls = '';
        const selectedToolNames = [];

        sortedPhaseIds.forEach(phaseId => {
            const step = reconSteps.find(s => s.phase === phaseId);
            if (!step) return;

            const functionName = `run_phase_${phaseId}_${step.workflowName.replace(/\s/g, '_').toLowerCase()}`;
            functionCalls += `    ${functionName}\n`;
            
            functionDefinitions += `
# --- Phase ${phaseId}: ${step.title} ---
`;
            functionDefinitions += `${functionName}() {
`;
            functionDefinitions += `	log_info "Phase ${phaseId}: Running ${step.workflowName}..."
`;

            const toolsInPhase = selectedToolsByPhase[phaseId];
            toolsInPhase.forEach(tool => {
                selectedToolNames.push(tool.name);
                functionDefinitions += `	log_sub_info "Running ${tool.name}..."
	${tool.command}
`;
            });

            if (phaseId === '02') {
                functionDefinitions += `	log_sub_info "Combining and sorting unique subdomains..."
	sort -u $RECON_DIR/subdomains/raw.txt > $RECON_DIR/subdomains/final.txt
	rm $RECON_DIR/subdomains/raw.txt 2>/dev/null
	log_sub_info "Found $(wc -l < $RECON_DIR/subdomains/final.txt) unique subdomains."
`;
            }
            if (phaseId === '06') {
                 functionDefinitions += `	log_sub_info "Combining and sorting unique URLs..."
	sort -u $RECON_DIR/urls/raw.txt > $RECON_DIR/urls/final.txt
	rm $RECON_DIR/urls/raw.txt 2>/dev/null
	log_sub_info "Found $(wc -l < $RECON_DIR/urls/final.txt) unique URLs."
`;
            }
            functionDefinitions += `}
`;
        });

        const dirList = "info subdomains hosts urls scans screenshots scans/nmap scans/sqlmap scans/testssl";
        
        generatedScriptContent = `#!/bin/bash
# --- BountyScope Automation Script ---
# Target: ${targetDomain}
# Generated: ${new Date().toISOString()}
# Selected Tools: ${selectedToolNames.length}
#
# Usage: ./bountyscope_${targetDomain}.sh
# -----------------------------------------

set -eo pipefail

# --- Configuration & Setup ---
TARGET="${targetDomain}"
RECON_DIR="$TARGET/recon"

# --- Logging Helpers ---
log_info() { echo -e "\n[+] \\e[1;36m$1\\e[0m"; }
log_sub_info() { echo -e "  [i] \\e[0;34m$1\\e[0m"; }
log_warn() { echo -e "  [!] \\e[1;33m$1\\e[0m"; }

# --- Phase Functions ---
${functionDefinitions}

# --- Main Execution ---
main() {
    log_info "Starting reconnaissance workflow for: $TARGET"
    
    log_sub_info "Setting up directory structure..."
    mkdir -p "$TARGET"
    for dir in ${dirList}; do mkdir -p "$RECON_DIR/$dir"; done

${functionCalls}
    log_info "\\e[1;32mReconnaissance workflow finished for $TARGET!\\e[0m"
    echo -e "[+] All results are stored in the '$TARGET/' directory."
}

main "$@"
`;
        
        elements.generatedScript.textContent = generatedScriptContent;
        elements.scriptContainer.classList.remove('hidden');
        elements.scriptFilename.textContent = `bountyscope_${targetDomain}.sh`;
        elements.scriptStats.textContent = `${generatedScriptContent.split('\n').length} lines, ${utils.formatBytes(new Blob([generatedScriptContent]).size)}`;
        ui.toggleDisabled(elements.copyScriptBtn, false);
        ui.toggleDisabled(elements.downloadScriptBtn, false);
        
        if(finalWarning) {
            ui.showStatusMessage(finalWarning, 'warning');
        } else {
            ui.showStatusMessage('Custom automation script generated successfully!');
        }
        
        elements.scriptSection.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }

    function resetAll() {
        setTarget('');
        elements.urlInput.value = '';

        document.querySelectorAll('.phase-checkbox:checked').forEach(cb => cb.checked = false);
        document.querySelectorAll('.phase-select-all-checkbox').forEach(cb => cb.indeterminate = false);
        updateDependencyWarnings();

        elements.scriptContainer.classList.add('hidden');
        elements.workflowMapContainer.classList.add('hidden');
        elements.depsContainer.classList.add('hidden');
        
        generatedScriptContent = '';
        ui.toggleDisabled(elements.copyScriptBtn, true);
        ui.toggleDisabled(elements.downloadScriptBtn, true);

        elements.searchInput.value = '';
        document.querySelectorAll('.tag-filter-btn.active').forEach(btn => btn.classList.remove('active'));
        updateGridVisibility();

        toggleAllAccordions(false);
        
        ui.showStatusMessage('Workflow has been reset.');
        elements.targetSection.scrollIntoView({ behavior: 'smooth' });
    }

    function toggleAllAccordions(expand) {
        document.querySelectorAll('.accordion-button').forEach(button => {
            const content = button.nextElementSibling;
            const isCurrentlyExpanded = button.getAttribute('aria-expanded') === 'true';

            if (expand && !isCurrentlyExpanded) {
                ui.updateAccordion({ button, content });
            } else if (!expand && isCurrentlyExpanded) {
                ui.updateAccordion({ button, content });
            }
        });
    }
    
    function loadPreset(phaseIds, presetName) {
        if (!targetDomain) {
            ui.showStatusMessage('Set a target before loading a workflow', 'warning');
            return;
        }
        document.querySelectorAll('.tool-checkbox:not(:disabled)').forEach(cb => cb.checked = false);
        
        phaseIds.forEach(phaseId => {
            const toolCheckboxes = document.querySelectorAll(`.tool-checkbox[data-phase-id="${phaseId}"]`);
            toolCheckboxes.forEach(checkbox => {
                 if(checkbox) checkbox.checked = true;
            });
        });
        
        document.querySelectorAll('.phase-card').forEach(card => updatePhaseCheckboxState(card));
        updateDependencyWarnings();
        ui.showStatusMessage(`${presetName} workflow loaded successfully!`);
    }
    
    function updatePhaseCheckboxState(phaseCard) {
        const phaseCheckbox = phaseCard.querySelector('.phase-select-all-checkbox');
        if (!phaseCheckbox) return;

        const toolCheckboxes = phaseCard.querySelectorAll('.tool-checkbox');
        if (toolCheckboxes.length === 0) return;

        const total = toolCheckboxes.length;
        const checkedCount = Array.from(toolCheckboxes).filter(cb => cb.checked).length;

        if (checkedCount === 0) {
            phaseCheckbox.checked = false;
            phaseCheckbox.indeterminate = false;
        } else if (checkedCount === total) {
            phaseCheckbox.checked = true;
            phaseCheckbox.indeterminate = false;
        } else {
            phaseCheckbox.checked = false;
            phaseCheckbox.indeterminate = true;
        }
    }

    async function initialize() {
        if (Object.values(elements).some(el => !el)) {
            console.error('Initialization failed: A required DOM element is missing.');
            return;
        }

        reconSteps = await fetchData();
        renderFramework(reconSteps, elements.reconGrid);
        renderTagFilters(reconSteps, elements.tagFilterContainer);
        updateToolsUI();

        elements.reconGrid.addEventListener('click', (e) => {
            const button = e.target.closest('.accordion-button');
            if (button) {
                 ui.updateAccordion({ button, content: button.nextElementSibling });
            }
            const copyButton = e.target.closest('.copy-btn');
            if (copyButton && !copyButton.classList.contains(CSS_CLASSES.DISABLED_LINK)) {
                e.preventDefault(); e.stopPropagation();
                const inputElement = copyButton.closest('.group')?.querySelector('input.command-input');
                if (inputElement && inputElement.value.trim() !== '') {
                    utils.copyToClipboard(inputElement.value, copyButton);
                }
            }
        });

        elements.reconGrid.addEventListener('change', (e) => {
            const target = e.target;
            if(target.classList.contains('phase-select-all-checkbox')) {
                const phaseId = target.dataset.phaseId;
                const toolCheckboxes = target.closest('.phase-card').querySelectorAll(`.tool-checkbox[data-phase-id="${phaseId}"]`);
                toolCheckboxes.forEach(cb => cb.checked = target.checked);
            } else if (target.classList.contains('tool-checkbox')) {
                updatePhaseCheckboxState(target.closest('.phase-card'));
            }
            updateDependencyWarnings();
        });

        elements.setTargetBtn.addEventListener('click', () => setTarget(elements.urlInput.value));
        elements.urlInput.addEventListener('input', () => ui.toggleVisibility(elements.clearTargetBtn, elements.urlInput.value.trim().length > 0));
        elements.urlInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); setTarget(elements.urlInput.value); } });
        elements.clearTargetBtn.addEventListener('click', () => setTarget(''));
        
        elements.generateScriptBtn.addEventListener('click', generateScript);
        elements.copyScriptBtn.addEventListener('click', () => { if (generatedScriptContent) utils.copyToClipboard(generatedScriptContent, elements.copyScriptBtn); });
        elements.downloadScriptBtn.addEventListener('click', () => { if (generatedScriptContent && targetDomain) utils.downloadFile(generatedScriptContent, `bountyscope_${targetDomain}.sh`, 'application/x-sh'); });
        
        elements.selectAllBtn.addEventListener('click', () => {
            document.querySelectorAll('.tool-checkbox:not(:disabled)').forEach(cb => cb.checked = true);
            document.querySelectorAll('.phase-card').forEach(card => updatePhaseCheckboxState(card));
            updateDependencyWarnings();
        });
        elements.deselectAllBtn.addEventListener('click', () => {
            document.querySelectorAll('.tool-checkbox:not(:disabled)').forEach(cb => cb.checked = false);
            document.querySelectorAll('.phase-card').forEach(card => updatePhaseCheckboxState(card));
            updateDependencyWarnings();
        });
        
        elements.loadPassiveScanBtn.addEventListener('click', () => loadPreset(PRESETS.PASSIVE, 'Passive Scan'));
        elements.loadQuickScanBtn.addEventListener('click', () => loadPreset(PRESETS.QUICK, 'Quick Scan'));
        elements.loadDeepScanBtn.addEventListener('click', () => loadPreset(PRESETS.DEEP, 'Deep Scan'));
        elements.loadWebVulnScanBtn.addEventListener('click', () => loadPreset(PRESETS.WEB_VULN, 'Web Vuln Scan'));
        elements.loadFullScanBtn.addEventListener('click', () => loadPreset(PRESETS.FULL, 'Full Scan'));
        
        elements.expandAllBtn.addEventListener('click', () => toggleAllAccordions(true));
        elements.collapseAllBtn.addEventListener('click', () => toggleAllAccordions(false));

        elements.viewDepsBtn.addEventListener('click', () => {
            const isHidden = elements.depsContainer.classList.contains('hidden');
            elements.depsContainer.classList.toggle('hidden', !isHidden);
            if (isHidden) {
                elements.depsContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            }
        });
        
        elements.generateInstallerBtn.addEventListener('click', generateInstallerScript);
        elements.searchInput.addEventListener('input', updateGridVisibility);
        elements.clearSearchBtn.addEventListener('click', () => { elements.searchInput.value = ''; updateGridVisibility(); });
        elements.tagFilterContainer.addEventListener('click', (e) => {
            if (e.target.classList.contains('tag-filter-btn')) {
                e.target.classList.toggle('active');
                updateGridVisibility();
            }
        });
        elements.resetAllBtn.addEventListener('click', resetAll);
        elements.copyDepsBtn.addEventListener('click', () => { if(generatedInstallerContent) utils.copyToClipboard(generatedInstallerContent, elements.copyDepsBtn)});
    }

    function generateInstallerScript() {
        const selectedToolNames = new Set(Array.from(document.querySelectorAll('.tool-checkbox:checked')).map(cb => cb.dataset.toolName));
        if (selectedToolNames.size === 0) {
            ui.showStatusMessage('Select at least one tool to generate an installer script', 'warning');
            elements.depsList.innerHTML = `<p class="text-neutral-400 font-mono">Select tools and click \"Generate Installer\" to create a dependency installation script.</p>`;
            elements.copyDepsBtn.classList.add('hidden');
            return;
        }

        const requiredTools = TOOL_INSTALL_COMMANDS.filter(tool => selectedToolNames.has(tool.name));
        
        const installers = { apt: [], brew: [], go: [], pip: [], gem: [], source: [] };

        requiredTools.forEach(tool => {
            if (tool.apt) installers.apt.push(tool.apt);
            if (tool.brew) installers.brew.push(tool.brew);
            if (tool.go) installers.go.push(tool.go);
            if (tool.pip) installers.pip.push(tool.pip);
            if (tool.gem) installers.gem.push(tool.gem);
            if (tool.source) installers.source.push(tool.source);
        });

        let script = `#!/bin/bash
# --- BountyScope Dependency Installer Script ---
# Generated: ${new Date().toISOString()}
# This script will attempt to install dependencies for the selected tools.
# Run with caution. Review the commands before executing. Some steps may require manual intervention.
set -e

# --- Helper function ---
command_exists() {
    command -v "$1" &> /dev/null
}

echo "--- Starting Dependency Installation ---" 

`;
        const addSection = (title, commands, check) => {
            if (commands.length === 0) return;
            script += `
# --- ${title} ---
`;
            if (check) {
                script += `if command_exists ${check}; then
    echo ">>> Installing ${title}..."
`;
                commands.forEach(cmd => { script += `    ${cmd}\n`; });
                script += `else
    echo "[WARNING] ${check} is not installed. Skipping ${title}."
fi
`;
            } else {
                 commands.forEach(cmd => { script += `${cmd}\n`; });
            } 
        };

        addSection('Go Tools', installers.go, 'go');
        addSection('Python (Pip) Packages', installers.pip, 'pip3');
        addSection('System Packages (Debian/Ubuntu)', installers.apt, 'apt-get');
        addSection('System Packages (macOS/Homebrew)', installers.brew, 'brew');
        addSection('Ruby (Gem) Packages', installers.gem, 'gem');

        if (installers.source.length > 0) {
            script += `
# --- Manual/Source Installation ---
echo "[INFO] The following tools require manual installation. The commands are provided for reference:"
`;
            installers.source.forEach(cmd => {
                script += `# --- For ${requiredTools.find(t=>t.source === cmd).name} ---
# ${cmd}\n
`;
            });
        }


        script += '\necho "--- Installation script finished ---"';
        
        generatedInstallerContent = script;
        elements.depsList.innerHTML = `<pre class="font-mono text-sm text-[#00d4ff] leading-relaxed"><code>${script}</code></pre>`;
        elements.copyDepsBtn.classList.remove('hidden');
        ui.showStatusMessage('Installer script generated successfully!');
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize);
    } else {
        initialize();
    }
})();
