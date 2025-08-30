(() => {
    'use strict';
    // --- SECTION: Constants & Configuration ---
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

    // --- SECTION: DOM Elements ---
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
    
    // --- SECTION: Application State ---
    let targetDomain = '';
    let statusTimeout;
    let generatedScriptContent = '';
    let generatedInstallerContent = '';

    // --- SECTION: Data (with curated tags) ---
    const reconSteps = [
        { phase: "01", title: "Domain Intelligence & Technology Profiling", workflowName: "Domain Intel", description: "Establish baseline intelligence about the target domain including registration details, DNS infrastructure, and underlying technology stack.", icon: "ph-detective", tools: [ { name: "WHOIS Lookup", type: "cli", command: "whois [TARGET] | tee $RECON_DIR/info/whois.txt", description: "Domain registration details", tags: ["OSINT"], sourceUrl: "https://www.icann.org/whois" }, { name: "Dig DNS Records", type: "cli", command: "dig +nocmd [TARGET] any +multiline +noall +answer | tee $RECON_DIR/info/dns.txt", description: "Complete DNS record enumeration", tags: ["Discovery"] }, { name: "DNSRecon", type: "cli", command: "dnsrecon -d [TARGET] -t std --xml $RECON_DIR/info/dnsrecon.xml", description: "Advanced DNS reconnaissance", tags: ["Discovery", "Active"], sourceUrl: "https://github.com/darkoperator/dnsrecon" }, { name: "Wappalyzer", type: "gui", url: "https://www.wappalyzer.com/lookup/[TARGET]", description: "Technology stack identification", tags: ["Web"], sourceUrl: "https://www.wappalyzer.com/" }, { name: "BuiltWith", type: "gui", url: "https://builtwith.com/?[TARGET]", description: "Comprehensive technology profiler", tags: ["Web"], sourceUrl: "https://builtwith.com/" } ] },
        { phase: "02", title: "Comprehensive Subdomain Discovery", workflowName: "Subdomain Discovery", description: "Employ multiple passive and active techniques to discover all possible subdomains, expanding the attack surface.", icon: "ph-tree-structure", tools: [ { name: "Subfinder", type: "cli", command: "subfinder -d [TARGET] -all -recursive -o- >> $RECON_DIR/subdomains/raw.txt", description: "Multi-source passive subdomain discovery", tags: ["Discovery", "Passive"], sourceUrl: "https://github.com/projectdiscovery/subfinder" }, { name: "Assetfinder", type: "cli", command: "assetfinder --subs-only [TARGET] >> $RECON_DIR/subdomains/raw.txt", description: "Fast subdomain and asset discovery", tags: ["Discovery", "Passive"], sourceUrl: "https://github.com/tomnomnom/assetfinder" }, { name: "Amass Enum", type: "cli", command: "amass enum -passive -d [TARGET] -config config.ini -o- >> $RECON_DIR/subdomains/raw.txt", description: "In-depth subdomain enumeration", tags: ["Discovery", "Active"], sourceUrl: "https://github.com/owasp-amass/amass" }, { name: "Findomain", type: "cli", command: "findomain -t [TARGET] -q >> $RECON_DIR/subdomains/raw.txt", description: "Cross-platform subdomain enumerator", tags: ["Discovery", "Passive"], sourceUrl: "https://github.com/findomain/findomain" }, { name: "crt.sh", type: "gui", url: "https://crt.sh/?q=%25.[TARGET]", description: "Certificate transparency logs", tags: ["Discovery", "Passive"], sourceUrl: "https://crt.sh" }, { name: "Chaos DB", type: "cli", command: "chaos -d [TARGET] -o- >> $RECON_DIR/subdomains/raw.txt", description: "ProjectDiscovery's subdomain dataset", tags: ["Discovery", "Passive"], sourceUrl: "https://github.com/projectdiscovery/chaos-client" } ] },
        { phase: "03", title: "DNS Resolution & Live Service Detection", workflowName: "Live Host Probing", requires: ['02'], description: "Validate discovered subdomains and probe for active web services, filtering out dead hosts and identifying accessible endpoints.", icon: "ph-broadcast", tools: [ { name: "dnsx Resolution", type: "cli", command: "cat $RECON_DIR/subdomains/final.txt | dnsx -resp -silent -o $RECON_DIR/hosts/resolved.txt", description: "Fast DNS resolver", tags: ["Discovery", "Active"], sourceUrl: "https://github.com/projectdiscovery/dnsx" }, { name: "httpx Probe", type: "cli", command: "cat $RECON_DIR/subdomains/final.txt | httpx -title -tech-detect -status-code -probe -fr -o $RECON_DIR/hosts/live.txt", description: "Advanced HTTP toolkit for probing", tags: ["Web", "Active"], sourceUrl: "https://github.com/projectdiscovery/httpx" }, { name: "Httprobe", type: "cli", command: "cat $RECON_DIR/subdomains/final.txt | httprobe -c 50 > $RECON_DIR/hosts/live_alt.txt", description: "Simple HTTP/HTTPS prober", tags: ["Web", "Active"], sourceUrl: "https://github.com/tomnomnom/httprobe" } ] },
        { phase: "04", title: "Visual Reconnaissance & Screenshot Analysis", workflowName: "Visual Recon", requires: ['03'], description: "Capture visual screenshots of live web applications to quickly identify interesting interfaces and visual anomalies.", icon: "ph-camera-plus", tools: [ { name: "Gowitness", type: "cli", command: "gowitness file -f $RECON_DIR/hosts/live.txt -P $RECON_DIR/screenshots --delay 3 --timeout 15", description: "Fast web screenshot utility", tags: ["Web"], sourceUrl: "https://github.com/sensepost/gowitness" }, { name: "Aquatone", type: "cli", command: "cat $RECON_DIR/hosts/live.txt | aquatone -out $RECON_DIR/aquatone", description: "Visual inspection with detailed reporting", tags: ["Web"], sourceUrl: "https://github.com/michenriksen/aquatone" } ] },
        { phase: "05", title: "Network Scanning & Service Enumeration", workflowName: "Port Scanning", requires: ['03'], description: "Perform comprehensive port scans across all discovered hosts, identify running services, and map the network topology.", icon: "ph-radar", tools: [ { name: "Naabu Fast Scan", type: "cli", command: "naabu -list $RECON_DIR/hosts/live.txt -top-ports 1000 -silent -o $RECON_DIR/scans/naabu_ports.txt", description: "Ultra-fast port scanner", tags: ["Scanning"], sourceUrl: "https://github.com/projectdiscovery/naabu" }, { name: "Nmap Service Detection", type: "cli", command: "nmap -sV -sC -O --script=default,discovery,vuln -iL $RECON_DIR/hosts/live.txt -oA $RECON_DIR/scans/nmap/nmap_detailed", description: "Comprehensive service and vulnerability scanning", tags: ["Scanning", "Vulnerability"], sourceUrl: "https://nmap.org/" }, { name: "RustScan", type: "cli", command: "rustscan -a [TARGET] -r 1-65535 -- -A -sC", description: "Modern fast port scanner", tags: ["Scanning"], sourceUrl: "https://github.com/RustScan/RustScan" }, { name: "Shodan", type: "gui", url: "https://www.shodan.io/search?query=hostname:[TARGET]", description: "Internet device search engine", tags: ["OSINT", "Scanning"], sourceUrl: "https://shodan.io" } ] },
        { phase: "06", title: "Web Crawling & URL Harvesting", workflowName: "URL Harvesting", requires: ['03'], description: "Systematically crawl discovered web applications and harvest URLs from multiple sources.", icon: "ph-spider", tools: [ { name: "Katana Crawler", type: "cli", command: "katana -list $RECON_DIR/hosts/live.txt -d 5 -jc -kf all -o- >> $RECON_DIR/urls/raw.txt", description: "Next-generation crawling framework", tags: ["Web", "Discovery"], sourceUrl: "https://github.com/projectdiscovery/katana" }, { name: "Gospider", type: "cli", command: "gospider -S $RECON_DIR/hosts/live.txt -c 10 -d 5 -t 20 -q -o- | grep -oE 'http.*' >> $RECON_DIR/urls/raw.txt", description: "Fast web spider with filtering", tags: ["Web", "Discovery"], sourceUrl: "https://github.com/jaeles-project/gospider" }, { name: "Waybackurls", type: "cli", command: "cat $RECON_DIR/hosts/live.txt | waybackurls >> $RECON_DIR/urls/raw.txt", description: "Wayback Machine URL fetcher", tags: ["OSINT", "Passive"], sourceUrl: "https://github.com/tomnomnom/waybackurls" }, { name: "Gau (Get All URLs)", type: "cli", command: "echo [TARGET] | gau --subs >> $RECON_DIR/urls/raw.txt", description: "Fetch URLs from multiple sources", tags: ["OSINT", "Passive"], sourceUrl: "https://github.com/lc/gau" } ] },
        { phase: "07", title: "Content Discovery & Directory Fuzzing", workflowName: "Content Fuzzing", requires: ['03'], description: "Systematically discover hidden directories, files, and other concealed content using wordlist-based fuzzing techniques.", icon: "ph-folder-open", tools: [ { name: "ffuf Fuzzer", type: "cli", command: "ffuf -w /opt/SecLists/Discovery/Web-Content/common.txt -u https://[TARGET]/FUZZ -mc 200,301,302 -o $RECON_DIR/scans/ffuf_root.json", description: "Fast web fuzzer with smart filtering", tags: ["Fuzzing"], sourceUrl: "https://github.com/ffuf/ffuf" }, { name: "Gobuster Directory", type: "cli", command: "gobuster dir -u https://[TARGET] -w /opt/SecLists/Discovery/Web-Content/common.txt -o $RECON_DIR/scans/gobuster_root.txt", description: "Directory and file brute-forcer", tags: ["Fuzzing"], sourceUrl: "https://github.com/OJ/gobuster" } ] },
        { phase: "08", title: "JavaScript Analysis & API Discovery", workflowName: "JS & API Analysis", requires: ['06'], description: "Extract sensitive information and discover hidden API endpoints from client-side JavaScript files.", icon: "ph-code", tools: [ { name: "subjs", type: "cli", command: "cat $RECON_DIR/urls/final.txt | grep -iE '\\\\.js($|\\\\?)' | subjs | anew $RECON_DIR/urls/js_files.txt", description: "JavaScript file extractor", tags: ["Web"], sourceUrl: "https://github.com/lc/subjs" }, { name: "LinkFinder", type: "cli", command: "cat $RECON_DIR/urls/js_files.txt | xargs -I % linkfinder -i % -o cli | anew $RECON_DIR/urls/linkfinder.txt", description: "Discover endpoints in JS files", tags: ["Web", "Discovery"], sourceUrl: "https://github.com/GerbenJavado/LinkFinder" }, { name: "SecretFinder", type: "cli", command: "cat $RECON_DIR/urls/js_files.txt | xargs -I % secretfinder -i % -o cli | anew $RECON_DIR/scans/secrets.txt", description: "Find secrets in JavaScript", tags: ["Secrets"], sourceUrl: "https://github.com/m4ll0k/SecretFinder" } ] },
        { phase: "09", title: "Parameter Discovery & Fuzzing", workflowName: "Parameter Hunting", requires: ['06'], description: "Identify hidden parameters, analyze parameter behavior, and discover potential injection points.", icon: "ph-list-bullets", tools: [ { name: "ParamSpider", type: "cli", command: "paramspider -d [TARGET] --exclude woff,css,png,svg,jpg -q -o $RECON_DIR/urls/paramspider", description: "Parameter discovery from web archives", tags: ["Fuzzing", "Discovery"], sourceUrl: "https://github.com/devanshbatham/ParamSpider" }, { name: "Arjun", type: "cli", command: "arjun -u https://[TARGET]/ -oT $RECON_DIR/urls/arjun_root.txt", description: "HTTP parameter discovery suite", tags: ["Fuzzing"], sourceUrl: "https://github.com/s0md3v/Arjun" }, { name: "GF Patterns", type: "cli", command: "cat $RECON_DIR/urls/final.txt | gf xss | anew $RECON_DIR/urls/gf_xss.txt", description: "Pattern-based URL filtering", tags: ["Vulnerability"], sourceUrl: "https://github.com/tomnomnom/gf" } ] },
        { phase: "10", title: "Cloud Asset & Storage Discovery", workflowName: "Cloud Discovery", description: "Enumerate cloud infrastructure including S3 buckets, Azure blobs, GCP storage, and other misconfigured services.", icon: "ph-cloud", tools: [ { name: "S3Scanner", type: "cli", command: "# Example: s3scanner -bucket-file buckets.txt -dump", description: "AWS S3 bucket scanner", tags: ["Cloud"], sourceUrl: "https://github.com/sa7mon/S3Scanner" }, { name: "Cloud_enum", type: "cli", command: "cloud_enum -k [TARGET] -l $RECON_DIR/scans/cloud_enum.txt", description: "Multi-cloud asset discovery", tags: ["Cloud"], sourceUrl: "https://github.com/initstring/cloud_enum" } ] },
        { phase: "11", title: "Git Repository & Source Code Analysis", workflowName: "Source Code Secrets", description: "Search for exposed repositories, leaked credentials, API keys, and sensitive information in public code repositories.", icon: "ph-git-branch", tools: [ { name: "TruffleHog", type: "cli", command: "trufflehog github --org=[TARGET] --json > $RECON_DIR/scans/trufflehog.json", description: "Find secrets in git repositories", tags: ["Secrets", "OSINT"], sourceUrl: "https://github.com/trufflesecurity/trufflehog" }, { name: "GitLeaks", type: "cli", command: "gitleaks detect --source . -r $RECON_DIR/scans/gitleaks.json", description: "Detect secrets in git repos", tags: ["Secrets"], sourceUrl: "https://github.com/gitleaks/gitleaks" } ] },
        { phase: "12", title: "Vulnerability Scanning & Template-Based Testing", workflowName: "Vulnerability Scanning", requires: ['03'], description: "Execute scans using template-based tools to find common security issues, misconfigurations, and known CVEs.", icon: "ph-shield-warning", tools: [ { name: "Nuclei Templates", type: "cli", command: "nuclei -l $RECON_DIR/hosts/live.txt -t ~/nuclei-templates/ -s critical,high,medium -o $RECON_DIR/scans/nuclei.txt", description: "Template-based vulnerability scanner", tags: ["Vulnerability", "Scanning"], sourceUrl: "https://github.com/projectdiscovery/nuclei" }, { name: "Nuclei CVE Scan", type: "cli", command: "nuclei -l $RECON_DIR/hosts/live.txt -t ~/nuclei-templates/cves/ -s critical,high -o $RECON_DIR/scans/nuclei_cves.txt", description: "CVE-specific vulnerability detection", tags: ["Vulnerability", "Scanning"], sourceUrl: "https://github.com/projectdiscovery/nuclei" }, { name: "testssl.sh", type: "cli", command: "testssl.sh --parallel --html --outdir $RECON_DIR/scans/testssl/ [TARGET]", description: "Comprehensive SSL/TLS tester", tags: ["Vulnerability", "Scanning"], sourceUrl: "https://github.com/drwetter/testssl.sh" } ] },
        { phase: "13", title: "Specialized Vulnerability Hunting", workflowName: "Exploit Hunting", requires: ['09'], description: "Deploy specialized tools targeting specific vulnerability classes like XSS and SQLi.", icon: "ph-bug", tools: [ { name: "Dalfox XSS", type: "cli", command: "dalfox file $RECON_DIR/urls/gf_xss.txt --silence -o $RECON_DIR/scans/dalfox.txt", description: "Advanced XSS scanner and analyzer", tags: ["Vulnerability", "Web"], sourceUrl: "https://github.com/hahwul/dalfox" }, { name: "SQLMap", type: "cli", command: "sqlmap -m $RECON_DIR/urls/gf_sqli.txt --batch --level=5 --risk=3 --output-dir=$RECON_DIR/scans/sqlmap/ -v 1", description: "Automatic SQL injection tester", tags: ["Vulnerability", "Web"], sourceUrl: "http://sqlmap.org/" } ] },
        { phase: "14", title: "CMS & Framework Security Assessment", workflowName: "CMS Scanning", requires: ['03'], description: "Identify and assess Content Management Systems for known vulnerabilities and misconfigurations.", icon: "ph-gear-six", tools: [ { name: "WPScan", type: "cli", command: "wpscan --url https://[TARGET] --enumerate ap,at,u -o $RECON_DIR/scans/wpscan.json -f json", description: "WordPress vulnerability scanner", tags: ["Vulnerability", "Web"], sourceUrl: "https://wpscan.com/" }, { name: "Nikto Web Scanner", type: "cli", command: "nikto -h https://[TARGET] -ssl -output $RECON_DIR/scans/nikto.txt", description: "Web server vulnerability scanner", tags: ["Web", "Vulnerability", "Scanning"], sourceUrl: "https://cirt.net/Nikto2" } ] },
        { phase: "15", title: "Essential Resources & Wordlists", workflowName: "Resource Library", description: "Curated collection of essential wordlists and payloads for comprehensive security testing.", icon: "ph-books", isResource: true, tools: [ { name: "SecLists", type: "gui", url: "https://github.com/danielmiessler/SecLists", noTarget: true, description: "Security tester's companion wordlist collection", tags: ["Fuzzing"], sourceUrl: "https://github.com/danielmiessler/SecLists" }, { name: "PayloadsAllTheThings", type: "gui", url: "https://github.com/swisskyrepo/PayloadsAllTheThings", noTarget: true, description: "Web application security payload repository", tags: ["Vulnerability"], sourceUrl: "https://github.com/swisskyrepo/PayloadsAllTheThings" } ] }
    ];

    // --- SECTION: Utility Functions ---
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

    // --- SECTION: UI Manipulation ---
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

    // --- SECTION: HTML Generation ---
    const createCliToolHtml = (tool, step) => `
        <div class="tool-container bg-neutral-900 border border-neutral-800 p-4 rounded-lg group transition-all duration-300 hover:border-neutral-700">
            <div class="flex justify-between items-start mb-3">
                <div class="flex items-start gap-4 flex-1">
                    <label class="flex items-center cursor-pointer pt-1" onclick="event.stopPropagation()">
                        <input type="checkbox" data-phase-id="${step.phase}" data-tool-name="${tool.name}" class="phase-checkbox tool-checkbox" disabled>
                    </label>
                    <div class="w-10 h-10 rounded-md bg-neutral-800 flex items-center justify-center flex-shrink-0"><i class="ph-bold ph-terminal text-neutral-400 text-xl"></i></div>
                    <div class="flex-1">
                        <p class="text-white font-bold flex items-center gap-2">
                            <span>${tool.name}</span>
                            ${tool.sourceUrl ? `<a href="${tool.sourceUrl}" target="_blank" rel="noopener noreferrer" class="text-neutral-500 hover:text-white transition-colors" title="Visit tool homepage" onclick="event.stopPropagation()"><i class="ph-bold ph-info text-sm"></i></a>` : ''}
                        </p>
                        <p class="text-neutral-400 text-sm">${tool.description}</p>
                    </div>
                </div>
                <button class="copy-btn ${CSS_CLASSES.DISABLED_LINK} bg-neutral-800 hover:bg-neutral-700 text-neutral-300 text-xs font-medium py-2 px-3 rounded-md flex items-center gap-2 transition-colors active:scale-95 ml-2" aria-label="Copy ${tool.name} command"><i class="ph-bold ph-copy text-sm"></i><span>Copy</span></button>
            </div>
            <div class="bg-black rounded-md ml-10">
                <input type="text"
                    class="command-input w-full bg-transparent p-3 text-[#00d4ff] text-sm font-mono leading-relaxed border-0 focus:ring-0"
                    data-command-template="${tool.command}"
                    placeholder="Set target to see command..."
                    disabled>
            </div>
        </div>`;

    const createGuiToolHtml = (tool) => {
        const linkHref = tool.noTarget ? `href="${tool.url}"` : `href="#" data-url-template="${tool.url}"`;
        const linkClass = tool.noTarget ? 'recon-link-no-target' : `recon-link ${CSS_CLASSES.DISABLED_LINK}`;
        return `
            <a ${linkHref} target="_blank" rel="noopener noreferrer" class="tool-container ${linkClass} group bg-neutral-900 border border-neutral-800 p-4 rounded-lg flex items-center justify-between transition-all duration-300 hover:border-neutral-700 hover:bg-neutral-800/50">
                <div class="flex items-center gap-4">
                    <div class="w-10 h-10 rounded-md bg-neutral-800 flex items-center justify-center flex-shrink-0"><i class="ph-bold ph-arrow-square-out text-neutral-400 text-xl"></i></div>
                    <div>
                       <h4 class="font-bold text-white group-hover:accent-text transition-colors flex items-center gap-2">
                            <span>${tool.name}</span>
                            ${tool.sourceUrl ? `<a href="${tool.sourceUrl}" target="_blank" rel="noopener noreferrer" class="text-neutral-500 hover:text-white transition-colors" title="Visit tool homepage" onclick="event.stopPropagation()"><i class="ph-bold ph-info text-sm"></i></a>` : ''}
                       </h4>
                       <p class="text-neutral-400 text-sm">${tool.description}</p>
                    </div>
                </div>
                <i class="ph-bold ph-arrow-right text-xl text-neutral-500 group-hover:text-white group-hover:translate-x-1 transition-all"></i>
            </a>`;
    };

    const renderFramework = () => {
        const fragment = document.createDocumentFragment();
        reconSteps.forEach((step, index) => {
            const phaseCard = document.createElement('div');
            phaseCard.className = 'phase-card themed-container themed-container-hover rounded-xl transition-all duration-300 animate-fade-in';
            phaseCard.style.animationDelay = `${index * 0.05}s`;
            phaseCard.dataset.phaseId = step.phase; // Add data attribute for filtering
            
            const allTags = step.tools.flatMap(tool => tool.tags || []).join(' ');
            phaseCard.dataset.tags = allTags;

            const toolsHtml = step.tools.map(tool => {
                const toolContainer = document.createElement('div');
                toolContainer.innerHTML = tool.type === 'gui' ? createGuiToolHtml(tool) : createCliToolHtml(tool, step);
                const firstChild = toolContainer.firstElementChild;
                firstChild.dataset.tags = (tool.tags || []).join(' '); // Add tags to each tool container
                return firstChild.outerHTML;
            }).join('');
            

            const checkboxHtml = step.isResource 
                ? `<div class="flex items-center justify-center w-10 h-10 pt-1"><i class="ph-bold ph-books text-neutral-500 text-2xl"></i></div>`
                : `<label class="flex items-center cursor-pointer pt-1" onclick="event.stopPropagation()" title="Select all tools in this phase">
                     <input type="checkbox" data-phase-id="${step.phase}" class="phase-checkbox phase-select-all-checkbox" disabled>
                   </label>`;
            
            phaseCard.innerHTML = `
                <button class="accordion-button w-full flex justify-between items-start p-5 text-left group cursor-pointer" aria-expanded="false">
                    <div class="flex items-start gap-4">
                        ${checkboxHtml}
                        <div>
                            <h3 class="text-xl font-bold text-white flex items-center gap-3">
                                <i class="${step.icon} text-2xl accent-text"></i>
                                <span>${step.title}</span>
                                <div id="dep-warning-${step.phase}" class="dep-warning hidden">
                                    <i class="ph-fill ph-warning-circle text-2xl" style="color: var(--warning-color);"></i>
                                    <span class="dep-tooltip"></span>
                                </div>
                            </h3>
                            <p class="text-neutral-400 text-sm mt-2">${step.description}</p>
                        </div>
                    </div>
                    <div class="flex items-center gap-4 flex-shrink-0 pl-4">
                         <span class="bg-neutral-800 text-neutral-300 px-3 py-1 rounded-full text-xs font-medium">${step.tools.length} tools</span>
                        <i class="accordion-arrow ph-bold ph-caret-right text-2xl text-neutral-500 transition-transform duration-300"></i>
                    </div>
                </button>
                <div class="accordion-content px-5 pb-5">
                    <div class="grid grid-cols-1 gap-4 pt-4 border-t border-neutral-800">
                       ${toolsHtml}
                    </div>
                </div>
            `;
            fragment.appendChild(phaseCard);
        });
        elements.reconGrid.appendChild(fragment);
    };

    // --- SECTION: Core Application Logic ---
    function renderTagFilters() {
        const allTags = new Set(reconSteps.flatMap(step => step.tools.flatMap(tool => tool.tags || [])));
        const sortedTags = Array.from(allTags).sort();

        const tagsHtml = sortedTags.map(tag =>
            `<button class="tag-filter-btn text-xs font-medium py-1.5 px-3 rounded-md transition-colors active:scale-95" data-tag="${tag}">${tag}</button>`
        ).join('');
        elements.tagFilterContainer.innerHTML = tagsHtml;
    }

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
    
    function generateInstallerScript() {
        const selectedToolNames = new Set(Array.from(document.querySelectorAll('.tool-checkbox:checked')).map(cb => cb.dataset.toolName));
        if (selectedToolNames.size === 0) {
            ui.showStatusMessage('Select at least one tool to generate an installer script', 'warning');
            elements.depsList.innerHTML = `<p class="text-neutral-400 font-mono">Select tools and click "Generate Installer" to create a dependency installation script.</p>`;
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
            script += `\n# --- ${title} ---\n`;
            if (check) {
                script += `if command_exists ${check}; then\n    echo ">>> Installing ${title}..."\n`;
                commands.forEach(cmd => { script += `    ${cmd}\n`; });
                script += `else\n    echo "[WARNING] ${check} is not installed. Skipping ${title}."\nfi\n`;
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
                script += `# --- For ${requiredTools.find(t=>t.source === cmd).name} ---\n# ${cmd}\n\n`;
            });
        }


        script += '\necho "--- Installation script finished ---"';
        
        generatedInstallerContent = script;
        elements.depsList.innerHTML = `<pre class="font-mono text-sm text-[#00d4ff] leading-relaxed"><code>${script}</code></pre>`;
        elements.copyDepsBtn.classList.remove('hidden');
        ui.showStatusMessage('Installer script generated successfully!');
    }


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
            
            functionDefinitions += `\n# --- Phase ${phaseId}: ${step.title} ---\n`;
            functionDefinitions += `${functionName}() {\n`;
            functionDefinitions += `\tlog_info "Phase ${phaseId}: Running ${step.workflowName}..."\n`;

            const toolsInPhase = selectedToolsByPhase[phaseId];
            toolsInPhase.forEach(tool => {
                selectedToolNames.push(tool.name);
                functionDefinitions += `\tlog_sub_info "Running ${tool.name}..."\n\t${tool.command}\n`;
            });

            if (phaseId === '02') {
                functionDefinitions += `\tlog_sub_info "Combining and sorting unique subdomains..."\n\tsort -u $RECON_DIR/subdomains/raw.txt > $RECON_DIR/subdomains/final.txt\n\trm $RECON_DIR/subdomains/raw.txt 2>/dev/null\n\tlog_sub_info "Found $(wc -l < $RECON_DIR/subdomains/final.txt) unique subdomains."\n`;
            }
            if (phaseId === '06') {
                 functionDefinitions += `\tlog_sub_info "Combining and sorting unique URLs..."\n\tsort -u $RECON_DIR/urls/raw.txt > $RECON_DIR/urls/final.txt\n\trm $RECON_DIR/urls/raw.txt 2>/dev/null\n\tlog_sub_info "Found $(wc -l < $RECON_DIR/urls/final.txt) unique URLs."\n`;
            }
            functionDefinitions += `}\n`;
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
log_info() { echo -e "\\n[+] \\e[1;36m$1\\e[0m"; }
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

    // --- SECTION: Event Handlers & Initialization ---
    function initialize() {
        if (Object.values(elements).some(el => !el)) {
            console.error('Initialization failed: A required DOM element is missing.');
            return;
        }

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
        elements.copyDepsBtn.addEventListener('click', () => { if(generatedInstallerContent) utils.copyToClipboard(generatedInstallerContent, elements.copyDepsBtn)});

        elements.searchInput.addEventListener('input', updateGridVisibility);
        elements.clearSearchBtn.addEventListener('click', () => { elements.searchInput.value = ''; updateGridVisibility(); });
        elements.tagFilterContainer.addEventListener('click', (e) => {
            if (e.target.classList.contains('tag-filter-btn')) {
                e.target.classList.toggle('active');
                updateGridVisibility();
            }
        });
        elements.resetAllBtn.addEventListener('click', resetAll);
        
        renderFramework();
        renderTagFilters();
        updateToolsUI();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize);
    } else {
        initialize();
    }
})();