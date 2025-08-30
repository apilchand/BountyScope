(() => {
    'use strict';
    // --- SECTION: Constants & Configuration ---
    const SUCCESS_COLOR = '#00d4ff'; // Updated Color
    const ERROR_COLOR = '#ef4444';
    const WARNING_COLOR = '#facc15';
    const CSS_CLASSES = {
        DISABLED_LINK: 'disabled-link',
        COPY_SUCCESS: 'is-copied',
        COPY_FAILURE: 'is-failed',
    };
    const PRESETS = {
        PASSIVE: ['WHOIS Lookup', 'Dig DNS Records', 'Subfinder', 'Assetfinder', 'Amass Enum', 'Chaos DB'],
        QUICK: ['Subfinder', 'Assetfinder', 'httpx Probe', 'Naabu Fast Scan', 'Nuclei Templates'],
        DEEP: ['WHOIS Lookup', 'Dig DNS Records', 'Subfinder', 'Assetfinder', 'Amass Enum', 'httpx Probe', 'Gowitness', 'Naabu Fast Scan', 'Nmap Service Detection', 'Katana Crawler', 'Waybackurls', 'ParamSpider', 'Nuclei Templates'],
        WEB_VULN: ['Subfinder', 'httpx Probe', 'Katana Crawler', 'Waybackurls', 'GF Patterns', 'ParamSpider', 'Nuclei Templates', 'Dalfox XSS', 'SQLMap'],
        FULL: [ 'WHOIS Lookup', 'Dig DNS Records', 'DNSRecon', 'Subfinder', 'Assetfinder', 'Amass Enum', 'Findomain', 'Chaos DB', 'dnsx Resolution', 'httpx Probe', 'Gowitness', 'Aquatone', 'Naabu Fast Scan', 'Nmap Service Detection', 'Katana Crawler', 'Gospider', 'Waybackurls', 'Gau (Get All URLs)', 'ffuf Fuzzer', 'Gobuster Directory', 'subjs', 'LinkFinder', 'SecretFinder', 'ParamSpider', 'Arjun', 'Nuclei Templates', 'Nuclei CVE Scan', 'Dalfox XSS', 'SQLMap', 'WPScan', 'Nikto Web Scanner' ],
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
        workflowMapContainer: document.getElementById('workflowMapContainer'),
        workflowMap: document.getElementById('workflowMap'),
        searchInput: document.getElementById('searchInput'),
        clearSearchBtn: document.getElementById('clearSearchBtn'),
        noResultsMessage: document.getElementById('noResultsMessage'),
        expandAllBtn: document.getElementById('expandAllBtn'),
        collapseAllBtn: document.getElementById('collapseAllBtn'),
    };
    
    // --- SECTION: Application State ---
    let targetDomain = '';
    let statusTimeout;
    let generatedScriptContent = '';

    // --- SECTION: Data ---
    const reconSteps = [
        { phase: "01", title: "Domain Intelligence & Technology Profiling", workflowName: "Domain Intel", description: "Establish baseline intelligence about the target domain including registration details, DNS infrastructure, and underlying technology stack to understand the attack surface.", icon: "ph-detective", tools: [ { name: "WHOIS Lookup", type: "cli", command: "whois [TARGET] | tee [TARGET]_whois.txt", description: "Domain registration and ownership details", category: "info", sourceUrl: "https://www.icann.org/whois" }, { name: "Dig DNS Records", type: "cli", command: "dig +nocmd [TARGET] any +multiline +noall +answer | tee [TARGET]_dns.txt", description: "Complete DNS record enumeration", category: "dns" }, { name: "DNSRecon", type: "cli", command: "dnsrecon -d [TARGET] -t std --xml [TARGET]_dnsrecon.xml", description: "Advanced DNS reconnaissance", category: "dns", sourceUrl: "https://github.com/darkoperator/dnsrecon" }, { name: "Wappalyzer", type: "gui", url: "https://www.wappalyzer.com/lookup/[TARGET]", description: "Technology stack identification", category: "tech", sourceUrl: "https://www.wappalyzer.com/" }, { name: "BuiltWith", type: "gui", url: "https://builtwith.com/?[TARGET]", description: "Comprehensive technology profiler", category: "tech", sourceUrl: "https://builtwith.com/" } ] },
        { phase: "02", title: "Comprehensive Subdomain Discovery", workflowName: "Subdomain Discovery", description: "Employ multiple passive and active techniques to discover all possible subdomains, expanding the attack surface through various data sources and enumeration methods.", icon: "ph-tree-structure", tools: [ { name: "Subfinder", type: "cli", command: "subfinder -d [TARGET] -all -recursive -o [TARGET]_subfinder.txt", description: "Multi-source passive subdomain discovery", category: "passive", sourceUrl: "https://github.com/projectdiscovery/subfinder" }, { name: "Assetfinder", type: "cli", command: "echo [TARGET] | assetfinder --subs-only >> [TARGET]_assetfinder.txt", description: "Fast subdomain and asset discovery", category: "passive", sourceUrl: "https://github.com/tomnomnom/assetfinder" }, { name: "Amass Enum", type: "cli", command: "amass enum -passive -d [TARGET] -config config.ini -o [TARGET]_amass.txt", description: "In-depth subdomain enumeration", category: "active", sourceUrl: "https://github.com/owasp-amass/amass" }, { name: "Findomain", type: "cli", command: "findomain -t [TARGET] -u [TARGET]_findomain.txt", description: "Cross-platform subdomain enumerator", category: "passive", sourceUrl: "https://github.com/findomain/findomain" }, { name: "crt.sh", type: "gui", url: "https://crt.sh/?q=%25.[TARGET]", description: "Certificate transparency logs", category: "passive", sourceUrl: "https://crt.sh" }, { name: "Chaos DB", type: "cli", command: "chaos -d [TARGET] -o [TARGET]_chaos.txt", description: "ProjectDiscovery's subdomain dataset", category: "passive", sourceUrl: "https://github.com/projectdiscovery/chaos-client" } ] },
        { phase: "03", title: "DNS Resolution & Live Service Detection", workflowName: "Live Host Probing", requires: ['02'], description: "Validate discovered subdomains through DNS resolution and probe for active web services, filtering out dead hosts and identifying accessible endpoints.", icon: "ph-broadcast", tools: [ { name: "dnsx Resolution", type: "cli", command: "cat [TARGET]_all_subs.txt | dnsx -resp -a -aaaa -cname -mx -ns -txt -srv -ptr -caa -soa -axfr -caa -any -o [TARGET]_resolved.txt", description: "Fast DNS resolver with multiple record types", category: "dns", sourceUrl: "https://github.com/projectdiscovery/dnsx" }, { name: "PureDNS", type: "cli", command: "puredns resolve [TARGET]_all_subs.txt -r resolvers.txt -w [TARGET]_puredns_valid.txt", description: "Fast domain resolver and subdomain bruteforcing", category: "dns", sourceUrl: "https://github.com/d3mondev/puredns" }, { name: "httpx Probe", type: "cli", command: "cat [TARGET]_resolved.txt | httpx -title -tech-detect -status-code -favicon -jarm -asn -cdn -probe -fr -random-agent -retries 2 -threads 100 -timeout 10 -o [TARGET]_httpx.txt", description: "Advanced HTTP toolkit for probing", category: "http", sourceUrl: "https://github.com/projectdiscovery/httpx" }, { name: "Httprobe", type: "cli", command: "cat [TARGET]_resolved.txt | httprobe -c 50 -t 10000 > [TARGET]_httprobe.txt", description: "Simple HTTP/HTTPS prober", category: "http", sourceUrl: "https://github.com/tomnomnom/httprobe" } ] },
        { phase: "04", title: "Visual Reconnaissance & Screenshot Analysis", workflowName: "Visual Recon", requires: ['03'], description: "Capture visual screenshots of all live web applications to quickly identify interesting interfaces, outdated software, admin panels, and visual anomalies.", icon: "ph-camera-plus", tools: [ { name: "Gowitness", type: "cli", command: "gowitness file -f [TARGET]_live_hosts.txt -P [TARGET]_screenshots --delay 3 --timeout 15 --resolution 1440,900", description: "Fast web screenshot utility with custom resolution", category: "visual", sourceUrl: "https://github.com/sensepost/gowitness" }, { name: "Aquatone", type: "cli", command: "cat [TARGET]_live_hosts.txt | aquatone -out [TARGET]_aquatone -screenshot-timeout 30000 -http-timeout 10000 -threads 5", description: "Visual inspection with detailed reporting", category: "visual", sourceUrl: "https://github.com/michenriksen/aquatone" }, { name: "WebScreenshot", type: "cli", command: "python3 webscreenshot.py -i [TARGET]_live_hosts.txt -o [TARGET]_webscreenshots", description: "Python-based screenshot tool", category: "visual", sourceUrl: "https://github.com/maK-/webscreenshot" } ] },
        { phase: "05", title: "Network Scanning & Service Enumeration", workflowName: "Port Scanning", requires: ['03'], description: "Perform comprehensive port scans across all discovered hosts, identify running services, detect versions, and map the complete network topology.", icon: "ph-radar", tools: [ { name: "Naabu Fast Scan", type: "cli", command: "naabu -list [TARGET]_live_hosts.txt -top-ports 1000 -exclude-ports 80,443 -c 50 -rate 1000 -warm-up-time 2 -o [TARGET]_naabu_ports.txt", description: "Ultra-fast port scanner", category: "ports", sourceUrl: "https://github.com/projectdiscovery/naabu" }, { name: "Masscan Ultra-Fast", type: "cli", command: "masscan -p1-65535 -iL [TARGET]_ips.txt --rate=10000 --open -oG [TARGET]_masscan.txt", description: "Internet-scale port scanner", category: "ports", sourceUrl: "https://github.com/robertdavidgraham/masscan" }, { name: "Nmap Service Detection", type: "cli", command: "nmap -sV -sC -O -A --script=default,discovery,safe,vuln -iL [TARGET]_live_hosts.txt -oA [TARGET]_nmap_detailed", description: "Comprehensive service and vulnerability scanning", category: "services", sourceUrl: "https://nmap.org/" }, { name: "RustScan", type: "cli", command: "rustscan -a [TARGET] -r 1-65535 --ulimit 5000 -t 2000 --scripts -- -A -sC", description: "Modern fast port scanner", category: "ports", sourceUrl: "https://github.com/RustScan/RustScan" }, { name: "Shodan", type: "gui", url: "https://www.shodan.io/search?query=hostname:[TARGET]", description: "Internet device search engine", category: "osint", sourceUrl: "https://shodan.io" } ] },
        { phase: "06", title: "Web Crawling & URL Harvesting", workflowName: "URL Harvesting", requires: ['03'], description: "Systematically crawl discovered web applications and harvest URLs from multiple sources including web archives, search engines, and direct crawling.", icon: "ph-spider", tools: [ { name: "Katana Crawler", type: "cli", command: "katana -list [TARGET]_live_hosts.txt -d 5 -jc -kf all -aff -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o [TARGET]_katana.txt", description: "Next-generation crawling framework", category: "crawler", sourceUrl: "https://github.com/projectdiscovery/katana" }, { name: "Gospider", type: "cli", command: "gospider -S [TARGET]_live_hosts.txt -c 10 -d 5 -t 20 --blacklist jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,svg,txt --random-agent -o [TARGET]_gospider", description: "Fast web spider with filtering", category: "crawler", sourceUrl: "https://github.com/jaeles-project/gospider" }, { name: "Waybackurls", type: "cli", command: "cat [TARGET]_live_hosts.txt | waybackurls | anew [TARGET]_wayback.txt", description: "Wayback Machine URL fetcher", category: "archive", sourceUrl: "https://github.com/tomnomnom/waybackurls" }, { name: "Gau (Get All URLs)", type: "cli", command: "echo [TARGET] | gau --blacklist png,jpg,gif,jpeg,swf,woff,gif,svg --threads 5 | anew [TARGET]_gau.txt", description: "Fetch URLs from multiple sources", category: "archive", sourceUrl: "https://github.com/lc/gau" }, { name: "Hakrawler", type: "cli", command: "echo https://[TARGET] | hakrawler -depth 3 -plain | anew [TARGET]_hakrawler.txt", description: "Simple, fast web crawler", category: "crawler", sourceUrl: "https://github.com/hakluke/hakrawler" } ] },
        { phase: "07", title: "Content Discovery & Directory Fuzzing", workflowName: "Content Fuzzing", requires: ['03'], description: "Systematically discover hidden directories, files, virtual hosts, and other concealed content using advanced wordlist-based fuzzing techniques.", icon: "ph-folder-open", tools: [ { name: "ffuf Fuzzer", type: "cli", command: "ffuf -w /opt/SecLists/Discovery/Web-Content/big.txt -u https://[TARGET]/FUZZ -t 100 -ac -sf -mc 200,204,301,302,307,401,403 -o [TARGET]_ffuf.json", description: "Fast web fuzzer with smart filtering", category: "fuzzer", sourceUrl: "https://github.com/ffuf/ffuf" }, { name: "Gobuster Directory", type: "cli", command: "gobuster dir -u https://[TARGET] -w /opt/SecLists/Discovery/Web-Content/common.txt -t 50 -x php,html,js,txt,json,xml -s 200,204,301,302,307,401,403 -o [TARGET]_gobuster.txt", description: "Directory and file brute-forcer", category: "fuzzer", sourceUrl: "https://github.com/OJ/gobuster" }, { name: "Feroxbuster", type: "cli", command: "feroxbuster -u https://[TARGET] -w /opt/SecLists/Discovery/Web-Content/raft-large-directories.txt -d 2 -t 50 --auto-tune -o [TARGET]_feroxbuster.txt", description: "Fast recursive content discovery", category: "fuzzer", sourceUrl: "https://github.com/epi052/feroxbuster" }, { name: "Dirsearch", type: "cli", command: "dirsearch -u https://[TARGET] -e all -t 50 --random-agent --exclude-status 404,500,502,503 -o [TARGET]_dirsearch.txt", description: "Advanced web path scanner", category: "fuzzer", sourceUrl: "https://github.com/maurosoria/dirsearch" }, { name: "Gobuster VHost", type: "cli", command: "gobuster vhost -u https://[TARGET] -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -t 50 --domain [TARGET] -o [TARGET]_vhosts.txt", description: "Virtual host brute-forcer", category: "vhost", sourceUrl: "https://github.com/OJ/gobuster" } ] },
        { phase: "08", title: "JavaScript Analysis & API Discovery", workflowName: "JS & API Analysis", requires: ['06'], description: "Extract sensitive information, discover hidden API endpoints, analyze client-side code, and identify potential security issues in JavaScript files.", icon: "ph-code", tools: [ { name: "subjs", type: "cli", command: "cat [TARGET]_all_urls.txt | grep -iE '\\.js($|\\?)' | subjs | anew [TARGET]_js_files.txt", description: "JavaScript file extractor", category: "js", sourceUrl: "https://github.com/lc/subjs" }, { name: "LinkFinder", type: "cli", command: "cat [TARGET]_js_files.txt | while read url; do linkfinder -i \"$url\" -o cli; done | anew [TARGET]_linkfinder.txt", description: "Discover endpoints in JS files", category: "js", sourceUrl: "https://github.com/GerbenJavado/LinkFinder" }, { name: "SecretFinder", type: "cli", command: "cat [TARGET]_js_files.txt | while read url; do secretfinder -i \"$url\" -o cli; done | anew [TARGET]_secrets.txt", description: "Find secrets in JavaScript", category: "secrets", sourceUrl: "https://github.com/m4ll0k/SecretFinder" }, { name: "JSParser", type: "cli", command: "cat [TARGET]_js_files.txt | while read url; do jsparser --url \"$url\"; done | anew [TARGET]_jsparser.txt", description: "Parse JavaScript for endpoints", category: "js", sourceUrl: "https://github.com/nahamsec/JSParser" }, { name: "Kiterunner", type: "cli", command: "kr scan [TARGET] -A raft-large-words -x 10 -j 100 --fail-status-codes 404,400 -o [TARGET]_kiterunner", description: "API and content discovery", category: "api", sourceUrl: "https://github.com/assetnote/kiterunner" } ] },
        { phase: "09", title: "Parameter Discovery & Fuzzing", workflowName: "Parameter Hunting", requires: ['06'], description: "Identify hidden parameters, analyze parameter behavior, and discover potential injection points across all discovered endpoints and forms.", icon: "ph-list-bullets", tools: [ { name: "ParamSpider", type: "cli", command: "paramspider -d [TARGET] --exclude woff,css,js,png,svg,jpg,woff2,jpeg,gif,svg --level high -o [TARGET]_paramspider.txt", description: "Parameter discovery from web archives", category: "params", sourceUrl: "https://github.com/devanshbatham/ParamSpider" }, { name: "Arjun", type: "cli", command: "arjun -u https://[TARGET] --get --post -f /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt -oT [TARGET]_arjun.txt", description: "HTTP parameter discovery suite", category: "params", sourceUrl: "https://github.com/s0md3v/Arjun" }, { name: "x8 Hidden Parameters", type: "cli", command: "x8 -u https://[TARGET] -w /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt -X POST --as-body -o [TARGET]_x8.txt", description: "Hidden parameter discovery", category: "params", sourceUrl: "https://github.com/Sh1Yo/x8" }, { name: "GF Patterns", type: "cli", command: "cat [TARGET]_all_urls.txt | gf xss sqli ssrf redirect rce lfi | anew [TARGET]_gf_patterns.txt", description: "Pattern-based URL filtering", category: "patterns", sourceUrl: "https://github.com/tomnomnom/gf" } ] },
        { phase: "10", title: "Cloud Asset & Storage Discovery", workflowName: "Cloud Discovery", description: "Enumerate cloud infrastructure including S3 buckets, Azure blobs, GCP storage, and other cloud services that may contain sensitive data.", icon: "ph-cloud", tools: [ { name: "S3Scanner", type: "cli", command: "s3scanner -bucket-file [TARGET]_buckets.txt -enumerate -dump", description: "AWS S3 bucket scanner", category: "cloud", sourceUrl: "https://github.com/sa7mon/S3Scanner" }, { name: "Cloud_enum", type: "cli", command: "cloud_enum -k [TARGET] -l [TARGET]_cloud_enum.txt", description: "Multi-cloud asset discovery", category: "cloud", sourceUrl: "https://github.com/initstring/cloud_enum" }, { name: "Lazys3", type: "cli", command: "lazys3 [TARGET]", description: "AWS S3 bucket bruteforcer", category: "s3", sourceUrl: "https://github.com/gwen001/lazys3" }, { name: "CloudBrute", type: "cli", command: "cloudbrute -d [TARGET] -k keyword -w /opt/SecLists/Discovery/Web-Content/common.txt", description: "Cloud infrastructure discovery", category: "cloud", sourceUrl: "https://github.com/0xsha/CloudBrute" } ] },
        { phase: "11", title: "Git Repository & Source Code Analysis", workflowName: "Source Code Secrets", description: "Search for exposed repositories, leaked credentials, API keys, and sensitive information in public code repositories and git directories.", icon: "ph-git-branch", tools: [ { name: "TruffleHog", type: "cli", command: "trufflehog github --org=[TARGET] --json | jq . > [TARGET]_trufflehog.json", description: "Find secrets in git repositories", category: "secrets", sourceUrl: "https://github.com/trufflesecurity/trufflehog" }, { name: "GitLeaks", type: "cli", command: "gitleaks detect --source . --report-path [TARGET]_gitleaks.json --verbose", description: "Detect secrets in git repos", category: "secrets", sourceUrl: "https://github.com/gitleaks/gitleaks" }, { name: "GitDorker", type: "cli", command: "python3 GitDorker.py -t [TOKEN] -q [TARGET] -d Dorks/medium_dorks.txt -o [TARGET]_gitdorker.txt", description: "GitHub dorking for sensitive info", category: "osint", sourceUrl: "https://github.com/obheda12/GitDorker" }, { name: "GitHound", type: "cli", command: "githound --dig-files --dig-commits --many-results --regex-file regexes.txt --language-file languages.txt --subdomain-file [TARGET]_subdomains.txt", description: "Git repository secret scanner", category: "secrets", sourceUrl: "https://github.com/tillson/githound" } ] },
        { phase: "12", title: "Vulnerability Scanning & Template-Based Testing", workflowName: "Vulnerability Scanning", requires: ['03'], description: "Execute comprehensive vulnerability scans using template-based tools to identify common security issues, misconfigurations, and known CVEs.", icon: "ph-shield-warning", tools: [ { name: "Nuclei Templates", type: "cli", command: "nuclei -list [TARGET]_live_hosts.txt -t /opt/nuclei-templates/ -severity critical,high,medium -rate-limit 150 -bulk-size 25 -c 25 -o [TARGET]_nuclei.txt", description: "Template-based vulnerability scanner", category: "vuln", sourceUrl: "https://github.com/projectdiscovery/nuclei" }, { name: "Nuclei CVE Scan", type: "cli", command: "nuclei -list [TARGET]_live_hosts.txt -t /opt/nuclei-templates/cves/ -severity critical,high -o [TARGET]_nuclei_cves.txt", description: "CVE-specific vulnerability detection", category: "cve", sourceUrl: "https://github.com/projectdiscovery/nuclei" }, { name: "SSL Labs Test", type: "gui", url: "https://www.ssllabs.com/ssltest/analyze.html?d=[TARGET]", description: "SSL/TLS security analysis", category: "ssl", sourceUrl: "https://www.ssllabs.com/ssltest/" }, { name: "Security Headers", type: "gui", url: "https://securityheaders.com/?q=[TARGET]&followRedirects=on", description: "HTTP security headers analysis", category: "headers", sourceUrl: "https://securityheaders.com/" }, { name: "testssl.sh", type: "cli", command: "testssl.sh --parallel --html --outdir [TARGET]_testssl [TARGET]", description: "Comprehensive SSL/TLS tester", category: "ssl", sourceUrl: "https://github.com/drwetter/testssl.sh" } ] },
        { phase: "13", title: "Specialized Vulnerability Hunting", workflowName: "Exploit Hunting", requires: ['09'], description: "Deploy specialized tools targeting specific vulnerability classes including XSS, SQLi, SSRF, LFI, and other high-impact security issues.", icon: "ph-bug", tools: [ { name: "Dalfox XSS", type: "cli", command: "dalfox file [TARGET]_xss_urls.txt --deep-domxss --blind [BLIND_SERVER] --only-discovery --ignore-return 302,404 -o [TARGET]_dalfox.txt", description: "Advanced XSS scanner and analyzer", category: "xss", sourceUrl: "https://github.com/hahwul/dalfox" }, { name: "SQLMap", type: "cli", command: "sqlmap -m [TARGET]_sqli_urls.txt --batch --level=5 --risk=3 --tamper=space2comment --random-agent --output-dir=[TARGET]_sqlmap/", description: "Automatic SQL injection tester", category: "sqli", sourceUrl: "http://sqlmap.org/" }, { name: "SSRFmap", type: "cli", command: "python3 ssrfmap.py -r [TARGET]_requests.txt -p url -m readfiles", description: "SSRF detection and exploitation", category: "ssrf", sourceUrl: "https://github.com/swisskyrepo/SSRFmap" }, { name: "NoSQLMap", type: "cli", command: "python3 nosqlmap.py -u https://[TARGET]/endpoint --scan --exploit", description: "NoSQL injection scanner", category: "nosql", sourceUrl: "https://github.com/codingo/NoSQLMap" }, { name: "Commix", type: "cli", command: "python3 commix.py -u https://[TARGET]/page?param=value --batch", description: "Command injection exploiter", category: "rce", sourceUrl: "https://github.com/commixproject/commix" } ] },
        { phase: "14", title: "CMS & Framework Security Assessment", workflowName: "CMS Scanning", requires: ['03'], description: "Identify and assess Content Management Systems, frameworks, and platforms for known vulnerabilities, misconfigurations, and security weaknesses.", icon: "ph-gear-six", tools: [ { name: "WPScan", type: "cli", command: "wpscan --url https://[TARGET] --enumerate ap,at,cb,dbe,u,m --plugins-detection aggressive --api-token [TOKEN] --format json -o [TARGET]_wpscan.json", description: "WordPress vulnerability scanner", category: "cms", sourceUrl: "https://wpscan.com/" }, { name: "Joomscan", type: "cli", command: "joomscan --url https://[TARGET] --enumerate-components --random-agent", description: "Joomla vulnerability scanner", category: "cms", sourceUrl: "https://github.com/OWASP/joomscan" }, { name: "Droopescan", type: "cli", command: "droopescan scan drupal --url https://[TARGET] --enumerate p,t,u,v", description: "Drupal security scanner", category: "cms", sourceUrl: "https://github.com/droope/droopescan" }, { name: "CMSmap", type: "cli", command: "cmsmap https://[TARGET] -a -d", description: "Multi-CMS vulnerability scanner", category: "cms", sourceUrl: "https://github.com/Dionach/CMSmap" }, { name: "Nikto Web Scanner", type: "cli", command: "nikto -h https://[TARGET] -ssl -evasion 1 -output [TARGET]_nikto.txt", description: "Web server vulnerability scanner", category: "web", sourceUrl: "https://cirt.net/Nikto2" } ] },
        { phase: "15", title: "Essential Resources & Wordlists", workflowName: "Resource Library", description: "Curated collection of essential wordlists, payloads, and resources for comprehensive security testing and vulnerability research.", icon: "ph-books", isResource: true, tools: [ { name: "SecLists", type: "gui", url: "https://github.com/danielmiessler/SecLists", noTarget: true, description: "Security tester's companion wordlist collection", category: "wordlists", sourceUrl: "https://github.com/danielmiessler/SecLists" }, { name: "PayloadsAllTheThings", type: "gui", url: "https://github.com/swisskyrepo/PayloadsAllTheThings", noTarget: true, description: "Web application security payload repository", category: "payloads", sourceUrl: "https://github.com/swisskyrepo/PayloadsAllTheThings" }, { name: "FuzzDB", type: "gui", url: "https://github.com/fuzzdb-project/fuzzdb", noTarget: true, description: "Dictionary of attack patterns and primitives", category: "fuzzing", sourceUrl: "https://github.com/fuzzdb-project/fuzzdb" }, { name: "GF Patterns", type: "gui", url: "https://github.com/1ndianl33t/Gf-Patterns", noTarget: true, description: "Grep-friendly patterns for bug bounty", category: "patterns", sourceUrl: "https://github.com/1ndianl33t/Gf-Patterns" }, { name: "Nuclei Templates", type: "gui", url: "https://github.com/projectdiscovery/nuclei-templates", noTarget: true, description: "Community-powered vulnerability templates", category: "templates", sourceUrl: "https://github.com/projectdiscovery/nuclei-templates" } ] }
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
            <div class="bg-black rounded-md p-3 ml-10"><code class="block text-[#00d4ff] text-sm font-mono leading-relaxed overflow-x-auto" data-command-template="${tool.command}">Set target to see command...</code></div>
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

            const toolsHtml = step.tools.map(tool => tool.type === 'gui' ? createGuiToolHtml(tool) : createCliToolHtml(tool, step)).join('');

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
    function renderDependencies() {
        const TOOL_INSTALL_COMMANDS = [
            { name: 'amass', go: 'go install -v github.com/owasp-amass/amass/v4/...@master' },
            { name: 'aquatone', go: 'go install github.com/michenriksen/aquatone@latest' },
            { name: 'arjun', pip: 'pip3 install arjun' },
            { name: 'assetfinder', go: 'go install github.com/tomnomnom/assetfinder@latest' },
            { name: 'chaos', go: 'go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest' },
            { name: 'cloud_enum', pip: 'pip3 install cloud_enum' },
            { name: 'cloudbrute', source: 'git clone https://github.com/0xsha/CloudBrute && cd CloudBrute && pip3 install -r requirements.txt' },
            { name: 'cmsmap', source: 'git clone https://github.com/Dionach/CMSmap.git && cd CMSmap && pip3 install .'},
            { name: 'commix', source: 'git clone https://github.com/commixproject/commix.git commix' },
            { name: 'dalfox', go: 'go install -v github.com/hahwul/dalfox/v2@latest' },
            { name: 'dig', apt: 'sudo apt install dnsutils', brew: 'brew install bind', notes: 'Usually pre-installed on Linux/macOS.' },
            { name: 'dirsearch', source: 'git clone https://github.com/maurosoria/dirsearch.git && cd dirsearch && pip3 install -r requirements.txt' },
            { name: 'dnsrecon', pip: 'pip3 install dnsrecon' },
            { name: 'dnsx', go: 'go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest' },
            { name: 'droopescan', pip: 'pip3 install droopescan' },
            { name: 'feroxbuster', apt: 'sudo apt install feroxbuster', brew: 'brew install feroxbuster' },
            { name: 'ffuf', go: 'go install github.com/ffuf/ffuf@latest' },
            { name: 'findomain', source: 'https://github.com/findomain/findomain/releases', notes: 'Install from official releases.' },
            { name: 'gau', go: 'go install github.com/lc/gau/v2/cmd/gau@latest' },
            { name: 'gf', go: 'go install github.com/tomnomnom/gf@latest', notes: 'Also requires Gf-Patterns.' },
            { name: 'gitleaks', apt: 'sudo apt install gitleaks', brew: 'brew install gitleaks' },
            { name: 'gobuster', apt: 'sudo apt install gobuster', brew: 'brew install gobuster' },
            { name: 'gospider', go: 'go install github.com/jaeles-project/gospider@latest' },
            { name: 'gowitness', go: 'go install github.com/sensepost/gowitness@latest' },
            { name: 'hakrawler', go: 'go install github.com/hakluke/hakrawler@latest' },
            { name: 'httprobe', go: 'go install github.com/tomnomnom/httprobe@latest' },
            { name: 'httpx', go: 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest' },
            { name: 'joomscan', perl: 'cpan install JSON', source: 'git clone https://github.com/OWASP/joomscan.git' },
            { name: 'katana', go: 'go install -v github.com/projectdiscovery/katana/cmd/katana@latest' },
            { name: 'kiterunner', source: 'https://github.com/assetnote/kiterunner/releases', notes: 'Install from official releases.' },
            { name: 'linkfinder', source: 'git clone https://github.com/GerbenJavado/LinkFinder.git && cd LinkFinder && pip3 install -r requirements.txt' },
            { name: 'masscan', apt: 'sudo apt install masscan', brew: 'brew install masscan' },
            { name: 'naabu', go: 'go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest' },
            { name: 'nikto', apt: 'sudo apt install nikto', brew: 'brew install nikto' },
            { name: 'nmap', apt: 'sudo apt install nmap', brew: 'brew install nmap' },
            { name: 'nuclei', go: 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest' },
            { name: 'paramspider', source: 'git clone https://github.com/devanshbatham/ParamSpider && cd ParamSpider && pip3 install -r requirements.txt' },
            { name: 'puredns', go: 'go install -v github.com/d3mondev/puredns/v2@latest' },
            { name: 'rustscan', brew: 'brew install rustscan', source: 'https://github.com/RustScan/RustScan/releases', notes: 'Install from releases or Docker.' },
            { name: 's3scanner', pip: 'pip3 install s3scanner' },
            { name: 'secretfinder', pip: 'pip3 install secretfinder' },
            { name: 'sqlmap', apt: 'sudo apt install sqlmap', brew: 'brew install sqlmap' },
            { name: 'ssrfmap', source: 'git clone https://github.com/swisskyrepo/SSRFmap && cd SSRFmap && pip3 install -r requirements.txt' },
            { name: 'subfinder', go: 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest' },
            { name: 'subjs', go: 'go install github.com/lc/subjs@latest' },
            { name: 'testssl.sh', source: 'git clone --depth 1 https://github.com/drwetter/testssl.sh.git' },
            { name: 'trufflehog', source: 'curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh' },
            { name: 'waybackurls', go: 'go install github.com/tomnomnom/waybackurls@latest' },
            { name: 'whois', apt: 'sudo apt install whois', brew: 'brew install whois' },
            { name: 'wpscan', gem: 'gem install wpscan', notes: 'Requires Ruby.' },
            { name: 'x8', go: 'go install github.com/Sh1Yo/x8/v2@latest' }
        ].sort((a, b) => a.name.localeCompare(b.name));

        const platform = navigator.platform.toLowerCase();
        let recommendedManager = null;
        if (platform.includes('mac') || platform.includes('iphone')) {
            recommendedManager = 'brew';
        } else if (platform.includes('linux')) {
            recommendedManager = 'apt';
        }

        const getButtonHtml = (manager, command, toolName) => {
            if (!command) return '';
            const isRecommended = manager === recommendedManager;
            const managerLabel = manager.charAt(0).toUpperCase() + manager.slice(1);
            return `<button class="dep-command-btn ${isRecommended ? 'is-recommended' : ''}" data-command="${command.replace(/"/g, '&quot;')}" title="Copy install command for ${toolName}">
                        <i class="ph-bold ph-copy text-xs"></i>
                        <span>${managerLabel}</span>
                    </button>`;
        };

        const depsHtml = TOOL_INSTALL_COMMANDS.map(tool => {
            const buttons = [
                getButtonHtml('apt', tool.apt, tool.name),
                getButtonHtml('brew', tool.brew, tool.name),
                getButtonHtml('go', tool.go, tool.name),
                getButtonHtml('pip', tool.pip, tool.name),
                getButtonHtml('gem', tool.gem, tool.name),
                getButtonHtml('perl', tool.perl, tool.name),
                getButtonHtml('source', tool.source, tool.name),
            ].filter(Boolean).join('');
            
            const notesHtml = tool.notes ? `<p class="dep-notes">Note: ${tool.notes}</p>` : '';

            return `
                <div class="dep-card">
                    <div class="dep-card-header">
                        <h4 class="dep-card-title">${tool.name}</h4>
                    </div>
                    <div class="dep-commands">
                        ${buttons}
                    </div>
                    ${notesHtml}
                </div>`;
        }).join('');
        
        elements.depsList.className = 'deps-grid'; // Use grid layout
        elements.depsList.innerHTML = depsHtml || '<p class="text-neutral-400">Could not load dependency installation commands.</p>';
        // Hide the generic "Copy List" button for the new UI
        elements.copyDepsBtn.style.display = 'none';
    }
    
    function updateToolsUI() {
        const isTargetSet = !!targetDomain;
        document.querySelectorAll(`a.recon-link`).forEach(link => {
            link.classList.toggle(CSS_CLASSES.DISABLED_LINK, !isTargetSet);
            link.href = isTargetSet ? link.dataset.urlTemplate.replace(/\[TARGET\]/g, encodeURIComponent(targetDomain)) : "#";
        });
        document.querySelectorAll('code[data-command-template]').forEach(code => {
            const copyButton = code.closest('.group').querySelector('.copy-btn');
            copyButton.classList.toggle(CSS_CLASSES.DISABLED_LINK, !isTargetSet);
            code.textContent = isTargetSet ? code.dataset.commandTemplate.replace(/\[TARGET\]/g, targetDomain) : 'Set target to see command...';
        });
        document.querySelectorAll('.phase-checkbox').forEach(checkbox => {
             ui.toggleDisabled(checkbox, !isTargetSet);
        });
        const controlButtons = [
            elements.generateScriptBtn, elements.viewDepsBtn, elements.selectAllBtn,
            elements.deselectAllBtn, elements.loadPassiveScanBtn, elements.loadQuickScanBtn,
            elements.loadDeepScanBtn, elements.loadWebVulnScanBtn, elements.loadFullScanBtn
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
    
    function handleSearch() {
        const searchTerm = elements.searchInput.value.toLowerCase().trim();
        ui.toggleVisibility(elements.clearSearchBtn, searchTerm.length > 0);

        const allToolContainers = document.querySelectorAll('.tool-container');
        allToolContainers.forEach(el => el.classList.remove('tool-highlight'));

        const phaseCards = document.querySelectorAll('.phase-card');
        let visibleCount = 0;

        phaseCards.forEach((card, index) => {
            const stepData = reconSteps[index];
            let isPhaseVisible = false;

            if (!searchTerm) {
                isPhaseVisible = true;
            } else {
                const phaseTitleMatch = stepData.title.toLowerCase().includes(searchTerm);
                const phaseDescMatch = stepData.description.toLowerCase().includes(searchTerm);

                if (phaseTitleMatch || phaseDescMatch) {
                    isPhaseVisible = true;
                }

                const toolElements = card.querySelectorAll('.tool-container');
                stepData.tools.forEach((tool, toolIndex) => {
                    const toolNameMatch = tool.name.toLowerCase().includes(searchTerm);
                    const toolDescMatch = tool.description.toLowerCase().includes(searchTerm);

                    if (toolNameMatch || toolDescMatch) {
                        isPhaseVisible = true;
                        const toolEl = toolElements[toolIndex];
                        if (toolEl) {
                            toolEl.classList.add('tool-highlight');
                        }
                    }
                });
            }
            
            card.style.display = isPhaseVisible ? '' : 'none';
            if (isPhaseVisible) {
                visibleCount++;
            }
        });
        
        elements.noResultsMessage.classList.toggle('hidden', visibleCount > 0);
    }

    function updateDependencyWarnings() {
        const activePhaseIds = new Set(
            Array.from(document.querySelectorAll('.tool-checkbox:checked'))
                 .map(cb => cb.dataset.phaseId)
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
    
    const TOOL_SCRIPTS = {
        'WHOIS Lookup': c => `\tlog_sub_info "Performing WHOIS Lookup..."\n\twhois $TARGET > "${c.INFO_DIR}/whois.txt" 2>/dev/null || log_warn "WHOIS lookup failed for $TARGET."`,
        'Dig DNS Records': c => `\tlog_sub_info "Querying all DNS records with Dig..."\n\tdig +nocmd $TARGET ANY +multiline +noall +answer > "${c.INFO_DIR}/dns_records.txt"`,
        'DNSRecon': c => `\tlog_sub_info "Running DNSRecon..."\n\tdnsrecon -d $TARGET -t std > "${c.INFO_DIR}/dnsrecon.txt" 2>/dev/null || log_warn "DNSRecon scan failed."`,
        'Subfinder': c => `\tlog_sub_info "Running Subfinder..."\n\tsubfinder -d "$TARGET" -all -silent -o- >> ${c.SUBDOMAINS_RAW}`,
        'Assetfinder': c => `\tlog_sub_info "Running Assetfinder..."\n\tassetfinder --subs-only "$TARGET" >> ${c.SUBDOMAINS_RAW}`,
        'Amass Enum': c => `\tlog_sub_info "Running Amass Enum (passive)..."\n\tamass enum -passive -d "$TARGET" -silent -o- >> ${c.SUBDOMAINS_RAW}`,
        'Findomain': c => `\tlog_sub_info "Running Findomain..."\n\tfindomain -t $TARGET -q >> ${c.SUBDOMAINS_RAW}`,
        'Chaos DB': c => `\tlog_sub_info "Running Chaos Client..."\n\tchaos -d $TARGET -silent >> ${c.SUBDOMAINS_RAW}`,
        'dnsx Resolution': c => `\tlog_sub_info "Resolving subdomains with dnsx..."\n\tcat ${c.SUBDOMAINS_FINAL} | dnsx -resp -silent -o ${c.RESOLVED_HOSTS}`,
        'httpx Probe': c => `\tlog_sub_info "Probing for live web servers with httpx..."\n\tcat ${c.SUBDOMAINS_FINAL} | httpx -silent -threads 100 -o ${c.LIVE_HOSTS}`,
        'Httprobe': c => `\tlog_sub_info "Probing for live web servers with httprobe..."\n\tcat ${c.SUBDOMAINS_FINAL} | httprobe -c 50 > ${c.LIVE_HOSTS_ALT}`,
        'Gowitness': c => `\tlog_sub_info "Taking screenshots with Gowitness..."\n\tgowitness file -f ${c.LIVE_HOSTS} -P ${c.SCREENSHOTS_DIR} --disable-db --timeout 15`,
        'Aquatone': c => `\tlog_sub_info "Generating report with Aquatone..."\n\tcat ${c.LIVE_HOSTS} | aquatone -out "${c.RECON_DIR}/aquatone"`,
        'Naabu Fast Scan': c => `\tlog_sub_info "Running Naabu for fast port scan (Top 1000)..."\n\tnaabu -list ${c.LIVE_HOSTS} -top-ports 1000 -silent -o ${c.NAABU_RESULTS}`,
        'Nmap Service Detection': c => `\tlog_sub_info "Running Nmap for detailed service detection..."\n\tnmap -iL ${c.LIVE_HOSTS} -sV -sC -A -T4 -oA "${c.NMAP_DIR}/nmap_scan"`,
        'Katana Crawler': c => `\tlog_sub_info "Crawling hosts with Katana..."\n\tcat ${c.LIVE_HOSTS} | katana -silent -d 3 -jc -kf -o- >> ${c.URLS_RAW}`,
        'Waybackurls': c => `\tlog_sub_info "Fetching URLs from Wayback Machine..."\n\tcat ${c.LIVE_HOSTS} | waybackurls >> ${c.URLS_RAW}`,
        'Gospider': c => `\tlog_sub_info "Crawling hosts with Gospider..."\n\tgospider -S ${c.LIVE_HOSTS} -c 10 -d 3 -q -o- | grep -E '^\\[(gospider|url)\\]' | cut -d ' ' -f 3 >> ${c.URLS_RAW}`,
        'Gau (Get All URLs)': c => `\tlog_sub_info "Fetching URLs with Gau..."\n\techo $TARGET | gau --subs >> ${c.URLS_RAW}`,
        'ffuf Fuzzer': c => `\tlog_sub_info "Fuzzing root domain with ffuf..."\n\tffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://$TARGET/FUZZ -mc 200,301,302 -o "${c.SCANS_DIR}/ffuf_root.json"`,
        'Gobuster Directory': c => `\tlog_sub_info "Brute-forcing directories on root with Gobuster..."\n\tgobuster dir -u https://$TARGET -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 50 -o "${c.SCANS_DIR}/gobuster_root.txt"`,
        'subjs': c => `\tlog_sub_info "Extracting JavaScript files with subjs..."\n\tcat ${c.URLS_FINAL} | grep -iE '\\.js($|\\?)' | subjs | anew "${c.URLS_DIR}/js_files.txt"`,
        'LinkFinder': c => `\tlog_sub_info "Finding endpoints in JS files with LinkFinder..."\n\tcat "${c.URLS_DIR}/js_files.txt" | while read url; do linkfinder -i "$url" -o cli; done | anew "${c.URLS_DIR}/linkfinder.txt"`,
        'SecretFinder': c => `\tlog_sub_info "Finding secrets in JS with SecretFinder..."\n\tcat "${c.URLS_DIR}/js_files.txt" | while read url; do secretfinder -i "$url" -o cli; done | anew "${c.URLS_DIR}/secrets.txt"`,
        'ParamSpider': c => `\tlog_sub_info "Discovering parameters with ParamSpider..."\n\tparamspider -d $TARGET --exclude woff,css,png,svg,jpg -q -o "${c.URLS_DIR}/paramspider.txt"`,
        'Arjun': c => `\tlog_sub_info "Discovering parameters on root with Arjun..."\n\tarjun -u "https://$TARGET/" -oT "${c.URLS_DIR}/arjun_root.txt"`,
        'GF Patterns': c => `\tlog_sub_info "Filtering URLs with GF patterns..."\n\tcat ${c.URLS_FINAL} | gf xss | anew "${c.URLS_DIR}/gf_xss.txt"\n\tcat ${c.URLS_FINAL} | gf sqli | anew "${c.URLS_DIR}/gf_sqli.txt"\n\tcat ${c.URLS_FINAL} | gf ssrf | anew "${c.URLS_DIR}/gf_ssrf.txt"`,
        'Nuclei Templates': c => `\tlog_sub_info "Running Nuclei with default templates..."\n\tnuclei -l ${c.LIVE_HOSTS} -t /opt/nuclei-templates/ -severity critical,high,medium -o ${c.NUCLEI_RESULTS}`,
        'Nuclei CVE Scan': c => `\tlog_sub_info "Running Nuclei CVE scan..."\n\tnuclei -l ${c.LIVE_HOSTS} -t /opt/nuclei-templates/cves/ -severity critical,high -o ${c.NUCLEI_CVE_RESULTS}`,
        'Dalfox XSS': c => `\tlog_sub_info "Scanning for XSS with Dalfox (requires gf_xss.txt file)..."\n\tif [ -s "${c.URLS_DIR}/gf_xss.txt" ]; then dalfox file "${c.URLS_DIR}/gf_xss.txt" -o "${c.SCANS_DIR}/dalfox.txt"; else log_warn "XSS candidates file not found, skipping Dalfox."; fi`,
        'SQLMap': c => `\tlog_sub_info "Scanning for SQLi with SQLMap (requires gf_sqli.txt file)..."\n\tif [ -s "${c.URLS_DIR}/gf_sqli.txt" ]; then sqlmap -m "${c.URLS_DIR}/gf_sqli.txt" --batch --random-agent --output-dir="${c.SCANS_DIR}/sqlmap" -dbs; else log_warn "SQLi candidates file not found, skipping SQLMap."; fi`,
        'WPScan': c => `\tlog_sub_info "Scanning root domain with WPScan..."\n\twpscan --url https://$TARGET --enumerate ap,at,dbe --random-user-agent --output "${c.SCANS_DIR}/wpscan.txt"`,
        'Nikto Web Scanner': c => `\tlog_sub_info "Scanning root domain with Nikto..."\n\tnikto -h https://$TARGET -o "${c.SCANS_DIR}/nikto_root.txt"`,
    };

    function generateScript() {
        if (!targetDomain) return ui.showStatusMessage('Please set a target domain first', 'error');
        
        const selectedToolCheckboxes = Array.from(document.querySelectorAll('.tool-checkbox:checked'));
        if (selectedToolCheckboxes.length === 0) {
             return ui.showStatusMessage('Please select at least one tool to generate a script', 'error');
        }
        
        const selectedToolsByPhase = selectedToolCheckboxes.reduce((acc, cb) => {
            const phaseId = cb.dataset.phaseId;
            const toolName = cb.dataset.toolName;
            if (!acc[phaseId]) acc[phaseId] = [];
            acc[phaseId].push(toolName);
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

        const SCRIPT_CONFIG = {
            TARGET: targetDomain, RECON_DIR: `"$TARGET/recon"`,
            INFO_DIR: `"$RECON_DIR/info"`, URLS_DIR: `"$RECON_DIR/urls"`, SCANS_DIR: `"$RECON_DIR/scans"`,
            SUBDOMAINS_RAW: `"$RECON_DIR/subdomains/raw.txt"`, SUBDOMAINS_FINAL: `"$RECON_DIR/subdomains/final.txt"`,
            LIVE_HOSTS: `"$RECON_DIR/hosts/live.txt"`, LIVE_HOSTS_ALT: `"$RECON_DIR/hosts/live_alt.txt"`, RESOLVED_HOSTS: `"$RECON_DIR/hosts/resolved.txt"`,
            URLS_RAW: `"$RECON_DIR/urls/raw.txt"`, URLS_FINAL: `"$RECON_DIR/urls/final.txt"`,
            SCREENSHOTS_DIR: `"$RECON_DIR/screenshots/"`,
            NMAP_DIR: `"$RECON_DIR/scans/nmap"`, NAABU_RESULTS: `"$RECON_DIR/scans/naabu_ports.txt"`, 
            NUCLEI_RESULTS: `"$RECON_DIR/scans/nuclei.txt"`, NUCLEI_CVE_RESULTS: `"$RECON_DIR/scans/nuclei_cves.txt"`
        };

        let functionDefinitions = '';
        let functionCalls = '';

        sortedPhaseIds.forEach(phaseId => {
            const step = reconSteps.find(s => s.phase === phaseId);
            if (!step) return;

            const functionName = `run_phase_${phaseId}`;
            functionCalls += `    ${functionName}\n`;
            
            functionDefinitions += `\n# --- Phase ${phaseId}: ${step.title} ---\n`;
            functionDefinitions += `${functionName}() {\n`;
            functionDefinitions += `\tlog_info "Phase ${phaseId}: Running ${step.workflowName}..."\n`;

            const toolsInPhase = selectedToolsByPhase[phaseId];
            toolsInPhase.forEach(toolName => {
                if (TOOL_SCRIPTS[toolName]) {
                    functionDefinitions += TOOL_SCRIPTS[toolName](SCRIPT_CONFIG) + '\n';
                } else {
                    functionDefinitions += `\tlog_warn "Script generation for tool '${toolName}' is not implemented."\n`;
                }
            });

            // Add aggregation logic for specific phases
            if (phaseId === '02') {
                functionDefinitions += `\tlog_sub_info "Combining and sorting unique subdomains..."\n\tsort -u ${SCRIPT_CONFIG.SUBDOMAINS_RAW} > ${SCRIPT_CONFIG.SUBDOMAINS_FINAL}\n\trm ${SCRIPT_CONFIG.SUBDOMAINS_RAW} 2>/dev/null\n\tlog_sub_info "Found $(wc -l < ${SCRIPT_CONFIG.SUBDOMAINS_FINAL}) unique subdomains."\n`;
            }
            if (phaseId === '06') {
                 functionDefinitions += `\tlog_sub_info "Combining and sorting unique URLs..."\n\tsort -u ${SCRIPT_CONFIG.URLS_RAW} > ${SCRIPT_CONFIG.URLS_FINAL}\n\trm ${SCRIPT_CONFIG.URLS_RAW} 2>/dev/null\n\tlog_sub_info "Found $(wc -l < ${SCRIPT_CONFIG.URLS_FINAL}) unique URLs."\n`;
            }
            functionDefinitions += `}\n`;
        });

        const dirList = "info subdomains hosts urls scans screenshots scans/nmap";
        const selectedToolNames = selectedToolCheckboxes.map(cb => cb.dataset.toolName);

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
# Each step of the recon process is encapsulated in a function.
# You can easily skip a phase by commenting out its call in the main() function.
${functionDefinitions}

# --- Main Execution ---
# The main function orchestrates the entire workflow.
main() {
    log_info "Starting reconnaissance workflow for: $TARGET"
    
    log_sub_info "Setting up directory structure..."
    mkdir -p "$TARGET"
    for dir in ${dirList}; do mkdir -p "$RECON_DIR/$dir"; done

${functionCalls}
    log_info "\\e[1;32mReconnaissance workflow finished for $TARGET!\\e[0m"
    echo -e "[+] All results are stored in the '$TARGET/' directory."
}

# Run the main function
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
        handleSearch();

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
    
    function loadPreset(toolNames, presetName) {
        if (!targetDomain) {
            ui.showStatusMessage('Set a target before loading a workflow', 'warning');
            return;
        }
        document.querySelectorAll('.tool-checkbox:not(:disabled)').forEach(cb => cb.checked = false);
        
        toolNames.forEach(name => {
            const checkbox = document.querySelector(`.tool-checkbox[data-tool-name="${name}"]`);
            if (checkbox) checkbox.checked = true;
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
                e.preventDefault();
                e.stopPropagation();
                const codeElement = copyButton.closest('.group')?.querySelector('code[data-command-template]');
                if (codeElement && codeElement.textContent.trim() !== 'Set target to see command...') {
                    utils.copyToClipboard(codeElement.textContent, copyButton);
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

        elements.depsContainer.addEventListener('click', (e) => {
            const copyButton = e.target.closest('.dep-command-btn');
            if (copyButton && copyButton.dataset.command) {
                e.preventDefault();
                utils.copyToClipboard(copyButton.dataset.command, copyButton);
            }
        });

        elements.searchInput.addEventListener('input', handleSearch);
        elements.clearSearchBtn.addEventListener('click', () => {
            elements.searchInput.value = '';
            handleSearch();
        });

        elements.resetAllBtn.addEventListener('click', resetAll);
        
        renderFramework();
        renderDependencies();
        updateToolsUI();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize);
    } else {
        initialize();
    }
})();