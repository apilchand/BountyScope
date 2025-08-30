#!/bin/bash
# --- BountyScope Automation Script ---
# Target: apilchand.com.np
# Generated: 2025-08-30T05:59:10.300Z
# Selected Tools: 26
#
# Usage: ./bountyscope_apilchand.com.np.sh
# -----------------------------------------

set -eo pipefail

# --- Configuration & Setup ---
TARGET="apilchand.com.np"
RECON_DIR="$TARGET/recon"

# --- Logging Helpers ---
log_info() { echo -e "\n[+] \e[1;36m$1\e[0m"; }
log_sub_info() { echo -e "  [i] \e[0;34m$1\e[0m"; }
log_warn() { echo -e "  [!] \e[1;33m$1\e[0m"; }

# --- Phase Functions ---

# --- Phase 01: Domain Intelligence & Technology Profiling ---
run_phase_01_domain_intel() {
	log_info "Phase 01: Running Domain Intel..."
	log_sub_info "Running WHOIS Lookup..."
	whois apilchand.com.np | tee $RECON_DIR/info/whois.txt
	log_sub_info "Running Dig DNS Records..."
	dig +nocmd apilchand.com.np any +multiline +noall +answer | tee $RECON_DIR/info/dns.txt
	log_sub_info "Running DNSRecon..."
	dnsrecon -d apilchand.com.np -t std --xml $RECON_DIR/info/dnsrecon.xml
}

# --- Phase 02: Comprehensive Subdomain Discovery ---
run_phase_02_subdomain_discovery() {
	log_info "Phase 02: Running Subdomain Discovery..."
	log_sub_info "Running Subfinder..."
	subfinder -d apilchand.com.np -all -recursive -o- >> $RECON_DIR/subdomains/raw.txt
	log_sub_info "Running Assetfinder..."
	assetfinder --subs-only apilchand.com.np >> $RECON_DIR/subdomains/raw.txt
	log_sub_info "Running Amass Enum..."
	amass enum -passive -d apilchand.com.np -config config.ini -o- >> $RECON_DIR/subdomains/raw.txt
	log_sub_info "Running Findomain..."
	findomain -t apilchand.com.np -q >> $RECON_DIR/subdomains/raw.txt
	log_sub_info "Running Chaos DB..."
	chaos -d apilchand.com.np -o- >> $RECON_DIR/subdomains/raw.txt
	log_sub_info "Combining and sorting unique subdomains..."
	sort -u $RECON_DIR/subdomains/raw.txt > $RECON_DIR/subdomains/final.txt
	rm $RECON_DIR/subdomains/raw.txt 2>/dev/null
	log_sub_info "Found $(wc -l < $RECON_DIR/subdomains/final.txt) unique subdomains."
}

# --- Phase 03: DNS Resolution & Live Service Detection ---
run_phase_03_live_host_probing() {
	log_info "Phase 03: Running Live Host Probing..."
	log_sub_info "Running dnsx Resolution..."
	cat $RECON_DIR/subdomains/final.txt | dnsx -resp -silent -o $RECON_DIR/hosts/resolved.txt
	log_sub_info "Running httpx Probe..."
	cat $RECON_DIR/subdomains/final.txt | httpx -title -tech-detect -status-code -probe -fr -o $RECON_DIR/hosts/live.txt
	log_sub_info "Running Httprobe..."
	cat $RECON_DIR/subdomains/final.txt | httprobe -c 50 > $RECON_DIR/hosts/live_alt.txt
}

# --- Phase 04: Visual Reconnaissance & Screenshot Analysis ---
run_phase_04_visual_recon() {
	log_info "Phase 04: Running Visual Recon..."
	log_sub_info "Running Gowitness..."
	gowitness file -f $RECON_DIR/hosts/live.txt -P $RECON_DIR/screenshots --delay 3 --timeout 15
	log_sub_info "Running Aquatone..."
	cat $RECON_DIR/hosts/live.txt | aquatone -out $RECON_DIR/aquatone
}

# --- Phase 05: Network Scanning & Service Enumeration ---
run_phase_05_port_scanning() {
	log_info "Phase 05: Running Port Scanning..."
	log_sub_info "Running Naabu Fast Scan..."
	naabu -list $RECON_DIR/hosts/live.txt -top-ports 1000 -silent -o $RECON_DIR/scans/naabu_ports.txt
	log_sub_info "Running Nmap Service Detection..."
	nmap -sV -sC -O --script=default,discovery,vuln -iL $RECON_DIR/hosts/live.txt -oA $RECON_DIR/scans/nmap/nmap_detailed
	log_sub_info "Running RustScan..."
	rustscan -a apilchand.com.np -r 1-65535 -- -A -sC
}

# --- Phase 06: Web Crawling & URL Harvesting ---
run_phase_06_url_harvesting() {
	log_info "Phase 06: Running URL Harvesting..."
	log_sub_info "Running Katana Crawler..."
	katana -list $RECON_DIR/hosts/live.txt -d 5 -jc -kf all -o- >> $RECON_DIR/urls/raw.txt
	log_sub_info "Running Gospider..."
	gospider -S $RECON_DIR/hosts/live.txt -c 10 -d 5 -t 20 -q -o- | grep -oE 'http.*' >> $RECON_DIR/urls/raw.txt
	log_sub_info "Running Waybackurls..."
	cat $RECON_DIR/hosts/live.txt | waybackurls >> $RECON_DIR/urls/raw.txt
	log_sub_info "Running Gau (Get All URLs)..."
	echo apilchand.com.np | gau --subs >> $RECON_DIR/urls/raw.txt
	log_sub_info "Combining and sorting unique URLs..."
	sort -u $RECON_DIR/urls/raw.txt > $RECON_DIR/urls/final.txt
	rm $RECON_DIR/urls/raw.txt 2>/dev/null
	log_sub_info "Found $(wc -l < $RECON_DIR/urls/final.txt) unique URLs."
}

# --- Phase 09: Parameter Discovery & Fuzzing ---
run_phase_09_parameter_hunting() {
	log_info "Phase 09: Running Parameter Hunting..."
	log_sub_info "Running ParamSpider..."
	paramspider -d apilchand.com.np --exclude woff,css,png,svg,jpg -q -o $RECON_DIR/urls/paramspider
	log_sub_info "Running Arjun..."
	arjun -u https://apilchand.com.np/ -oT $RECON_DIR/urls/arjun_root.txt
	log_sub_info "Running GF Patterns..."
	cat $RECON_DIR/urls/final.txt | gf xss | anew $RECON_DIR/urls/gf_xss.txt
}

# --- Phase 12: Vulnerability Scanning & Template-Based Testing ---
run_phase_12_vulnerability_scanning() {
	log_info "Phase 12: Running Vulnerability Scanning..."
	log_sub_info "Running Nuclei Templates..."
	nuclei -l $RECON_DIR/hosts/live.txt -t ~/nuclei-templates/ -s critical,high,medium -o $RECON_DIR/scans/nuclei.txt
	log_sub_info "Running Nuclei CVE Scan..."
	nuclei -l $RECON_DIR/hosts/live.txt -t ~/nuclei-templates/cves/ -s critical,high -o $RECON_DIR/scans/nuclei_cves.txt
	log_sub_info "Running testssl.sh..."
	testssl.sh --parallel --html --outdir $RECON_DIR/scans/testssl/ apilchand.com.np
}


# --- Main Execution ---
main() {
    log_info "Starting reconnaissance workflow for: $TARGET"
    
    log_sub_info "Setting up directory structure..."
    mkdir -p "$TARGET"
    for dir in info subdomains hosts urls scans screenshots scans/nmap scans/sqlmap scans/testssl; do mkdir -p "$RECON_DIR/$dir"; done

    run_phase_01_domain_intel
    run_phase_02_subdomain_discovery
    run_phase_03_live_host_probing
    run_phase_04_visual_recon
    run_phase_05_port_scanning
    run_phase_06_url_harvesting
    run_phase_09_parameter_hunting
    run_phase_12_vulnerability_scanning

    log_info "\e[1;32mReconnaissance workflow finished for $TARGET!\e[0m"
    echo -e "[+] All results are stored in the '$TARGET/' directory."
}

main "$@"
