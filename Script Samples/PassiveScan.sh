#!/bin/bash
# --- BountyScope Automation Script ---
# Target: apilchand.com.np
# Generated: 2025-08-30T05:58:59.667Z
# Selected Tools: 8
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


# --- Main Execution ---
main() {
    log_info "Starting reconnaissance workflow for: $TARGET"
    
    log_sub_info "Setting up directory structure..."
    mkdir -p "$TARGET"
    for dir in info subdomains hosts urls scans screenshots scans/nmap scans/sqlmap scans/testssl; do mkdir -p "$RECON_DIR/$dir"; done

    run_phase_01_domain_intel
    run_phase_02_subdomain_discovery

    log_info "\e[1;32mReconnaissance workflow finished for $TARGET!\e[0m"
    echo -e "[+] All results are stored in the '$TARGET/' directory."
}

main "$@"
