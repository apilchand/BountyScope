#!/bin/bash
# --- BountyScope Automation Script ---
# Target: apilchand.com.np
# Generated: 2025-08-30T05:59:46.748Z
# Selected Tools: 10
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


# --- Main Execution ---
main() {
    log_info "Starting reconnaissance workflow for: $TARGET"
    
    log_sub_info "Setting up directory structure..."
    mkdir -p "$TARGET"
    for dir in info subdomains hosts urls scans screenshots scans/nmap scans/sqlmap scans/testssl; do mkdir -p "$RECON_DIR/$dir"; done

    run_phase_02_subdomain_discovery
    run_phase_03_live_host_probing
    run_phase_04_visual_recon

    log_info "\e[1;32mReconnaissance workflow finished for $TARGET!\e[0m"
    echo -e "[+] All results are stored in the '$TARGET/' directory."
}

main "$@"
