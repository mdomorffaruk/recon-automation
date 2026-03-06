#!/usr/bin/env bash
set -euo pipefail

# -----------------------------
# Config (edit these)
# -----------------------------
WORDLIST="${WORDLIST:-/home/billi/seclists/Discovery/DNS/subdomains-top1million-20000.txt}"
FEROX_WORDLIST="${FEROX_WORDLIST:-/home/billi/seclists/Discovery/Web-Content/raft-small-files.txt}"

HTTPX_RL="${HTTPX_RL:-30}"          # requests/sec (httpx)
DNS_RL="${DNS_RL:-50}"              # requests/sec (subfinder/dnsx)
NUCLEI_RL="${NUCLEI_RL:-20}"        # requests/sec (nuclei)
KATANA_RL="${KATANA_RL:-10}"        # requests/sec (katana)
NAABU_RATE="${NAABU_RATE:-2000}"    # packets/sec (naabu) - not "requests/sec"

PARALLEL="${PARALLEL:-6}"           # parallel workers for loops (waf/ferox)
FEROX_THREADS="${FEROX_THREADS:-8}" # per-target threads
FEROX_DEPTH="${FEROX_DEPTH:-2}"

USER_AGENT="${USER_AGENT:-Mozilla/5.0 (X11; Linux x86_64) recon}"
TIMEOUT="${TIMEOUT:-10}"

# -----------------------------
# Colors
# -----------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

# -----------------------------
# Helpers
# -----------------------------
die(){ echo -e "${RED}[!] $*${NC}" >&2; exit 1; }

need_cmd(){
  command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1"
}

banner(){ echo -e "${BLUE}[*]${NC} $*"; }
ok(){ echo -e "${GREEN}[+]${NC} $*"; }
warn(){ echo -e "${YELLOW}[!]${NC} $*"; }

sanitize_host(){
  # convert https://a.b:443/path -> a.b_443
  echo "$1" | sed -E 's#^https?://##; s#/$##; s#[/:]#_#g'
}

# -----------------------------
# Args
# -----------------------------
[[ ${1:-} ]] || die "Usage: $0 <domain>  (example: $0 example.com)"
DOMAIN="$1"

DATE="$(date +%Y-%m-%d)"
STAMP="$(date +%Y%m%d_%H%M%S)"
BASE_DIR="${DOMAIN}_recon_${DATE}_${STAMP}"

mkdir -p "$BASE_DIR"
cd "$BASE_DIR"

# Logging: everything to file + console
exec > >(tee -a run.log) 2>&1

banner "Starting recon for: ${YELLOW}${DOMAIN}${NC}"
banner "Output: ${YELLOW}${BASE_DIR}${NC}"

# -----------------------------
# Dependency checks
# -----------------------------
need_cmd subfinder
need_cmd amass
need_cmd dnsx
need_cmd httpx
need_cmd naabu
need_cmd nuclei
need_cmd katana
need_cmd feroxbuster
need_cmd wafw00f
need_cmd sort
need_cmd uniq
need_cmd xargs

# -----------------------------
# Folder structure
# -----------------------------
mkdir -p 00_inputs 01_subdomains 02_httpx 03_waf 04_ports 05_content 06_nuclei 07_katana

# Save configs used
cat > 00_inputs/config_used.txt <<EOF
DOMAIN=$DOMAIN
DATE=$DATE
HTTPX_RL=$HTTPX_RL
DNS_RL=$DNS_RL
NUCLEI_RL=$NUCLEI_RL
KATANA_RL=$KATANA_RL
NAABU_RATE=$NAABU_RATE
PARALLEL=$PARALLEL
FEROX_THREADS=$FEROX_THREADS
FEROX_DEPTH=$FEROX_DEPTH
USER_AGENT=$USER_AGENT
TIMEOUT=$TIMEOUT
WORDLIST=$WORDLIST
FEROX_WORDLIST=$FEROX_WORDLIST
EOF

# -----------------------------
# Phase 1: Subdomain enum
# -----------------------------
ok "Phase 1: Subdomain Enumeration"
banner "subfinder..."
subfinder -d "$DOMAIN" -all -silent -rl "$DNS_RL" -o 01_subdomains/subfinder.txt || true

banner "amass (passive)..."
amass enum -passive -d "$DOMAIN" -o 01_subdomains/amass.txt || true

banner "dnsx brute..."
dnsx -d "$DOMAIN" -w "$WORDLIST" -silent -rl "$DNS_RL" -o 01_subdomains/dnsx.txt || true

cat 01_subdomains/subfinder.txt 01_subdomains/amass.txt 01_subdomains/dnsx.txt 2>/dev/null \
  | sed '/^\s*$/d' \
  | sort -u > 01_subdomains/final_subdomains.txt

SUB_COUNT="$(wc -l < 01_subdomains/final_subdomains.txt | tr -d ' ')"
ok "Unique subdomains: ${SUB_COUNT}"

if [[ "$SUB_COUNT" -eq 0 ]]; then
  die "No subdomains found. Either wrong domain or tools blocked."
fi

# -----------------------------
# Phase 2: HTTP probing (CLEAN URL LIST + JSON metadata)
# -----------------------------
ok "Phase 2: Probing for alive web targets (clean outputs)"
# Clean URL list
httpx -l 01_subdomains/final_subdomains.txt \
  -silent \
  -timeout "$TIMEOUT" \
  -follow-redirects \
  -rl "$HTTPX_RL" \
  -H "User-Agent: $USER_AGENT" \
  -o 02_httpx/alive_urls.txt

# Metadata in JSON (optional but very useful)
httpx -l 01_subdomains/final_subdomains.txt \
  -silent \
  -json \
  -timeout "$TIMEOUT" \
  -follow-redirects \
  -title -tech-detect -status-code -location \
  -rl "$HTTPX_RL" \
  -H "User-Agent: $USER_AGENT" \
  -o 02_httpx/httpx.json

ALIVE_COUNT="$(wc -l < 02_httpx/alive_urls.txt | tr -d ' ')"
ok "Alive URLs: ${ALIVE_COUNT}"

if [[ "$ALIVE_COUNT" -eq 0 ]]; then
  warn "No alive web targets found. Continuing with ports on discovered hosts anyway."
fi

# Hosts list for ports/WAF
cat 01_subdomains/final_subdomains.txt | sort -u > 00_inputs/hosts_all.txt

# If you want ONLY alive hosts for some steps:
if [[ -s 02_httpx/alive_urls.txt ]]; then
  sed -E 's#^https?://##; s#/$##; s#:.*##' 02_httpx/alive_urls.txt | sort -u > 00_inputs/hosts_alive.txt
else
  : > 00_inputs/hosts_alive.txt
fi

# -----------------------------
# Phase 3: WAF detection (parallel)
# -----------------------------
ok "Phase 3: WAF Detection (parallel)"
if [[ -s 02_httpx/alive_urls.txt ]]; then
  cat 02_httpx/alive_urls.txt \
    | xargs -I{} -P "$PARALLEL" bash -c '
        url="{}"
        out="03_waf/wafw00f_$(echo "$url" | sed -E "s#^https?://##; s#/$##; s#[/:]#_#g").txt"
        wafw00f "$url" > "$out" 2>/dev/null || true
      '
  ok "WAF reports saved in 03_waf/"
else
  warn "Skipping WAF detection (no alive URLs)."
fi

# -----------------------------
# Phase 4: Port scanning (naabu)
# -----------------------------
ok "Phase 4: Port Scanning (naabu)"
# Scan all discovered hosts (better coverage); you can swap to hosts_alive.txt if you want speed.
naabu -list 00_inputs/hosts_all.txt \
  -rate "$NAABU_RATE" \
  -silent \
  -top-ports 1000 \
  -o 04_ports/naabu_top1000.txt || true

# -----------------------------
# Phase 5: Content discovery (ferox) - parallel, per-target output
# -----------------------------
ok "Phase 5: Directory / content discovery (ferox) - parallel"
if [[ -s 02_httpx/alive_urls.txt ]]; then
  # Limit to first N if you want (uncomment):
  # head -n 50 02_httpx/alive_urls.txt > 02_httpx/alive_urls_limited.txt && URLS=02_httpx/alive_urls_limited.txt
  URLS="02_httpx/alive_urls.txt"

  cat "$URLS" | xargs -I{} -P "$PARALLEL" bash -c '
    url="{}"
    safe="$(echo "$url" | sed -E "s#^https?://##; s#/$##; s#[/:]#_#g")"
    out="05_content/ferox_${safe}.txt"
    feroxbuster -u "$url" -w "'"$FEROX_WORDLIST"'" \
      --threads "'"$FEROX_THREADS"'" \
      --depth "'"$FEROX_DEPTH"'" \
      -C 404 \
      --silent \
      --auto-tune \
      --timeout 10 \
      -o "$out" >/dev/null 2>&1 || true
  '
  ok "Ferox results saved in 05_content/"
else
  warn "Skipping ferox (no alive URLs)."
fi

# -----------------------------
# Phase 6: Nuclei (high/critical only)
# -----------------------------
ok "Phase 6: Nuclei scan (high/critical)"
nuclei -ut >/dev/null 2>&1 || true

if [[ -s 02_httpx/alive_urls.txt ]]; then
  nuclei -l 02_httpx/alive_urls.txt \
    -severity critical,high \
    -rl "$NUCLEI_RL" \
    -timeout "$TIMEOUT" \
    -retries 2 \
    -H "User-Agent: $USER_AGENT" \
    -o 06_nuclei/nuclei_high_critical.txt \
    -stats || true
else
  warn "Skipping nuclei (no alive URLs)."
fi

# -----------------------------
# Phase 7: Katana crawl (only alive URLs)
# -----------------------------
ok "Phase 7: Katana crawl"
if [[ -s 02_httpx/alive_urls.txt ]]; then
  katana -list 02_httpx/alive_urls.txt \
    -silent \
    -jc \
    -aff \
    -d 3 \
    -rl "$KATANA_RL" \
    -o 07_katana/katana_urls.txt || true
else
  warn "Skipping katana (no alive URLs)."
fi

# -----------------------------
# Summary
# -----------------------------
ok "Recon completed."
banner "Key outputs:"
echo "  - Subdomains: 01_subdomains/final_subdomains.txt"
echo "  - Alive URLs: 02_httpx/alive_urls.txt"
echo "  - HTTP metadata: 02_httpx/httpx.json"
echo "  - WAF reports: 03_waf/"
echo "  - Ports: 04_ports/naabu_top1000.txt"
echo "  - Content brute: 05_content/"
echo "  - Nuclei results: 06_nuclei/nuclei_high_critical.txt"
echo "  - Katana URLs: 07_katana/katana_urls.txt"
echo
ok "Run log: run.log"
