#!/usr/bin/env bash
set -euo pipefail

# ─── Colors & Helpers ─────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

STEP_TOTAL=7
step_start=0

ok()      { echo -e "  ${GREEN}✔${RESET}  $1"; }
skip()    { echo -e "  ${DIM}–  $1 (already installed)${RESET}"; }
miss()    { echo -e "  ${RED}✘${RESET}  $1"; }
info()    { echo -e "  ${YELLOW}→${RESET}  $1"; }
xfail()   { echo -e "  ${RED}✘  FAILED: $1${RESET}"; }
section() {
  local n="$1" title="$2"
  echo ""
  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo -e "${BOLD} Step ${n}/${STEP_TOTAL} — ${title}${RESET}"
  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  step_start=$SECONDS
}
step_done() {
  local elapsed=$(( SECONDS - step_start ))
  echo -e "  ${DIM}Completed in ${elapsed}s${RESET}"
}

PIP_EXTRA=""
PYVER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
if [ -f "/usr/lib/python${PYVER}/EXTERNALLY-MANAGED" ]; then
  PIP_EXTRA="--break-system-packages"
fi

# ─── Distro Detection ─────────────────────────────────────────────────────────
DISTRO="unknown"
if command -v apt-get &>/dev/null && command -v dpkg-query &>/dev/null; then
  DISTRO="debian"
elif command -v pacman &>/dev/null; then
  DISTRO="arch"
fi

AUR_CMD=""
if [ "$DISTRO" = "arch" ]; then
  if command -v yay &>/dev/null; then AUR_CMD="yay"
  elif command -v paru &>/dev/null; then AUR_CMD="paru"
  fi
fi
pip_pkg() {
  local pkg="$1"
  local base; base="${pkg%%[>=<!]*}"
  if python3 -m pip show "$base" &>/dev/null 2>&1; then
    skip "$base"
  else
    info "pip install $base"
    python3 -m pip install --quiet --upgrade-strategy only-if-needed $PIP_EXTRA "$pkg" \
      && ok "$base" || xfail "$base"
  fi
}

# ─── Banner ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${CYAN}║         CTF SLOPER — Tool Installer v2           ║${RESET}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════╝${RESET}"
echo -e "  ${DIM}$(date)${RESET}"
echo -e "  ${DIM}Distro: ${DISTRO}${RESET}"
if [ "$DISTRO" = "arch" ]; then
  if [ -n "$AUR_CMD" ]; then
    echo -e "  ${DIM}AUR helper: ${AUR_CMD}${RESET}"
  else
    echo -e "  ${YELLOW}→  No AUR helper (yay/paru) found — AUR packages will be skipped${RESET}"
    echo -e "  ${DIM}  Install yay: git clone https://aur.archlinux.org/yay.git && cd yay && makepkg -si${RESET}"
  fi
fi

info "Syntax-checking app.py..."
timeout 45 python3 -m py_compile app.py \
  && ok "app.py syntax OK" \
  || { xfail "app.py has syntax errors — aborting"; exit 1; }

# ─── Step 1 ───────────────────────────────────────────────────────────────────
section "1" "Checking sudo"
if command -v sudo >/dev/null 2>&1; then
  ok "sudo at $(command -v sudo)"
else
  xfail "sudo not found — run as root or install sudo first"; exit 1
fi
step_done

# ─── Step 2 ───────────────────────────────────────────────────────────────────
section "2" "System packages"

if [ "$DISTRO" = "debian" ]; then
  info "Writing fast-apt config..."
  sudo bash -c 'cat > /etc/apt/apt.conf.d/99ctf-fast <<EOF
Acquire::Queue-Mode "host";
Acquire::http::Timeout "30";
Acquire::https::Timeout "30";
Acquire::Retries "3";
APT::Install-Recommends "false";
APT::Install-Suggests "false";
EOF'

  info "Running apt-get update..."
  sudo apt-get update -q
  export DEBIAN_FRONTEND=noninteractive

  apt_group() {
    local label="$1"; shift
    echo ""
    echo -e "  ${CYAN}▸ ${label}${RESET}"
    for pkg in "$@"; do
      if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
        skip "$pkg"
      else
        info "apt install $pkg"
        sudo apt-get install -y -q "$pkg" 2>&1 \
          | grep -E "^(Get:|Unpacking|Setting up)" | sed 's/^/        /' || true
        ok "$pkg"
      fi
    done
  }

  apt_group "Python"          python3 python3-pip python3-dev python3-setuptools python3-wheel
  apt_group "Build tools"     build-essential cmake make gcc g++ git curl wget unzip zip p7zip-full p7zip-rar unrar-free
  apt_group "Binary / Debug"  file binutils binutils-multiarch gdb ltrace strace patchelf elfutils checksec
  apt_group "Forensics"       binwalk foremost sleuthkit bulk-extractor exiftool steghide outguess
  apt_group "Media"           imagemagick ffmpeg sox libimage-exiftool-perl tesseract-ocr tesseract-ocr-lit tesseract-ocr-eng zbar-tools
  apt_group "Network"         tshark tcpdump wireshark-common netcat-openbsd nmap
  apt_group "PDF / Docs"      poppler-utils qpdf mupdf-tools
  apt_group "Utils"           sqlite3 jq ripgrep tree xxd bsdmainutils dos2unix
  apt_group "Ruby"            ruby ruby-dev gem
  apt_group "Java / Android"  apktool jadx default-jdk
  apt_group "Node.js"         nodejs npm
  apt_group "Dev libs"        libssl-dev libffi-dev libmagic-dev libzbar0 libjpeg-dev zlib1g-dev libbz2-dev liblzma-dev

elif [ "$DISTRO" = "arch" ]; then
  info "Running pacman -Sy..."
  sudo pacman -Sy --noconfirm

  pac_installed() { pacman -Q "$1" &>/dev/null 2>&1; }

  pacman_group() {
    local label="$1"; shift
    echo ""
    echo -e "  ${CYAN}▸ ${label}${RESET}"
    for pkg in "$@"; do
      if pac_installed "$pkg"; then
        skip "$pkg"
      else
        info "pacman -S $pkg"
        sudo pacman -S --noconfirm --needed "$pkg" 2>&1 \
          | grep -E "^(Packages|downloading|installing|upgrading|resolving)" \
          | sed 's/^/        /' || true
        if pac_installed "$pkg"; then ok "$pkg"; else xfail "$pkg"; fi
      fi
    done
  }

  arch_aur_group() {
    local label="$1"; shift
    if [ -z "$AUR_CMD" ]; then
      echo -e "  ${YELLOW}→  Skipping '${label}' — no AUR helper (install yay or paru)${RESET}"
      return
    fi
    echo ""
    echo -e "  ${CYAN}▸ ${label} (AUR)${RESET}"
    for pkg in "$@"; do
      if pac_installed "$pkg"; then
        skip "$pkg"
      else
        info "$AUR_CMD -S $pkg"
        "$AUR_CMD" -S --noconfirm --needed "$pkg" 2>&1 \
          | grep -E "^(Packages|downloading|installing|upgrading|resolving)" \
          | sed 's/^/        /' || true
        if pac_installed "$pkg"; then ok "$pkg"; else xfail "$pkg"; fi
      fi
    done
  }

  pacman_group "Python"         python python-pip python-setuptools python-wheel
  pacman_group "Build tools"    base-devel cmake make git curl wget unzip zip p7zip
  pacman_group "Binary / Debug" binutils gdb ltrace strace patchelf elfutils checksec
  pacman_group "Forensics"      binwalk sleuth-kit perl-image-exiftool
  pacman_group "Media"          imagemagick ffmpeg sox tesseract tesseract-data-eng zbar
  pacman_group "Network"        wireshark-cli tcpdump nmap openbsd-netcat
  pacman_group "PDF / Docs"     poppler qpdf mupdf
  pacman_group "Utils"          sqlite jq ripgrep tree xxd dos2unix unrar
  pacman_group "Ruby"           ruby
  pacman_group "Java"           jdk-openjdk
  pacman_group "Node.js"        nodejs npm
  pacman_group "Dev libs"       openssl libffi file zbar libjpeg-turbo zlib bzip2 xz

  arch_aur_group "Forensics (AUR)"  foremost bulk_extractor steghide outguess
  arch_aur_group "Android (AUR)"    apktool jadx

  # tesseract language data (try pacman first, then AUR)
  pacman_group "Tesseract LIT"  tesseract-data-lit || true

else
  echo -e "  ${YELLOW}→  Unknown or unsupported distro — skipping system package installation${RESET}"
  echo -e "  ${YELLOW}→  Please manually install: binwalk exiftool steghide binutils gdb python3 nodejs ruby${RESET}"
fi
step_done

# ─── Step 3 ───────────────────────────────────────────────────────────────────
section "3" "Python CTF libraries"
info "Upgrading pip / setuptools / wheel..."
python3 -m pip install --upgrade pip setuptools wheel -q $PIP_EXTRA
ok "pip $(python3 -m pip --version | awk '{print $2}')"
echo -e "  ${DIM}Skipping packages already installed${RESET}"

echo -e "\n  ${CYAN}▸ Web / API${RESET}"
for p in fastapi uvicorn python-multipart aiofiles jinja2; do pip_pkg "$p"; done

echo -e "\n  ${CYAN}▸ Image / Vision${RESET}"
for p in pillow numpy scipy scikit-image imageio opencv-python-headless matplotlib networkx; do pip_pkg "$p"; done

echo -e "\n  ${CYAN}▸ Crypto / Math${RESET}"
for p in pycryptodome cryptography sympy z3-solver gmpy2; do pip_pkg "$p"; done

echo -e "\n  ${CYAN}▸ Network / Packets${RESET}"
for p in scapy dpkt pyshark construct kaitaistruct; do pip_pkg "$p"; done

echo -e "\n  ${CYAN}▸ Binary / RE${RESET}"
for p in pwntools capstone unicorn ropper ROPGadget lief pefile python-magic yara-python; do pip_pkg "$p"; done

echo -e "\n  ${CYAN}▸ Web scraping${RESET}"
for p in pyjwt requests beautifulsoup4 lxml html5lib; do pip_pkg "$p"; done

echo -e "\n  ${CYAN}▸ PDF${RESET}"
for p in pypdf pdfplumber pymupdf; do pip_pkg "$p"; done

echo -e "\n  ${CYAN}▸ Archives${RESET}"
for p in py7zr rarfile zstandard lz4 brotli; do pip_pkg "$p"; done

echo -e "\n  ${CYAN}▸ Stego${RESET}"
for p in stegano bitstring bitarray; do pip_pkg "$p"; done

echo -e "\n  ${CYAN}▸ Office / Docs${RESET}"
for p in oletools python-docx openpyxl; do pip_pkg "$p"; done

echo -e "\n  ${CYAN}▸ Memory Forensics${RESET}"
pip_pkg volatility3

echo -e "\n  ${CYAN}▸ UI / Output${RESET}"
for p in rich textual tqdm colorama; do pip_pkg "$p"; done

echo -e "\n  ${CYAN}▸ Decompilers${RESET}"
for p in decompyle3 uncompyle6 xdis; do pip_pkg "$p"; done

step_done

# ─── Step 4 ───────────────────────────────────────────────────────────────────
section "4" "Ruby stego tools"
if gem list -i zsteg &>/dev/null 2>&1; then
  skip "zsteg"
else
  info "gem install zsteg"
  sudo gem install zsteg && ok "zsteg" || xfail "zsteg"
fi
step_done

# ─── Step 5 ───────────────────────────────────────────────────────────────────
section "5" "Node.js helpers"
for pkg in jwt-cli js-beautify prettier; do
  if npm list -g "$pkg" --depth=0 &>/dev/null 2>&1; then
    skip "$pkg"
  else
    info "npm install -g $pkg"
    sudo npm install -g "$pkg" && ok "$pkg" || xfail "$pkg"
  fi
done
step_done

# ─── Step 6 ───────────────────────────────────────────────────────────────────
section "6" "GitHub CTF tools"
mkdir -p local_tools
cd local_tools

clone_or_pull() {
  local repo="$1" dir="$2"
  if [ ! -d "$dir" ]; then
    info "Cloning $dir..."
    git clone --depth 1 --progress "$repo" "$dir" 2>&1 \
      | grep -E "^(Cloning|Receiving|Resolving)" | sed 's/^/        /' || true
    ok "$dir cloned"
  else
    info "Pulling $dir..."
    local out; out=$(git -C "$dir" pull --ff-only 2>&1)
    echo "$out" | sed 's/^/        /'
    ok "$dir up to date"
  fi
}

echo ""
echo -e "  ${CYAN}▸ RsaCtfTool${RESET}"
clone_or_pull https://github.com/RsaCtfTool/RsaCtfTool.git RsaCtfTool
if [ -d RsaCtfTool ]; then
  info "Installing RsaCtfTool requirements..."
  python3 -m pip install -q --upgrade-strategy only-if-needed $PIP_EXTRA \
    -r RsaCtfTool/requirements.txt && ok "RsaCtfTool deps" || xfail "RsaCtfTool deps"
fi

echo -e "\n  ${CYAN}▸ Ciphey${RESET}"
clone_or_pull https://github.com/Ciphey/Ciphey.git Ciphey
if [ -d Ciphey ]; then
  info "Installing Ciphey..."
  python3 -m pip install -q --upgrade-strategy only-if-needed $PIP_EXTRA \
    ./Ciphey && ok "Ciphey" || xfail "Ciphey"
fi

echo -e "\n  ${CYAN}▸ stegseek${RESET}"
clone_or_pull https://github.com/RickdeJager/stegseek.git stegseek

cd ..
step_done

# ─── Step 7 ───────────────────────────────────────────────────────────────────
section "7" "Verifying installed commands"
pass=0; fail_count=0
for c in file strings binwalk foremost exiftool steghide zsteg zbarimg tesseract \
         tshark tcpdump ffmpeg sox qpdf pdftotext pdfimages readelf objdump gdb python3; do
  if command -v "$c" >/dev/null 2>&1; then
    ok "$c  ${DIM}$(command -v "$c")${RESET}"
    (( pass++ )) || true
  else
    miss "$c"
    (( fail_count++ )) || true
  fi
done
echo ""
echo -e "  ${GREEN}${pass} present${RESET}  /  ${RED}${fail_count} missing${RESET}"
step_done

# ─── Summary ──────────────────────────────────────────────────────────────────
TOTAL=$SECONDS
echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════╗${RESET}"
printf "${BOLD}${CYAN}║  All done!  Total time: %-26s║${RESET}\n" "${TOTAL}s"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${BOLD}bash START_HERE.sh${RESET}"
echo ""
