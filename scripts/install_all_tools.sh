#!/usr/bin/env bash
set -euo pipefail
echo "[CTF SLOPER] Python syntax self-check..."
timeout 45 python3 -m py_compile app.py || { echo "[CTF SLOPER] app.py syntax error"; exit 1; }
echo "[CTF SLOPER] app.py syntax OK."

echo "[1/8] Checking sudo..."
if ! command -v sudo >/dev/null 2>&1; then
  echo "sudo not found. Run this script as root or install sudo first."
  exit 1
fi

echo "[2/8] Installing Debian/Ubuntu packages..."
sudo bash -lc 'export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y \
  python3 python3-pip python3-venv python3-dev python3-setuptools python3-wheel \
  build-essential cmake make gcc g++ git curl wget unzip zip p7zip-full p7zip-rar unrar-free \
  file binutils binutils-multiarch gdb ltrace strace patchelf elfutils checksec \
  binwalk foremost sleuthkit bulk-extractor exiftool steghide outguess \
  imagemagick ffmpeg sox libimage-exiftool-perl \
  tesseract-ocr tesseract-ocr-lit tesseract-ocr-eng zbar-tools \
  tshark tcpdump wireshark-common netcat-openbsd nmap \
  poppler-utils qpdf mupdf-tools \
  sqlite3 jq ripgrep tree xxd bsdmainutils dos2unix \
  ruby ruby-dev gem \
  apktool jadx default-jdk \
  nodejs npm \
  libssl-dev libffi-dev libmagic-dev libzbar0 libjpeg-dev zlib1g-dev libbz2-dev liblzma-dev \
  || true'

echo "[3/8] Creating Python virtualenv..."
python3 -m venv .venv || {
  echo "python3-venv missing. Trying to install python3-venv..."
  sudo apt-get install -y python3-venv
  python3 -m venv .venv
}
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel

echo "[4/8] Installing Python CTF libraries..."
python -m pip install --upgrade \
  fastapi uvicorn python-multipart aiofiles jinja2 \
  pillow numpy scipy scikit-image imageio opencv-python-headless matplotlib networkx \
  pycryptodome cryptography sympy z3-solver gmpy2 \
  scapy dpkt pyshark construct kaitaistruct \
  pwntools capstone unicorn ropper ROPGadget lief pefile python-magic yara-python \
  pyjwt requests beautifulsoup4 lxml html5lib \
  pypdf pdfplumber pymupdf \
  py7zr rarfile zstandard lz4 brotli \
  stegano bitstring bitarray \
  oletools python-docx openpyxl \
  volatility3 \
  rich textual tqdm colorama \
  decompyle3 uncompyle6 xdis || true

echo "[5/8] Installing Ruby stego tools..."
sudo gem install zsteg || true

echo "[6/8] Installing Node helpers..."
sudo npm install -g jwt-cli js-beautify prettier || true

echo "[7/8] Optional GitHub CTF tools..."
mkdir -p local_tools
cd local_tools

if [ ! -d RsaCtfTool ]; then
  git clone --depth 1 https://github.com/RsaCtfTool/RsaCtfTool.git || true
fi
if [ -d RsaCtfTool ]; then
  ../.venv/bin/python -m pip install -r RsaCtfTool/requirements.txt || true
fi

if [ ! -d Ciphey ]; then
  git clone --depth 1 https://github.com/Ciphey/Ciphey.git || true
fi
if [ -d Ciphey ]; then
  ../.venv/bin/python -m pip install ./Ciphey || true
fi

if [ ! -d stegseek ]; then
  git clone --depth 1 https://github.com/RickdeJager/stegseek.git || true
fi

cd ..

echo "[8/8] Verifying common commands..."
for c in file strings binwalk foremost exiftool steghide zsteg zbarimg tesseract tshark tcpdump ffmpeg sox qpdf pdftotext pdfimages readelf objdump gdb python3; do
  if command -v "$c" >/dev/null 2>&1; then
    echo "OK  $c -> $(command -v "$c")"
  else
    echo "MISS $c"
  fi
done

echo
echo "Done. Start the app with:"
echo "  source .venv/bin/activate"
echo "  bash START_HERE.sh"
