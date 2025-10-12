import os
import re
import requests
from pathlib import Path

IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"
CACHE_PATH = Path("tools/oui.txt")

def download_oui(url=IEEE_OUI_URL, outpath=CACHE_PATH, force=False):
    outpath.parent.mkdir(parents=True, exist_ok=True)
    if outpath.exists() and not force:
        print(f"Using cached OUI file at {outpath}")
        return outpath
    print("Downloading OUI file from IEEE...")
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    outpath.write_text(r.text, encoding="utf-8")
    print("Saved OUI file to", outpath)
    return outpath

def parse_oui_file(path):
    """
    Parse IEEE oui.txt format lines like:
    00-00-00   (hex)        XEROX CORPORATION
    Returns dict: {'000000': 'XEROX CORPORATION', ...}
    """
    text = Path(path).read_text(encoding="utf-8", errors="ignore")
    mapping = {}
    # regexp: prefix, then (hex), then spaces, then vendor
    pattern = re.compile(r"^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$", re.MULTILINE)
    for m in pattern.finditer(text):
        prefix = m.group(1).replace('-', '').lower()  # '000000'
        vendor = m.group(2).strip()
        mapping[prefix] = vendor
    return mapping

def load_oui(mapping_path=None, force_download=False):
    path = download_oui(outpath=Path(mapping_path) if mapping_path else CACHE_PATH, force=force_download)
    mapping = parse_oui_file(path)
    return mapping

def normalize_mac(mac):
    if not mac:
        return None
    m = mac.strip().lower()
    # remove separators
    m = re.sub(r'[^0-9a-f]', '', m)
    if len(m) != 12:
        return None
    return m

def lookup_oui(mac, mapping):
    nm = normalize_mac(mac)
    if not nm:
        return None
    prefix = nm[:6]
    return mapping.get(prefix)

# --- példa használat ---
# if __name__ == "__main__":
#     mapping = load_oui()    # letölti (ha kell) és beolvassa
#     print("Loaded OUI entries:", len(mapping))
#     tests = ["00:00:00:00:00:00", "b8:27:eb:aa:bb:cc"]  # 00:00:00 -> Xerox, b8:27:eb -> Raspberry Pi
#     for t in tests:
#         print(t, "->", lookup_oui(t, mapping))
