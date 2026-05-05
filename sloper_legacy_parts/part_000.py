# Auto-split from sloper_legacy_monolith.py lines 2-...
from fastapi import FastAPI, UploadFile, File, Form, BackgroundTasks
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from typing import List, Dict, Any
import subprocess, shutil, uuid, json, re, math, base64, html, urllib.parse, zipfile, tarfile, time, threading, requests, zlib, gzip, bz2, lzma, hashlib, os, signal
from sloper_v72.lazy_imports import install_lazy_imports
install_lazy_imports(globals())
BASE = Path(__file__).parent.resolve()
PROJECTS = BASE / "projects"
PROJECTS.mkdir(exist_ok=True)
app = FastAPI(title="CTF Slayer Local v25 VerifyLoop")
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")
LOCK = threading.Lock()
JOBS: Dict[str, Dict[str, Any]] = {}
FLAG_TEXT_RE = re.compile(r"(?:ctf_cs|flag|CTF|FLAG|cyber|sprint)\{[^}\r\n]{0,240}\}", re.I)
FLAG_BYTES_RE = re.compile(rb"(?:ctf_cs|flag|CTF|FLAG|cyber|sprint)\{[^}\r\n]{0,240}\}", re.I)
CTF_CS_RE = re.compile(r"ctf_cs\{[^}\r\n]{0,240}\}", re.I)
BRACE_RE = re.compile(r"[A-Za-z0-9_\-]{0,60}\{[^}\r\n]{1,260}\}")
PARTIAL_CTF_RE = re.compile(r"ctf_cs\{[^\s\r\n]{0,260}", re.I)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def now(): return time.strftime("%Y-%m-%d %H:%M:%S")
def exists(x): return shutil.which(x) is not None
def safe(name):
    s = re.sub(r"[^A-Za-z0-9._ -]+", "_", name or "file").strip()
    s = s.replace("\\", "_").replace("/", "_").lstrip(".")
    return s[:180] or "file"
def pdir(pid): return PROJECTS / pid
def meta_path(pid): return pdir(pid) / "project.json"
def report_path(pid): return pdir(pid) / "report.json"
def jread(p, d):
    try: return json.loads(Path(p).read_text(encoding="utf-8"))
    except Exception: return d
def jwrite(p, o): Path(p).write_text(json.dumps(o, ensure_ascii=False, indent=2), encoding="utf-8")
def log(pid, msg):
    d=pdir(pid); d.mkdir(exist_ok=True)
    with (d/"events.log").open("a", encoding="utf-8") as f: f.write(f"[{now()}] {msg}\n")
    with LOCK: JOBS.setdefault(pid,{}).update({"stage":msg,"updated":time.time()})
def progress(pid,pct,stage):
    pct=max(0,min(100,int(pct)))
    with LOCK: JOBS.setdefault(pid,{}).update({"progress":pct,"stage":stage,"updated":time.time()})
    log(pid,f"{pct}% {stage}")
def run(cmd, timeout=60, maxchars=120000):
    """Early safe subprocess runner. Blocks CTF SLOPER internals before v103/v104 layers load."""
    joined = " ".join(map(str, cmd)) if isinstance(cmd, (list, tuple)) else str(cmd)
    try:
        base = Path(__file__).parent.resolve()
        internal_markers = [str(base / "data"), str(base / "static"), str(base / "sloper_v72"), str(base / "__pycache__")]
        if any(m in joined for m in internal_markers) and not any(allow in joined.lower() for allow in ["basic.yar"]):
            return {"ok":False,"code":-3,"cmd":joined,"out":"BLOCKED: refusing subprocess against CTF SLOPER internal path during startup/runtime guard"}
    except Exception:
        pass
    try:
        env=os.environ.copy(); env.setdefault("PYTHONNOUSERSITE","1")
        p=subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace", env=env, start_new_session=True)
        try:
            out,_=p.communicate(timeout=timeout)
            return {"ok":p.returncode==0, "code":p.returncode, "cmd":joined, "out":(out or "")[:maxchars]}
        except subprocess.TimeoutExpired:
            try: os.killpg(p.pid, signal.SIGKILL)
            except Exception:
                try: p.kill()
                except Exception: pass
            try: out,_=p.communicate(timeout=2)
            except Exception: out=""
            return {"ok":False,"code":-2,"cmd":joined,"out":f"TIMEOUT after {timeout}s (killed process group)\n{(out or '')[:maxchars]}"}
    except Exception as e:
        return {"ok":False,"code":-1,"cmd":joined,"out":str(e)}
def readbytes(path,n=16_000_000):
    with open(path,"rb") as f: return f.read(n)
def entropy(data):
    if not data: return 0
    c=[0]*256
    for b in data: c[b]+=1
    l=len(data)
    return round(-sum((x/l)*math.log2(x/l) for x in c if x),4)
def py_strings(data,minlen=4,limit=3200):
    out=[]; cur=[]
    for b in data:
        if 32<=b<127: cur.append(chr(b))
        else:
            if len(cur)>=minlen: out.append("".join(cur))
            cur=[]
    if len(cur)>=minlen: out.append("".join(cur))
    return out[:limit]
def score_text(s):
    if not s: return 0
    s=str(s); low=s.lower(); score=0
    if "ctf_cs{" in low: score += 240
    if "ctf_cs" in low: score += 150
    if "{" in s and "}" in s: score += 65
    elif "{" in s or "}" in s: score += 25
    for k in ["flag{","ctf{","slapta","raktas","password","key","secret","veliava","token","hidden","decode","cipher","xor","base64","admin","login","answer","winner"]:
        if k in low: score += 24
    printable=sum(1 for c in s if c.isprintable() or c in "\n\r\t")/max(1,len(s))
    letters=sum(1 for c in s if c.isalpha())/max(1,len(s))
    score += min(25,int(printable*25))+min(12,int(letters*12))
    return score
def extract_flagish_text(text):
    text=text or ""; out=[]; seen=set()
    def add(kind,val,score,why):
        val=str(val)[:900]
        if not val: return
        k=(kind,val)
        if k in seen: return
        seen.add(k); out.append({"type":kind,"value":val,"score":int(score),"why":why})
    for m in CTF_CS_RE.findall(text): add("exact_ctf_cs",m,300,"Exact target format.")
    for m in PARTIAL_CTF_RE.findall(text): add("partial_ctf_cs",m,175,"Partial ctf_cs{ fragment; inspect context.")
    for m in BRACE_RE.findall(text): add("brace_fragment",m,160 if m.lower().startswith("ctf_cs{") else 90,"Contains {...}; flags often hide inside braces.")
    for line in text.splitlines():
        if any(x in line.lower() for x in ["ctf_cs","flag","raktas","slapta","key","secret","token"]) or "{" in line or "}" in line:
            if len(line) <= 900: add("context_line",line,score_text(line),"Useful context line.")
    return sorted(out,key=lambda x:x["score"],reverse=True)[:180]
def expert_context_lines(text, max_hits=160, radius=180):
    text=text or ""; hits=[]; low=text.lower()
    for needle in ["ctf_cs","flag","{","}","raktas","slapta","key","secret","token","password","admin"]:
        start=0
        while True:
            idx=low.find(needle,start)
            if idx<0: break
            chunk=text[max(0,idx-radius):idx+radius]
            if chunk and chunk not in hits: hits.append(chunk)
            start=idx+len(needle)
            if len(hits)>=max_hits: break
        if len(hits)>=max_hits: break
    return hits[:max_hits]
def atbash(s):
    a="abcdefghijklmnopqrstuvwxyz"; A=a.upper()
    return s.translate(str.maketrans(a+A,a[::-1]+A[::-1]))
def morse_decode(s):
    table={".-":"a","-...":"b","-.-.":"c","-..":"d",".":"e","..-.":"f","--.":"g","....":"h","..":"i",".---":"j","-.-":"k",".-..":"l","--":"m","-.":"n","---":"o",".--.":"p","--.-":"q",".-.":"r","...":"s","-":"t","..-":"u","...-":"v",".--":"w","-..-":"x","-.--":"y","--..":"z","-----":"0",".----":"1","..---":"2","...--":"3","....-":"4",".....":"5","-....":"6","--...":"7","---..":"8","----.":"9"}
    s=str(s or "").replace("_","-").replace("|","/").replace("\u2014","-").replace("\u2013","-")
    if not re.fullmatch(r"[.\-/\s]+",s.strip()) or len(s)<8: return ""
    return "".join(" " if x in ["/",""] else table.get(x,"?") for x in s.replace("/"," / ").split())
def try_base58(s):
    try:
        n=0
        for ch in s.strip():
            if ch not in BASE58_ALPHABET: return None
            n=n*58+BASE58_ALPHABET.index(ch)
        b=n.to_bytes((n.bit_length()+7)//8,"big")
        pad=len(s)-len(s.lstrip("1"))
        return (b"\x00"*pad+b).decode("utf-8","replace")
    except Exception: return None
def try_ascii85(s):
    try: return base64.a85decode(s.encode(),adobe=False).decode("utf-8","replace")
    except Exception:
        try: return base64.b85decode(s.encode()).decode("utf-8","replace")
        except Exception: return None
def try_ascii_codes(s):
    try:
        nums=re.split(r"[,;:\s]+",s.strip())
        if len(nums)<4: return None
        vals=[]
        for x in nums:
            if not x: continue
            if not x.isdigit(): return None
            n=int(x)
            if n<0 or n>255: return None
            vals.append(n)
        return bytes(vals).decode("utf-8","replace")
    except Exception: return None
def try_bacon(text):
    try:
        s=re.sub(r"[^abAB01]","",text or "")
        if len(s)<10: return None
        s=s.replace("0","A").replace("1","B").upper()
        table={"AAAAA":"a","AAAAB":"b","AAABA":"c","AAABB":"d","AABAA":"e","AABAB":"f","AABBA":"g","AABBB":"h","ABAAA":"i","ABAAB":"j","ABABA":"k","ABABB":"l","ABBAA":"m","ABBAB":"n","ABBBA":"o","ABBBB":"p","BAAAA":"q","BAAAB":"r","BAABA":"s","BAABB":"t","BABAA":"u","BABAB":"v","BABBA":"w","BABBB":"x","BBAAA":"y","BBAAB":"z"}
        return "".join(table.get(s[i:i+5],"?") for i in range(0,len(s)-4,5))
    except Exception: return None
def xor_single(data):
    outs=[]; sample=data[:45000]
    for k in range(256):
        txt=bytes(b^k for b in sample).decode("utf-8","replace")
        sc=score_text(txt)
        if sc>=50: outs.append({"type":f"xor_single_0x{k:02x}","input":"file bytes sample","output":txt[:9000],"flags":FLAG_TEXT_RE.findall(txt),"score":sc})
    return sorted(outs,key=lambda x:x["score"],reverse=True)[:30]
def repeating_xor_guesses(data):
    outs=[]; sample=data[:50000]
    keys=[b"ctf",b"ctf_cs",b"flag",b"key",b"secret",b"password",b"raktas",b"slapta",b"admin",b"xor"]
    for key in keys:
        txt=bytes(b^key[i%len(key)] for i,b in enumerate(sample)).decode("utf-8","replace")
        sc=score_text(txt)
        if sc>=50: outs.append({"type":"xor_repeating_"+key.decode("utf-8","replace"),"input":"file bytes sample","output":txt[:9000],"flags":FLAG_TEXT_RE.findall(txt),"score":sc+10})
    return sorted(outs,key=lambda x:x["score"],reverse=True)[:25]
def xor_crib_ctf_cs(data):
    outs=[]; sample=data[:70000]; crib=b"ctf_cs{"
    if len(sample)<len(crib): return outs
    for off in range(0,min(384,len(sample)-len(crib))):
        key=bytes(sample[off+i]^crib[i] for i in range(len(crib)))
        for kl in range(1,min(8,len(key)+1)):
            k=key[:kl]
            txt=bytes(b^k[i%len(k)] for i,b in enumerate(sample)).decode("utf-8","replace")
            sc=score_text(txt)
            if sc>85: outs.append({"type":"xor_crib_ctf_cs_key_"+k.hex(),"input":"file bytes + ctf_cs crib","output":txt[:10000],"flags":FLAG_TEXT_RE.findall(txt),"score":sc+45})
    return sorted(outs,key=lambda x:x["score"],reverse=True)[:25]
def try_decompress_bytes(data):
    outs=[]
    for name,fn in [("zlib",zlib.decompress),("gzip",gzip.decompress),("bz2",bz2.decompress),("lzma",lzma.decompress)]:
        try:
            raw=fn(data[:2_000_000]); txt=raw.decode("utf-8","replace")
            if score_text(txt)>22: outs.append({"type":"decompress_"+name,"input":"file bytes","output":txt[:10000],"flags":FLAG_TEXT_RE.findall(txt),"score":score_text(txt)+30})
        except Exception: pass
    return outs
def decode_candidates(text, data=b""):
    outs=[]; seen=set(); text=text or ""
    def add(t,i,o,base=0):
        if not o: return
        o=str(o)[:12000]; key=(t,o[:300])
        if key in seen: return
        seen.add(key)
        flags=FLAG_TEXT_RE.findall(o); sc=int(base)+score_text(o)+(100 if flags else 0)
        if sc>=18 or flags: outs.append({"type":t,"input":str(i)[:300],"output":o,"flags":flags,"score":sc})
    chunks=re.findall(r"[A-Za-z0-9+/=_-]{8,}|[A-Z2-7=]{8,}|[0-9a-fA-F]{8,}|(?:[01]{8}\s*){2,}|(?:[0-7]{2,3}\s+){2,}[0-7]{2,3}|(?:\d{2,3}[,\s]+){3,}\d{2,3}|(?:[.\-]{1,6}\s+){3,}[.\-]{1,6}",text)
    for raw in chunks[:1400]:
        s=raw.strip()
        try:
            if re.fullmatch(r"[A-Za-z0-9+/=_-]{8,}",s):
                padded=s+"="*((4-len(s)%4)%4)
                add("base64",s,base64.b64decode(padded,validate=False).decode("utf-8","replace"),10)
                if "-" in s or "_" in s: add("base64_urlsafe",s,base64.urlsafe_b64decode(padded).decode("utf-8","replace"),12)
        except Exception: pass
        try:
            if re.fullmatch(r"[A-Z2-7=]{8,}",s): add("base32",s,base64.b32decode(s).decode("utf-8","replace"),8)
        except Exception: pass
        try:
            b58=try_base58(s)
            if b58 and score_text(b58)>18: add("base58",s,b58,12)
        except Exception: pass
        try:
            a85=try_ascii85(s)
            if a85 and score_text(a85)>18: add("base85_ascii85",s,a85,12)
        except Exception: pass
        try:
            h=re.sub(r"\s+","",s)
            if len(h)%2==0 and re.fullmatch(r"[0-9a-fA-F]{8,}",h): add("hex",s,bytes.fromhex(h).decode("utf-8","replace"),10)
        except Exception: pass
        try:
            bits=re.sub(r"\s+","",s)
            if len(bits)%8==0 and re.fullmatch(r"[01]{16,}",bits): add("binary",s,bytes(int(bits[i:i+8],2) for i in range(0,len(bits),8)).decode("utf-8","replace"),10)
        except Exception: pass
        try:
            parts=s.split()
            if len(parts)>2 and all(re.fullmatch(r"[0-7]{2,3}",x) for x in parts):
                vals=[int(x,8) for x in parts]
                if all(0 <= v <= 255 for v in vals):
                    add("octal",s,bytes(vals).decode("utf-8","replace"),10)
        except Exception: pass
        try:
            ac=try_ascii_codes(s)
            if ac and score_text(ac)>18: add("ascii_codes",s,ac,14)
        except Exception: pass
        try:
            md=morse_decode(s)
            if md: add("morse",s,md,10)
        except Exception: pass
    add("url_decode","visible",urllib.parse.unquote(text[:12000]),8)
    add("html_unescape","visible",html.unescape(text[:12000]),8)
    add("atbash","visible",atbash(text[:12000]),8)
    add("reverse_text","visible",text[:12000][::-1],8)
    bacon=try_bacon(text)
    if bacon and score_text(bacon)>18: add("bacon_ab","visible",bacon,15)
    a="abcdefghijklmnopqrstuvwxyz"; A=a.upper()
    for r in range(1,26): add(f"rot{r}","visible",text[:12000].translate(str.maketrans(a+A,a[r:]+a[:r]+A[r:]+A[:r])),6)
    for hit in extract_flagish_text(text): add(hit["type"],"flag/brace hunter",hit["value"],hit["score"])
    for ctx in expert_context_lines(text)[:100]: add("context_near_flag_or_brace","context hunter",ctx,18)
    if data:
        outs+=xor_single(data)+repeating_xor_guesses(data)+try_decompress_bytes(data)+xor_crib_ctf_cs(data)
    return sorted(outs,key=lambda x:x.get("score",0),reverse=True)[:520]
def recursive_decode_seed(text,max_rounds=3):
    results=[]; seen=set(); frontier=[("input",text[:18000])]
    for depth in range(max_rounds):
        new=[]
        for label,val in frontier:
            key=(label,val[:300])
            if key in seen: continue
            seen.add(key)
            for item in decode_candidates(val,b"")[:40]:
                out=item.get("output","")
                item=dict(item); item["type"]=f"{label}->{item['type']}"; item["score"]=item.get("score",0)+depth*8
                results.append(item)
                if out and score_text(out)>30: new.append((item["type"],out))
        frontier=new[:30]
    return sorted(results,key=lambda x:x.get("score",0),reverse=True)[:200]
def detect_kind(path,fileout):
    n=path.name.lower(); f=(fileout or "").lower()
    if any(n.endswith(e) for e in [".png",".jpg",".jpeg",".bmp",".gif",".webp",".tif",".tiff"]) or "image" in f: return "image"
    if any(n.endswith(e) for e in [".pcap",".pcapng",".cap"]) or "capture file" in f or "tcpdump" in f: return "pcap"
    if n.endswith(".pdf") or "pdf document" in f: return "pdf"
    if any(n.endswith(e) for e in [".zip",".7z",".rar",".tar",".gz",".tgz",".bz2",".xz"]): return "archive"
    if any(n.endswith(e) for e in [".wav",".mp3",".flac",".ogg",".m4a",".mp4",".avi",".mov"]) or "audio" in f or "media" in f: return "media"
    if "elf" in f or "pe32" in f or any(n.endswith(e) for e in [".elf",".exe",".dll",".so",".bin"]): return "binary"
    if any(n.endswith(e) for e in [".sqlite",".db",".sqlite3"]): return "sqlite"
    if any(n.endswith(e) for e in [".apk",".dex",".jar"]): return "apk"
    if any(n.endswith(e) for e in [".pyc",".pyo"]): return "python_bytecode"
    if any(n.endswith(e) for e in [".txt",".py",".js",".json",".xml",".html",".csv",".log",".md",".css",".yaml",".yml"]): return "text"
    return "generic"
def extract_archive(path,outdir):
    made=[]
    try:
        d=outdir/(path.stem+"_extracted"); d.mkdir(exist_ok=True)
        base=d.resolve()
        def safe_member_dest(name):
            dest=(d/name).resolve()
            try:
                dest.relative_to(base)
                return dest
            except Exception:
                return None
        if path.suffix.lower()==".zip":
            with zipfile.ZipFile(path) as z:
                for member in z.infolist():
                    mode = (member.external_attr >> 16) & 0o170000
                    if mode == 0o120000:
                        continue
                    if safe_member_dest(member.filename) is not None:
                        z.extract(member, d)
                made.append(str(d))
        elif path.suffix.lower() in [".tar",".gz",".tgz",".bz2",".xz"]:
            with tarfile.open(path) as t:
                for member in t.getmembers():
                    if member.issym() or member.islnk() or member.isdev():
                        continue
                    if safe_member_dest(member.name) is not None:
                        t.extract(member, d)
                made.append(str(d))
        elif exists("7z") and path.suffix.lower() in [".7z",".rar"]:
            run(["7z","x",str(path),"-o"+str(d),"-y"],120); made.append(str(d))
    except Exception as e: made.append("extract failed: "+str(e))
    return made
def ocr_path(path):
    if not exists("tesseract"): return ""
    return run(["tesseract",str(path),"stdout"],50,18000).get("out","")
def qr_path(path):
    if not exists("zbarimg"): return ""
    return run(["zbarimg",str(path)],40,18000).get("out","")
def score_visual(name,ocr,qr):
    txt=(ocr or "")+"\n"+(qr or "")
    sc=score_text(txt)+(35 if (qr or "").strip() else 0)+(15 if (ocr or "").strip() else 0)
    if any(x in name.lower() for x in ["bitplane","lsb","invert","contrast","edges"]): sc+=5
    flags=FLAG_TEXT_RE.findall(txt)
    if flags: sc+=100
    return sc,flags
def image_lab(path,root):
    previews=[]; outputs=[]
    try:
        im=Image.open(path).convert("RGB")
        lab=root/"generated"/"image_lab"/path.stem; lab.mkdir(parents=True,exist_ok=True)
        saved=[]
        def save(name,img):
            p=lab/(name+".png"); img.save(p); saved.append((name,p))
        thumb=im.copy(); thumb.thumbnail((1400,1000)); save("00_preview",thumb)
        for name,img in [("grayscale",ImageOps.grayscale(im)),("invert",ImageOps.invert(im)),("autocontrast",ImageOps.autocontrast(im)),("edges",im.filter(ImageFilter.FIND_EDGES)),("sharpen",im.filter(ImageFilter.SHARPEN)),("emboss",im.filter(ImageFilter.EMBOSS))]: save(name,img)
        for f in [2,4,8,16]: save(f"contrast_x{f}",ImageEnhance.Contrast(im).enhance(f))
        for f in [0.5,2,4]: save(f"brightness_x{str(f).replace('.','_')}",ImageEnhance.Brightness(im).enhance(f))
        arr=np.array(im)
        for idx,ch in enumerate("RGB"):
            chan=arr[:,:,idx]; save(f"channel_{ch}",Image.fromarray(chan))
            for b in range(8): save(f"bitplane_{ch}_{b}",Image.fromarray(((chan>>b)&1).astype(np.uint8)*255))
        for order in ["RGB","BGR"]:
            bits=[]; idxs=["RGB".index(c) for c in order]
            for pix in arr.reshape(-1,3)[:600000]:
                for idx in idxs: bits.append(str(pix[idx]&1))
            bs=[int("".join(bits[i:i+8]),2) for i in range(0,len(bits)-7,8)]
            txt=bytes(bs).decode("utf-8","replace")
            outputs.append({"tool":f"LSB text attempt {order}","ok":True,"cmd":"internal LSB extractor","out":txt[:26000]})
        for name,p in saved:
            ocr=ocr_path(p); qr=qr_path(p); sc,flags=score_visual(name,ocr,qr)
            previews.append({"name":name,"url":"/api/raw?path="+str(p),"path":str(p),"score":sc,"ocr":ocr[:6000],"qr":qr[:6000],"flags":flags})
        previews=sorted(previews,key=lambda x:x.get("score",0),reverse=True)
        top="\n\n".join([f"## {v['name']} score={v['score']}\nQR:\n{v.get('qr','')}\nOCR:\n{v.get('ocr','')}" for v in previews[:18] if v.get("ocr") or v.get("qr")])
        if top: outputs.append({"tool":"auto OCR/QR over image filters","ok":True,"cmd":"internal OCR/QR ranker","out":top[:36000]})
    except Exception as e: outputs.append({"tool":"image_lab","ok":False,"cmd":"internal image lab","out":str(e)})
    return previews,outputs
def make_cmd(t,path): return [x.format(p=str(path),parent=str(path.parent),base=str(BASE)) for x in t]
PIPE={
"common":[("file",["file","{p}"],20),("sha256sum",["sha256sum","{p}"],20),("md5sum",["md5sum","{p}"],20),("xxd head",["xxd","-l","16000","{p}"],20),("exiftool",["exiftool","{p}"],35),("binwalk",["binwalk","{p}"],60),("yara basic",["yara","-w","{base}/data/basic.yar","{p}"],35)],
"image":[("identify",["identify","-verbose","{p}"],45),("pngcheck",["pngcheck","-v","{p}"],35),("zsteg",["zsteg","-a","{p}"],100),("tesseract original",["tesseract","{p}","stdout"],75),("zbar original",["zbarimg","{p}"],40),("foremost",["foremost","-i","{p}","-o","{parent}/foremost_out"],120)],
"pcap":[("capinfos",["capinfos","{p}"],35),("protocol hierarchy",["tshark","-r","{p}","-q","-z","io,phs"],80),("tcp conv",["tshark","-r","{p}","-q","-z","conv,tcp"],80),("http fields",["tshark","-r","{p}","-Y","http","-T","fields","-e","frame.number","-e","http.request.full_uri","-e","http.file_data"],110),("dns fields",["tshark","-r","{p}","-Y","dns","-T","fields","-e","dns.qry.name","-e","dns.txt"],110),("tcp stream 0",["tshark","-r","{p}","-q","-z","follow,tcp,ascii,0"],100),("tcp stream 1",["tshark","-r","{p}","-q","-z","follow,tcp,ascii,1"],100),("tcp stream 2",["tshark","-r","{p}","-q","-z","follow,tcp,ascii,2"],100),("tcp stream 3",["tshark","-r","{p}","-q","-z","follow,tcp,ascii,3"],100)],
"pdf":[("pdfinfo",["pdfinfo","{p}"],35),("pdftotext",["pdftotext","{p}","-"],60),("pdfimages",["pdfimages","-list","{p}"],35),("pdfdetach list",["pdfdetach","-list","{p}"],35),("qpdf",["qpdf","--check","{p}"],35)],
"archive":[("7z list",["7z","l","{p}"],50),("zipinfo",["zipinfo","{p}"],35),("zip comment",["zipinfo","-z","{p}"],35)],
"binary":[("readelf",["readelf","-a","{p}"],80),("objdump",["objdump","-d","{p}"],110),("objdump rodata",["bash","-lc","objdump -s -j .rodata '{p}' 2>/dev/null | head -800"],60),("nm",["nm","-an","{p}"],60),("rabin2 info",["rabin2","-I","{p}"],60),("rabin2 strings",["rabin2","-zz","{p}"],70),("r2 quick",["r2","-q","-c","iI; izz; aaa; afl; pdf @ main","{p}"],120)],
"media":[("ffprobe",["ffprobe","{p}"],45),("soxi",["soxi","{p}"],35)],
"sqlite":[("sqlite tables",["sqlite3","{p}",".tables"],35),("sqlite schema",["sqlite3","{p}",".schema"],35)],
"text":[]
}
def all_files(root):
    return [p for p in (root/"files").rglob("*") if p.is_file() and not p.name.startswith(".")]
def seed_texts(report):
    seeds=[]
    def add(source,text,weight=0):
        text=str(text or "")
        if text.strip(): seeds.append({"source":source,"text":text[:18000],"weight":weight})
    add("file_type",report.get("file",""),5)
    add("strings","\n".join(report.get("strings",[])[:1800]),20)
    for o in report.get("outputs",[]): add("tool:"+str(o.get("tool","")),o.get("out",""),15)
    for p in report.get("previews",[]): add("preview:"+str(p.get("name","")),(p.get("qr","") or "")+"\n"+(p.get("ocr","") or ""),30+int(p.get("score",0)))
    for ctx in report.get("expert_contexts",[]): add("context",ctx,40)
    out=[]; seen=set()
    for s in seeds:
        k=(s["source"],s["text"][:300])
        if k not in seen: seen.add(k); out.append(s)
    return out[:300]
def chain_decode_report(report,raw=b""):
    chain=[]
    for seed in seed_texts(report):
        for item in decode_candidates(seed["text"], raw if seed["source"]=="strings" else b"")[:55]:
            item=dict(item); item["chain_source"]=seed["source"]; item["score"]=item.get("score",0)+seed.get("weight",0); chain.append(item)
        if seed.get("weight",0)>=25:
            for item in recursive_decode_seed(seed["text"])[:45]:
                item=dict(item); item["chain_source"]=seed["source"]+" -> recursive"; item["score"]=item.get("score",0)+seed.get("weight",0)+10; chain.append(item)
    if raw: chain += try_decompress_bytes(raw)+xor_crib_ctf_cs(raw)
    out=[]; seen=set()
    for c in sorted(chain,key=lambda x:x.get("score",0),reverse=True):
        k=(c.get("type"),(c.get("output","") or "")[:350])
        if k not in seen: seen.add(k); out.append(c)
    return out[:350]
def write_intermediate_files(report,root):
    outdir=root/"generated"/"verifyloop_intermediates"/safe(report.get("name","file"))
    outdir.mkdir(parents=True,exist_ok=True)
    made=[]
    for i,c in enumerate(report.get("chain_results",[])[:25]):
        txt=c.get("output","")
        if c.get("score",0)>=70 and txt and len(txt)<60000:
            p=outdir/(f"{i:02d}_{safe(c.get('type','chain'))}.txt")
            try:
                p.write_text(txt,encoding="utf-8",errors="ignore")
                made.append({"name":p.name,"path":str(p),"source":c.get("type"),"score":c.get("score")})
            except Exception: pass
    report["intermediate_files"]=made[:30]
def next_steps(report):
    steps=[]; kind=report.get("kind","generic")
    if report.get("flags"): steps.append({"priority":100,"step":"Submit/check promoted verified flag candidate.","why":"Candidate passed VerifyLoop confidence filters."})
    elif report.get("verified_flags"):
        steps.append({"priority":90,"step":"Open Verified Flags and inspect possible candidates.","why":"Some candidates exist but were not promoted because confidence is not high enough."})
    if report.get("chain_results"):
        top=report["chain_results"][0]
        if top.get("score",0)>75: steps.append({"priority":95,"step":"Open Chain: "+top.get("type","")+" from "+top.get("chain_source",""),"why":"Highest scoring derived result."})
    if report.get("verifyloop"): steps.append({"priority":96,"step":"Review VerifyLoop results first.","why":"All relevant Quick+Deep tools were already run automatically and chained into evidence."})
    if report.get("transformations"): steps.append({"priority":92,"step":"Inspect real transformed artifacts.","why":"VerifyLoop created concrete derived files from bytes, decoders, tools, or category workflows."})
    if report.get("intermediate_files"): steps.append({"priority":88,"step":"Inspect generated intermediate files.","why":"Agents created derived files from decoded/tool outputs."})
    type_steps={
        "image":[("Open Preview Rank top 5 and OCR/QR.",84,"Image stego often solves through filters/bitplanes/OCR/QR."),("Run zsteg, binwalk_extract, foremost, steghide.",76,"LSB/appended/extracted payloads are common.")],
        "pcap":[("Check HTTP/DNS/TCP streams and Chain.",84,"Network flags often are encoded stream payloads."),("Run tshark_files and analyze exported child files.",76,"PCAPs often hide files.")],
        "binary":[("Run strings_braces, rabin2_strings, r2_info, UPX.",86,"Reverse tasks often hide encoded strings or packing."),("Inspect objdump_rodata and imports.",72,"String references and compare functions guide solving.")],
        "pdf":[("Check pdftotext, pdfimages, pdfdetach, metadata.",78,"PDFs hide text, images, attachments.")],
        "archive":[("Inspect extracted children, zip comments, names.",78,"Archive tasks hide the real artifact/hint inside.")],
        "sqlite":[("Open sqlite tables/schema and strings_braces.",76,"DB tasks hide flags in tables or schema.")],
    }
    for st,pri,why in type_steps.get(kind,[]): steps.append({"priority":pri,"step":st,"why":why})
    for h in report.get("hypotheses",[])[:5]:
        steps.append({"priority":min(99,h.get("score",0)),"step":"Hypothesis: "+h.get("title",""),"why":h.get("why","")})
    if not steps: steps.append({"priority":50,"step":"Evidence Board → Chain → Tools Quick Suite.","why":"Generic workflow."})
    return sorted(steps,key=lambda x:x["priority"],reverse=True)[:25]
def rank_findings(report):
    fs=[]
    for v in report.get("verified_flags",[])[:30]:
        fs.append({"score":v.get("score",0)+80,"type":"verified_flag_candidate:"+v.get("status",""),"value":v.get("flag",""),"why":"; ".join((v.get("reasons",[]) or [])[:3]) + (" | negatives: "+"; ".join(v.get("negative_reasons",[])[:2]) if v.get("negative_reasons") else "")})
    text="\n".join(report.get("strings",[])[:800])+"\n"+"\n".join((o.get("out") or "")[:8000] for o in report.get("outputs",[]))
    for hit in extract_flagish_text(text): fs.append({"score":hit["score"],"type":hit["type"],"value":hit["value"],"why":hit["why"]})
    for f in report.get("flags",[]): fs.append({"score":360,"type":"promoted_verified_flag","value":f,"why":"Verified likely/confirmed flag candidate."})
    for c in report.get("chain_results",[])[:60]:
        if c.get("score",0)>55: fs.append({"score":min(260,c.get("score",0)),"type":"chain:"+str(c.get("type","")),"value":(c.get("output","") or "")[:800],"why":"From "+str(c.get("chain_source","unknown"))})
    for a in report.get("agent_runs",[])[:25]:
        fs.append({"score":a.get("score",0),"type":"agent:"+a.get("agent","agent"),"value":a.get("title","")+" :: "+a.get("why",""),"why":"Agent workflow recommendation."})
    for p in report.get("previews",[])[:18]:
        if p.get("score",0)>10 or p.get("ocr") or p.get("qr"): fs.append({"score":min(230,p.get("score",0)),"type":"ranked_image_filter","value":f"{p.get('name')} :: {(p.get('qr') or p.get('ocr') or '')[:650]}","why":"OCR/QR over generated filter/bitplane."})
    wf={"image":("image/stego workflow","Preview rank, zsteg, binwalk, OCR/QR, bitplanes.",80),"pcap":("network workflow","HTTP/DNS/TCP streams, exported files, decoders.",80),"binary":("reverse workflow","strings/braces, rabin2/r2, UPX, encoded blobs.",78),"archive":("archive workflow","children/comments/names/password hints.",72),"pdf":("pdf workflow","text/images/attachments/metadata.",72),"media":("media workflow","spectrogram/metadata/reverse audio.",70)}
    if report.get("kind") in wf:
        typ,why,score=wf[report["kind"]]; fs.append({"score":score,"type":typ,"value":report.get("rel"),"why":why})
    out=[]; seen=set()
    for f in sorted(fs,key=lambda x:x.get("score",0),reverse=True):
        k=(f.get("type"),f.get("value","")[:300])
        if k not in seen: seen.add(k); out.append(f)
    return out[:120]
def detect_structured_clues(text):
    """Find non-flag evidence that should drive category-specific workflows."""
    text = text or ""
    clues = []
    def add(kind, value, score, why):
        value = str(value)[:900]
        if value:
            clues.append({"type": kind, "value": value, "score": int(score), "why": why})
    # hashes
    for h in re.findall(r"\b[a-fA-F0-9]{32}\b", text):
        add("hash_md5_candidate", h, 42, "32 hex chars; may be MD5/hash clue.")
    for h in re.findall(r"\b[a-fA-F0-9]{40}\b", text):
        add("hash_sha1_candidate", h, 42, "40 hex chars; may be SHA1/hash clue.")
    for h in re.findall(r"\b[a-fA-F0-9]{64}\b", text):
        add("hash_sha256_or_hex_blob", h, 48, "64 hex chars; hash or encoded bytes.")
    # URLs, domains, emails, tokens
    for u in re.findall(r"https?://[^\s'\"<>]+", text):
        add("url", u, 50, "URL found; web/OSINT/network clue.")
    for e in re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", text):
        add("email", e, 36, "Email-like clue.")
    for tok in re.findall(r"eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\.?[A-Za-z0-9_=-]*", text):
        add("jwt_token", tok, 65, "JWT-like token; decode header/payload.")
    # RSA-ish parameters in crypto tasks
    for m in re.finditer(r"\b(n|e|c|p|q|d)\s*[:=]\s*([0-9]{5,}|0x[0-9a-fA-F]{8,})", text):
        add("rsa_parameter_"+m.group(1), m.group(0), 62, "RSA-style parameter detected.")
    # Large encoded blobs
    for b in re.findall(r"[A-Za-z0-9+/=_-]{40,}", text):
        add("large_base_encoding_candidate", b[:260], 44, "Long base-like blob; feed to recursive decoder.")
    # Lithuanian hint words and common CTF clue words
    for line in text.splitlines():
        low=line.lower()
        if any(k in low for k in ["raktas","slapta","slaptažodis","veliava","užuomina","paslėpta","paveiksliukas","garsas","tinklas","archyvas","password","secret","key","xor","rsa","base64","hidden"]):
            add("hint_context", line[:700], score_text(line)+20, "Hint/context word detected.")
    # Deduplicate
    out=[]; seen=set()
    for c in sorted(clues,key=lambda x:x["score"],reverse=True):
        k=(c["type"],c["value"][:250])
        if k not in seen:
            seen.add(k); out.append(c)
    return out[:140]
def classify_workflow_hypotheses(report):
    """Build targeted solve hypotheses instead of only searching for ctf_cs everywhere."""
    kind = report.get("kind","generic")
    outputs = "\n".join((o.get("out") or "")[:9000] for o in report.get("outputs",[]))
    strings = "\n".join(report.get("strings",[])[:1800])
    text = strings + "\n" + outputs
    clues = detect_structured_clues(text)
    hyps = []
    def add(score, title, why, actions, evidence=None):
        hyps.append({"score":int(score), "title":title, "why":why, "actions":actions, "evidence":evidence or []})
    if report.get("flags"):
        add(100, "Exact/flag-like candidate exists", "A direct flag-like string was found.", ["Open Summary", "Copy exact candidate", "Check surrounding context if multiple candidates"], report.get("flags",[])[:5])
    if kind == "image":
        if "zsteg" in outputs.lower() or any(p.get("score",0)>40 for p in report.get("previews",[])):
            add(88, "Image LSB/visual stego path", "Image outputs or preview ranks suggest hidden text/visual content.", ["Open Preview Rank", "Inspect top 5 filters", "Run zsteg_all", "Run binwalk_extract", "Check Intermediates"])
        if "password" in text.lower() or "steghide" in text.lower():
            add(80, "Passworded stego path", "Text suggests password or steghide-style hiding.", ["Check metadata/hints for password", "Run steghide_info", "Try stegseek if wordlist exists"])
        if "zip" in outputs.lower() or "archive" in outputs.lower():
            add(78, "Appended archive path", "Binwalk/file output suggests embedded/archive data.", ["Run binwalk_extract", "Run foremost", "Analyze extracted child files"])
    elif kind == "pcap":
        add(84, "Network stream reconstruction path", "PCAP should be solved through protocols, streams, or exported objects.", ["Open Outputs: HTTP/DNS/TCP", "Run tshark_files", "Open Chain Results", "Analyze exported children"])
        if "dns" in outputs.lower():
            add(78, "DNS encoding path", "DNS traffic often contains encoded labels or TXT records.", ["Open DNS output", "Copy suspicious labels", "Use Decoder Lab"])
        if "http" in outputs.lower():
            add(78, "HTTP object/session path", "HTTP streams may contain flags, credentials, or downloaded files.", ["Run tshark_files", "Check HTTP fields", "Analyze exported children"])
    elif kind == "binary":
        if "upx" in text.lower():
            add(86, "Packed binary path", "UPX/packing indicator found.", ["Run upx_test", "Run upx_decompress", "Re-run project analysis on unpacked file"])
        add(82, "Static reverse path", "Binary tasks often hide encoded strings/check logic.", ["Run strings_braces", "Run rabin2_strings", "Open objdump_rodata", "Run r2_info", "Inspect Chain Results"])
        if any(x in text.lower() for x in ["strcmp","memcmp","scanf","xor","decode","check"]):
            add(86, "Validation/decryption function path", "Imports/strings suggest input checking or decoding logic.", ["Open elf_imports", "Open r2_info", "Inspect rodata and chain decoders"])
    elif kind in ["text","generic"]:
        if clues:
            add(78, "Encoding/crypto clue path", "Structured encoded/hash/JWT/RSA clues were found.", ["Open Chain", "Open Decoders", "Use Decoder Lab on top clue", "Ask AI Coach to explain top clue"], clues[:8])
        if any(c["type"].startswith("rsa_parameter") for c in clues):
            add(86, "RSA parameter path", "RSA-like n/e/c/p/q parameters detected.", ["Collect all RSA parameters", "Use local Python/RsaCtfTool if installed", "Ask AI Coach for exact attack classification"], clues[:12])
    elif kind == "pdf":
        add(80, "PDF layered content path", "PDFs commonly hide text layer, images, or attachments.", ["Open pdftotext output", "Run pdfdetach_extract", "Check pdfimages", "Analyze child files"])
    elif kind == "archive":
        add(78, "Nested archive/metadata path", "Archives commonly hide child tasks, comments, or password hints.", ["Open 7z/zipinfo output", "Check comments", "Analyze extracted children", "Check hint words in strings"])
    elif kind == "media":
        add(78, "Audio/visual media path", "Media tasks commonly use metadata, spectrograms, reversed audio, or appended data.", ["Open spectrogram preview", "Run ffprobe/soxi", "Check strings/binwalk", "Use Chain Results"])
    for c in clues[:10]:
        add(min(76,c["score"]), "Structured clue: "+c["type"], c["why"], ["Open Evidence Board", "Use Decoder Lab or relevant workflow for this clue"], [c["value"]])
    if not hyps:
        add(45, "Generic triage path", "No strong category-specific hypothesis yet.", ["Open Evidence Board", "Open Chain", "Run Deep Suite", "Inspect Outputs"])
    # Deduplicate by title/evidence
    out=[]; seen=set()
    for h in sorted(hyps,key=lambda x:x["score"],reverse=True):
        k=(h["title"], str(h.get("evidence",""))[:200])
        if k not in seen:
            seen.add(k); out.append(h)
    return out[:40]
def workflowbrain_project_hypotheses(reports):
    allh=[]
    for r in reports:
        for h in r.get("hypotheses",[])[:12]:
            h=dict(h); h["file"]=r.get("rel"); h["kind"]=r.get("kind"); allh.append(h)
    return sorted(allh,key=lambda x:x.get("score",0),reverse=True)[:120]
def agent_add_result(results, agent, title, score, why, actions=None, evidence=None, commands=None, generated=None):
    results.append({
        "agent": agent,
        "title": title,
        "score": int(score),
        "why": why,
        "actions": actions or [],
        "evidence": evidence or [],
        "commands": commands or [],
        "generated": generated or []
    })
def agent_write_note(root, report, agent_name, content, suffix="txt", score=0):
    outdir = root / "generated" / "verifyloop_intermediates" / safe(report.get("name","file"))
    outdir.mkdir(parents=True, exist_ok=True)
    fname = safe(agent_name) + "_" + uuid.uuid4().hex[:8] + "." + suffix
    p = outdir / fname
    try:
        p.write_text(str(content), encoding="utf-8", errors="ignore")
        return {"name": fname, "path": str(p), "source": agent_name, "score": score}
    except Exception:
        return None
def agent_blob_summary(text):
    text = text or ""
    return {
        "flagish": extract_flagish_text(text)[:12],
        "structured": detect_structured_clues(text)[:12] if "detect_structured_clues" in globals() else [],
        "contexts": expert_context_lines(text)[:8]
    }
def agent_image_stego(report, root):
    res = []
    previews = report.get("previews", [])
    outputs = "\n".join((o.get("out") or "")[:9000] for o in report.get("outputs", []))
    best = previews[:8]
    if best:
        ev = [{"name": p.get("name"), "score": p.get("score"), "ocr": (p.get("ocr") or "")[:400], "qr": (p.get("qr") or "")[:400]} for p in best]
        agent_add_result(res, "image_stego_agent", "Ranked visual/LSB/OCR path", max([p.get("score",0) for p in best] + [60]), "Generated filters, bitplanes and OCR/QR previews should be inspected in score order.", ["Open Preview", "Inspect top 5 ranked tiles", "If text appears partial, copy it to Decoder Lab"], ev, ["zsteg_all", "binwalk_extract", "foremost"])
    if any(x in outputs.lower() for x in ["zip", "7-zip", "rar", "gzip", "embedded", "compressed"]):
        agent_add_result(res, "image_payload_agent", "Possible appended payload", 82, "Binwalk/output suggests embedded payload or archive.", ["Run binwalk_extract", "Run foremost", "Re-run analysis after child files appear"], agent_blob_summary(outputs).get("flagish"), ["binwalk_extract", "foremost", "binwalk_recursive"])
    if any(x in outputs.lower() for x in ["password", "steghide", "passphrase"]):
        agent_add_result(res, "image_password_agent", "Passworded stego branch", 78, "Stego/password hints detected.", ["Look for password in statement/metadata", "Run steghide_info", "Run stegseek if rockyou exists"], agent_blob_summary(outputs).get("structured"), ["steghide_info", "stegseek"])
    return res
def agent_pcap(report, root):
    res=[]; outputs="\n".join((o.get("out") or "")[:12000] for o in report.get("outputs", []))
    low=outputs.lower()
    agent_add_result(res, "pcap_triage_agent", "Protocol and stream triage", 76, "PCAP workflows start with protocol overview, HTTP/DNS fields and TCP stream reconstruction.", ["Open Outputs", "Inspect HTTP/DNS/TCP streams", "Open Chain for decoded stream payloads"], agent_blob_summary(outputs).get("structured"), ["tshark_protocols", "tshark_http", "tshark_dns", "tshark_tcp0", "tshark_tcp1"])
    if "http" in low:
        agent_add_result(res, "pcap_http_agent", "HTTP object/session path", 84, "HTTP data often contains downloaded files, credentials, JWTs or flags.", ["Run tshark_files", "Analyze exported objects", "Check URLs/tokens in Evidence"], agent_blob_summary(outputs).get("flagish"), ["tshark_files", "grep_urls_tokens"])
    if "dns" in low:
        agent_add_result(res, "pcap_dns_agent", "DNS exfil/encoding path", 82, "DNS labels/TXT records may carry base-encoded chunks.", ["Open DNS output", "Copy long labels to Decoder Lab", "Check Chain Results"], agent_blob_summary(outputs).get("structured"), ["tshark_dns"])
    return res
def agent_reverse(report, root):
    res=[]; outputs="\n".join((o.get("out") or "")[:14000] for o in report.get("outputs", [])); low=outputs.lower()
    agent_add_result(res, "reverse_static_agent", "Static reverse triage", 78, "Binary should be checked via strings, imports, rodata and disassembly before deeper reversing.", ["Open Strings", "Run strings_braces", "Run rabin2_strings", "Open objdump_rodata", "Open Chain"], agent_blob_summary(outputs).get("flagish"), ["strings_braces", "rabin2_strings", "objdump_rodata", "r2_info"])
    if "upx" in low or "packed" in low:
        agent_add_result(res, "reverse_unpack_agent", "Packed binary branch", 88, "Packing/UPX clue detected.", ["Run upx_test", "Run upx_decompress", "Re-run project on unpacked file"], [], ["upx_test", "upx_decompress"])
    if any(x in low for x in ["strcmp", "memcmp", "scanf", "xor", "decode", "check", "decrypt"]):
        agent_add_result(res, "reverse_validation_agent", "Validation/decryption branch", 86, "Imports/strings suggest input validation or decryption routine.", ["Inspect elf_imports", "Inspect r2_info", "Check rodata blobs through Chain"], agent_blob_summary(outputs).get("structured"), ["elf_imports", "r2_info", "grep_crypto_clues"])
    return res
def agent_crypto_text(report, root):
    res=[]; text="\n".join(report.get("strings",[])[:2200])+"\n"+"\n".join((o.get("out") or "")[:9000] for o in report.get("outputs", []))
    clues = detect_structured_clues(text) if "detect_structured_clues" in globals() else []
    if clues:
        agent_add_result(res, "crypto_clue_agent", "Structured crypto/encoding clues", max([c.get("score",0) for c in clues[:10]]+[72]), "Hashes, JWTs, RSA params, URLs or encoded blobs were detected.", ["Open Hypotheses", "Open Decoders", "Use Decoder Lab on top clue", "Ask AI Coach for attack classification"], clues[:15], ["grep_crypto_clues", "grep_urls_tokens"])
    if any(c.get("type","").startswith("rsa_parameter") for c in clues):
        agent_add_result(res, "crypto_rsa_agent", "RSA parameter workflow", 90, "RSA-like n/e/c/p/q parameters were found.", ["Collect parameters", "Try local RsaCtfTool manually if installed", "Ask AI Coach which RSA attack applies"], [c for c in clues if c.get("type","").startswith("rsa_parameter")][:15], ["grep_crypto_clues"])
    if report.get("chain_results"):
        top = report["chain_results"][:12]
        agent_add_result(res, "crypto_chain_agent", "Recursive decoding stack", max([c.get("score",0) for c in top]+[70]), "Chain results show likely encoding/crypto transforms.", ["Inspect Chain top results", "Copy partial plaintext to Decoder Lab", "Check generated intermediates"], top[:8], [])
    return res
def agent_pdf_archive(report, root):
    res=[]; kind=report.get("kind"); outputs="\n".join((o.get("out") or "")[:10000] for o in report.get("outputs", []))
    if kind=="pdf":
        agent_add_result(res, "pdf_layer_agent", "PDF layered artifact path", 78, "PDFs may hide text layers, images, attachments or appended files.", ["Open pdftotext output", "Run pdfdetach_extract", "Run pdfimages", "Run binwalk_extract"], agent_blob_summary(outputs).get("structured"), ["pdftotext", "pdfimages", "pdfdetach_extract", "binwalk_extract"])
    if kind=="archive":
        agent_add_result(res, "archive_nested_agent", "Archive nesting/password-hint path", 78, "Archives often hide nested files, comments or password clues.", ["Open 7z/zipinfo output", "Check comments", "Inspect extracted children", "Run Deep Suite"], agent_blob_summary(outputs).get("structured"), ["seven_list", "zip_comment", "binwalk_extract", "foremost"])
    return res
def agent_media_artifact(report, root):
    res=[]; kind=report.get("kind"); outputs="\n".join((o.get("out") or "")[:10000] for o in report.get("outputs", []))
    if kind=="media":
        agent_add_result(res, "media_signal_agent", "Media/signal stego path", 76, "Media often hides metadata, spectrogram text, reversed audio or appended payload.", ["Open Preview spectrogram if present", "Run ffprobe/soxi", "Check strings/binwalk", "Open Chain"], agent_blob_summary(outputs).get("structured"), ["spectrogram", "ffprobe", "soxi", "binwalk_extract"])
    if kind=="sqlite":
        agent_add_result(res, "sqlite_agent", "Database table workflow", 78, "SQLite flags usually hide in table rows, schema or blobs.", ["Run sqlite_tables", "Run sqlite_schema", "Open strings/Chain"], agent_blob_summary(outputs).get("flagish"), ["sqlite_tables", "sqlite_schema", "strings_braces"])
    if kind in ["apk","python_bytecode"]:
        agent_add_result(res, "artifact_decompile_agent", "Decompile artifact workflow", 78, "APK/PYC artifacts should be decompiled and searched for constants/logic.", ["Run decompiler tool", "Search generated files", "Open Chain"], agent_blob_summary(outputs).get("structured"), ["apktool_decode", "jadx_decompile", "python_pyc_decompile", "decompyle3"])
    return res
def run_agent_forge(report, root):
    agents=[]
    kind=report.get("kind","generic")
    agents += agent_crypto_text(report, root)
    if kind=="image": agents += agent_image_stego(report, root)
    if kind=="pcap": agents += agent_pcap(report, root)
    if kind=="binary": agents += agent_reverse(report, root)
    if kind in ["pdf","archive"]: agents += agent_pdf_archive(report, root)
    if kind in ["media","sqlite","apk","python_bytecode"]: agents += agent_media_artifact(report, root)
    if not agents:
        agent_add_result(agents, "generic_operator_agent", "Generic artifact triage", 55, "No strong specialized branch. Use broad triage and chain outputs.", ["Run Quick Suite", "Open Evidence Board", "Open Chain", "Run Deep Suite if needed"], [], ["file", "strings_braces", "extract_ascii_context", "binwalk", "foremost"])
    # Write top agent briefs as intermediate files for local AI and humans
    generated=[]
    for a in sorted(agents,key=lambda x:x.get("score",0),reverse=True)[:12]:
        note = "AGENT: {agent}\nTITLE: {title}\nSCORE: {score}\nWHY: {why}\nACTIONS:\n- ".format(**a) + "\n- ".join(a.get("actions",[])) + "\nEVIDENCE:\n" + json.dumps(a.get("evidence",[])[:8], ensure_ascii=False, indent=2)
        g = agent_write_note(root, report, a.get("agent","agent"), note, "agent.txt", a.get("score",0))
        if g: generated.append(g)
    return sorted(agents,key=lambda x:x.get("score",0),reverse=True)[:80], generated
def tf_safe_write(path, data, binary=False):
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if binary:
            path.write_bytes(data)
        else:
            path.write_text(str(data), encoding="utf-8", errors="ignore")
        return True
    except Exception:
        return False
def transform_record(kind, name, path, source, score=0, note=""):
    return {"kind": kind, "name": name, "path": str(path), "source": source, "score": int(score), "note": note, "url": "/api/raw?path="+str(path)}
def agent_transform_generic(report, root, raw):
    """Always create actual transformed artifacts from bytes/strings/decoders."""
    out=[]
    base = root/"generated"/"verifyloop"/safe(report.get("name","file"))
    base.mkdir(parents=True, exist_ok=True)

    # raw strings dumps
    ascii_path = base/"strings_ascii.txt"
    if tf_safe_write(ascii_path, "\n".join(report.get("strings", []))):
        out.append(transform_record("strings", ascii_path.name, ascii_path, "ascii strings", score_text(ascii_path.read_text(errors="ignore")[:2000]), "ASCII printable strings dump"))

    utf16_path = base/"strings_utf16le.txt"
    utf16_strings = []
    try:
        txt = raw.decode("utf-16le", "ignore")
        for part in re.findall(r"[ -~]{4,}", txt):
            utf16_strings.append(part)
        if tf_safe_write(utf16_path, "\n".join(utf16_strings[:2000])):
            out.append(transform_record("strings", utf16_path.name, utf16_path, "utf16 strings", score_text("\n".join(utf16_strings[:100])), "UTF-16LE strings dump"))
    except Exception:
        pass

    # reversed bytes
    rev_path = base/"reverse_bytes.bin"
    if raw and tf_safe_write(rev_path, raw[::-1], binary=True):
        out.append(transform_record("bytes", rev_path.name, rev_path, "reverse bytes", 25, "Raw file bytes reversed"))

    # decompressed outputs
    for item in try_decompress_bytes(raw):
        p = base/(safe(item.get("type","decompress"))+".txt")
        if tf_safe_write(p, item.get("output","")):
            out.append(transform_record("decompress", p.name, p, item.get("type"), item.get("score",0), "Successful decompression candidate"))

    # top decoders / chain outputs become files
    combined_items = (report.get("decoders",[])[:40] + report.get("chain_results",[])[:60])
    seen = set()
    for i, item in enumerate(combined_items[:80]):
        txt = item.get("output","")
        sc = item.get("score",0)
        if not txt or sc < 50:
            continue
        key = txt[:300]
        if key in seen:
            continue
        seen.add(key)
        p = base/(f"decoded_{i:03d}_{safe(item.get('type','candidate'))}.txt")
        if tf_safe_write(p, txt):
            out.append(transform_record("decoded", p.name, p, item.get("type","decoder"), sc, "High-scoring decoder/chain output materialized as file"))

    # XOR best candidates become files
    for i, item in enumerate((xor_single(raw) + repeating_xor_guesses(raw) + xor_crib_ctf_cs(raw))[:25]):
        if item.get("score",0) < 55:
            continue
        p = base/(f"xor_{i:02d}_{safe(item.get('type','xor'))}.txt")
        if tf_safe_write(p, item.get("output","")):
            out.append(transform_record("xor", p.name, p, item.get("type"), item.get("score",0), "XOR transformation output"))

    # extract long encoded blobs as individual files for manual/AI review
    text_blob = "\n".join(report.get("strings",[])[:2000]) + "\n" + "\n".join((o.get("out") or "")[:9000] for o in report.get("outputs",[]))
    blobs = re.findall(r"[A-Za-z0-9+/=_-]{40,}|[A-Fa-f0-9]{40,}|(?:\d{2,3}[,\s]+){8,}\d{2,3}", text_blob)
    blobdir = base/"encoded_blobs"
    for i,b in enumerate(blobs[:60]):
        p = blobdir/(f"blob_{i:03d}.txt")
        if tf_safe_write(p, b):
            out.append(transform_record("blob", p.name, p, "encoded blob extraction", score_text(b), "Suspicious encoded/hash/blob candidate extracted"))
    return out[:160]
def agent_transform_image(report, root, raw):
    out=[]
    base=root/"generated"/"verifyloop"/safe(report.get("name","file"))/"image_agent"
    base.mkdir(parents=True, exist_ok=True)
    # Materialize OCR/QR summaries from generated image lab.
    lines=[]
    for p in report.get("previews",[])[:80]:
        lines.append(f"## {p.get('name')} score={p.get('score')}\nPATH={p.get('path')}\nQR:\n{p.get('qr','')}\nOCR:\n{p.get('ocr','')}\nFLAGS={p.get('flags',[])}\n")
    if lines:
        s= "\n".join(lines)
        f=base/"ocr_qr_ranked_summary.txt"
        if tf_safe_write(f, s):
            out.append(transform_record("image_summary", f.name, f, "image OCR/QR/filters", score_text(s), "Ranked OCR/QR output across visual transformations"))
    # Create a simple contact sheet from top previews if PIL can open them.
    try:
        imgs=[]
        for pv in report.get("previews",[])[:12]:
            pp=Path(pv.get("path",""))
            if pp.exists():
                im=Image.open(pp).convert("RGB")
                im.thumbnail((240,180))
                imgs.append((pv.get("name",""), im.copy()))
        if imgs:
            sheet=Image.new("RGB",(480, 180*((len(imgs)+1)//2)), "white")
            for idx,(name,im) in enumerate(imgs):
                x=(idx%2)*240; y=(idx//2)*180
                sheet.paste(im,(x,y))
            sheet_path=base/"top_preview_contact_sheet.jpg"
            sheet.save(sheet_path)
            out.append(transform_record("image_contact_sheet", sheet_path.name, sheet_path, "image preview contact sheet", 35, "Top generated filters in one view"))
    except Exception:
        pass
    return out
def agent_transform_pcap(report, root, raw):
    out=[]
    src=Path(report.get("path",""))
    if not src.exists(): return out
    base=root/"generated"/"verifyloop"/safe(report.get("name","file"))/"pcap_agent"
    base.mkdir(parents=True, exist_ok=True)
    if exists("tshark"):
        # export HTTP objects
        export_dir=base/"http_objects"
        export_dir.mkdir(parents=True, exist_ok=True)
        r=run(["tshark","-r",str(src),"--export-objects","http,"+str(export_dir)],120)
        logp=base/"tshark_http_export.log"
        tf_safe_write(logp, r.get("out",""))
        out.append(transform_record("pcap_export_log", logp.name, logp, "tshark http export", score_text(r.get("out","")), "HTTP object export log"))
        for f in export_dir.rglob("*"):
            if f.is_file():
                out.append(transform_record("pcap_exported_object", f.name, f, "tshark exported object", 45, "HTTP object exported from PCAP"))
        # TCP streams to files
        for i in range(8):
            r=run(["tshark","-r",str(src),"-q","-z",f"follow,tcp,ascii,{i}"],90)
            txt=r.get("out","")
            if txt and "Follow:" in txt:
                p=base/f"tcp_stream_{i}.txt"
                if tf_safe_write(p, txt):
                    out.append(transform_record("pcap_tcp_stream", p.name, p, f"tcp stream {i}", score_text(txt), "TCP stream materialized to text"))
        # DNS fields to file
        r=run(["tshark","-r",str(src),"-Y","dns","-T","fields","-e","dns.qry.name","-e","dns.txt"],90)
        if r.get("out","").strip():
            p=base/"dns_fields.txt"
            if tf_safe_write(p, r.get("out","")):
                out.append(transform_record("pcap_dns", p.name, p, "dns fields", score_text(r.get("out","")), "DNS labels/TXT extracted"))
    return out[:160]
def agent_transform_pdf(report, root, raw):
    out=[]
    src=Path(report.get("path",""))
    if not src.exists(): return out
    base=root/"generated"/"verifyloop"/safe(report.get("name","file"))/"pdf_agent"
    base.mkdir(parents=True, exist_ok=True)
    if exists("pdftotext"):
        r=run(["pdftotext",str(src),"-"],80)
        p=base/"pdftotext.txt"
        if tf_safe_write(p,r.get("out","")):
            out.append(transform_record("pdf_text", p.name, p, "pdftotext", score_text(r.get("out","")), "PDF text layer extracted"))
    if exists("pdfdetach"):
        att=base/"attachments"; att.mkdir(exist_ok=True)
        r=run(["pdfdetach","-saveall","-o",str(att),str(src)],80)
        logp=base/"pdfdetach.log"; tf_safe_write(logp,r.get("out",""))
        out.append(transform_record("pdfdetach_log", logp.name, logp, "pdfdetach", score_text(r.get("out","")), "PDF attachment extraction log"))
        for f in att.rglob("*"):
            if f.is_file(): out.append(transform_record("pdf_attachment", f.name, f, "pdfdetach", 55, "Attachment extracted from PDF"))
    if exists("pdfimages"):
        imgdir=base/"images"; imgdir.mkdir(exist_ok=True)
        r=run(["pdfimages","-png",str(src),str(imgdir/"img")],120)
        logp=base/"pdfimages.log"; tf_safe_write(logp,r.get("out",""))
        out.append(transform_record("pdfimages_log", logp.name, logp, "pdfimages", score_text(r.get("out","")), "PDF image extraction log"))
        for f in imgdir.rglob("*"):
            if f.is_file(): out.append(transform_record("pdf_image", f.name, f, "pdfimages", 50, "Image extracted from PDF"))
    return out[:160]
