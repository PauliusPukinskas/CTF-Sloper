"""CTF SLOPER v89 universal finishing layer.

Adds broad-but-evidence-based CTF finishing passes:
- promotes alternate flag formats: {body}, flag{body}, tsg{body}, ctf_cs{body}
- recursively re-scans decoded/decompressed child artifacts
- covers common multi-step encodings missed by strict-only v88
"""
from __future__ import annotations
import base64, binascii, codecs, csv, gzip, io, json, re, zipfile, zlib, html, urllib.parse, quopri, struct, tarfile, bz2, lzma
from pathlib import Path
from typing import Iterable

from .health import agent_crash
from .workflow_v74 import artifact, printable, quality_text, safe_name, scan_text

ALT_RE = re.compile(r"(?<![A-Za-z0-9_])(?:(?:ctf_cs|flag|tsg|ctf|cyber|sprint)?\{[A-Za-z0-9][A-Za-z0-9_\-:+./=]{2,140}\})", re.I)
BARE_RE = re.compile(r"(?<![A-Za-z0-9_])\{([A-Za-z0-9][A-Za-z0-9_\-:+./=]{2,140})\}")
STRICT_RE = re.compile(r"ctf_cs\{[A-Za-z0-9_\-:+./=]{1,140}\}", re.I)
DECOY = {"example","example_flag","test","test_flag","flag","placeholder","answer","answer_here","your_flag_here","todo","dummy","sample","fake","ctf_cs"}
HINT_RE = re.compile(r"(cyber|sprint|secret|hidden|flag|fl4g|veliava|v[eė]liava|atsak|answer|raktas|slapta|password|pass|key|decode|morse|bacon|rot|xor|zip|gzip|lsb|steg|bracket|done|ok|found|final|real|tsg|ctf)", re.I)

def _body(flag: str) -> str:
    m = re.search(r"\{([^{}]+)\}", str(flag or ""))
    return m.group(1) if m else ""

def _good_body(body: str, context: str = "") -> bool:
    b = (body or "").strip().strip("{}").lower()
    if not (4 <= len(b) <= 140): return False
    if b in DECOY: return False
    if any(x in b for x in ["schema", "xmlns", "helvetica", "endobj", "basefont", "quarantine", "com_apple"]): return False
    if re.fullmatch(r"[0-9a-f]{24,}", b): return False
    if re.fullmatch(r"[0-9]+", b): return False
    if sum(1 for c in b if c.isalnum() or c in "_-:+./=") / max(1, len(b)) < .92: return False
    if b[0] in "._:/=+-" or b[-1] in "._:/=+-": return False
    if "ctf_cs" in (context or "").lower() and re.fullmatch(r"[a-z0-9_\-]{4,80}", b) and re.search(r"[a-z]", b): return True
    if "_" in b and re.search(r"[a-z]", b): return True
    if re.search(r"[a-z]", b) and re.search(r"\d", b) and len(b) >= 5: return True
    if re.search(r"[a-z]", b) and "_" in b and len(b) >= 5: return True
    # Common CTF bare-brace style: meaningful lowercase words, often with leet, without prefix.
    if re.search(r"[a-z]", b) and len(b) >= 8 and not re.fullmatch(r"[a-z]{1,3}[0-9]{4,}", b): return True
    if HINT_RE.search(b) or HINT_RE.search(context or ""): return re.search(r"[a-z]", b) is not None
    return False

def _add_flag(report: dict, flag: str, source: str, artifact_path: str | None, why: str, score: int = 760) -> None:
    report.setdefault("flags", []); report.setdefault("workflow_evidence", []); report.setdefault("alternate_flag_candidates", [])
    flag = str(flag).strip()
    body = _body(flag)
    if not _good_body(body, source + " " + why): return
    # Prefer exact observed format. Bare {body} is now a first-class flag.
    prefix = flag.split("{",1)[0].lower()
    if not prefix:
        leety = (body.count("_") >= 1 and sum(c.isdigit() for c in body) >= 2 and re.search(r"[a-z]", body))
        transform = re.search(r"ROT\d+|morse|bacon", source, re.I)
        ctx_hint = HINT_RE.search(source + " " + why)
        noisy_transform = re.search(r"ROT\d+|atbash", source, re.I)
        has_word_shape = ("_" in body and re.search(r"[A-Za-z]", body) and len(body) >= 5) or (re.search(r"[A-Za-z]", body) and re.search(r"\d", body) and len(body) >= 5)
        # ROT/Atbash applied to already-braced plaintext creates many shifted-brace false positives.
        # For bare braces from these noisy transforms, require the decoded body itself to look semantic.
        if noisy_transform and not HINT_RE.search(body):
            return
        if not HINT_RE.search(body) and not ctx_hint and not has_word_shape and not (leety and not transform):
            return
    if flag not in report["flags"]:
        report["flags"].append(flag)
    ev = {"flag": flag, "source": source, "artifact": artifact_path or "", "why": why, "score": score}
    if ev not in report["workflow_evidence"]: report["workflow_evidence"].append(ev)
    alt = {"value": flag, "source": source, "artifact": artifact_path or "", "why": why, "score": score}
    if alt not in report["alternate_flag_candidates"]: report["alternate_flag_candidates"].append(alt)

def scan_any_flags(report: dict, text: str, source: str, artifact_path: str | None = None, why: str = "Evidence text contained a flag-like bracket token.", score: int = 760) -> list[str]:
    out=[]; text=str(text or "")
    # strict legacy first
    try: scan_text(report, text, source, artifact_path, why, score)
    except Exception: pass
    for m in ALT_RE.finditer(text):
        flag=m.group(0)
        body=_body(flag)
        # For bare braces demand stronger body unless source is a generated transform.
        if flag.startswith("{") and not (_good_body(body, text[max(0,m.start()-80):m.end()+80]) or "SLOPER" in source):
            continue
        before=text[max(0,m.start()-80):m.start()].lower()
        after=text[m.end():m.end()+80].lower()
        ctx=before+" "+after+" "+source
        if _good_body(body, ctx):
            before_len=len(report.get("flags", []))
            _add_flag(report, flag, source, artifact_path, why, score)
            if flag in report.get("flags", [])[before_len:] or flag in report.get("flags", []): out.append(flag)
    return out

MORSE = {".-":"A","-...":"B","-.-.":"C","-..":"D",".":"E","..-.":"F","--.":"G","....":"H","..":"I",".---":"J","-.-":"K",".-..":"L","--":"M","-.":"N","---":"O",".--.":"P","--.-":"Q",".-.":"R","...":"S","-":"T","..-":"U","...-":"V",".--":"W","-..-":"X","-.--":"Y","--..":"Z","-----":"0",".----":"1","..---":"2","...--":"3","....-":"4",".....":"5","-....":"6","--...":"7","---..":"8","----.":"9"}

def _rot(s: str, n: int) -> str:
    r=[]
    for ch in s:
        if 'a' <= ch <= 'z': r.append(chr((ord(ch)-97+n)%26+97))
        elif 'A' <= ch <= 'Z': r.append(chr((ord(ch)-65+n)%26+65))
        else: r.append(ch)
    return ''.join(r)

def _morse_decode(s: str) -> str:
    norm=s.replace("_","-").replace("|"," / ")
    words=[]
    for word in re.split(r"\s*/\s*", norm.strip()):
        chars=[]
        for tok in re.split(r"\s+", word.strip()):
            if tok: chars.append(MORSE.get(tok,"?"))
        words.append(''.join(chars))
    return ' '.join(words)

def _bacon_decode(s: str, inv=False) -> str:
    letters=re.findall(r"[ABab]{5}", s)
    out=[]
    for g in letters:
        bits=''.join(('1' if c.upper()=='B' else '0') for c in g)
        if inv: bits=''.join('1' if x=='0' else '0' for x in bits)
        v=int(bits,2)
        if 0 <= v < 26: out.append(chr(65+v))
    return ''.join(out)

def _bits_to_text_variants(bits: str) -> list[str]:
    bits = ''.join(c for c in str(bits or '') if c in '01')
    outs=[]
    if len(bits) < 8: return outs
    for off in range(8):
        usable=bits[off:]
        for rev in [False, True]:
            raw=bytearray()
            for i in range(0, len(usable)-7, 8):
                b=usable[i:i+8]
                if rev: b=b[::-1]
                raw.append(int(b,2))
            txt=bytes(raw).decode('utf-8','ignore')
            if txt.strip(): outs.append(txt)
    return outs

def _zero_width_variants(s: str) -> list[str]:
    maps=[
        {"\u200b":"0","\u200c":"1"}, {"\u200c":"0","\u200b":"1"},
        {"\u200b":"0","\u200d":"1"}, {"\u200d":"0","\u200b":"1"},
        {"\u200c":"0","\u200d":"1"}, {"\u200d":"0","\u200c":"1"},
        {"\u2060":"0","\ufeff":"1"}, {"\ufeff":"0","\u2060":"1"},
    ]
    outs=[]
    for mp in maps:
        bits=''.join(mp[c] for c in s if c in mp)
        outs += _bits_to_text_variants(bits)
    return list(dict.fromkeys(outs))[:80]

def _zero_width(s: str) -> str:
    vs=_zero_width_variants(s)
    return vs[0] if vs else ""

def _candidate_texts(data: bytes) -> Iterable[tuple[str,str]]:
    sample = bytes(data[:200000] or b'')
    txt = data[:2_000_000].decode('utf-8','ignore')
    yield "utf8", txt
    nul_even = sample[1::2].count(0) if sample else 0
    nul_odd = sample[0::2].count(0) if sample else 0
    if data.startswith((b'\xff\xfe', b'\xfe\xff')) or nul_even > len(sample)//8 or nul_odd > len(sample)//8:
        for enc in ['utf-16le','utf-16be']:
            try: yield enc, data[:1_000_000].decode(enc,'ignore')
            except Exception: pass
    printable_ratio = sum(1 for b in sample if 32 <= b < 127 or b in b'\r\n\t') / max(1, len(sample))
    if printable_ratio > .70 or b'{' in sample or b'}' in sample:
        try: yield 'latin1', data[:1_000_000].decode('latin1','ignore')
        except Exception: pass

def _atbash(s: str) -> str:
    out=[]
    for ch in s:
        if 'a' <= ch <= 'z': out.append(chr(ord('z')-(ord(ch)-ord('a'))))
        elif 'A' <= ch <= 'Z': out.append(chr(ord('Z')-(ord(ch)-ord('A'))))
        else: out.append(ch)
    return ''.join(out)

def _try_text_decoders(txt: str) -> list[tuple[str,str,bytes]]:
    outs=[]
    vals=[('reverse_all', txt[::-1]), ('url', urllib.parse.unquote_plus(txt)), ('html', html.unescape(txt))]
    try: vals.append(('quoted_printable', quopri.decodestring(txt.encode()).decode('utf-8','ignore')))
    except Exception: pass
    for n,v in vals:
        if v and v != txt: outs.append((n,v,v.encode()))
    return outs

def _png_lsb_texts(data: bytes, limit_pixels: int = 1_200_000) -> list[tuple[str,str]]:
    if not data.startswith(b'\x89PNG\r\n\x1a\n'):
        return []
    try:
        pos=8; w=h=ct=bd=None; idat=[]
        while pos+8 <= len(data):
            ln=struct.unpack('>I', data[pos:pos+4])[0]; typ=data[pos+4:pos+8]; chunk=data[pos+8:pos+8+ln]; pos += 12+ln
            if typ == b'IHDR':
                w,h,bd,ct,_,_,_ = struct.unpack('>IIBBBBB', chunk)
            elif typ == b'IDAT': idat.append(chunk)
            elif typ == b'IEND': break
        if not w or not h or bd != 8 or ct not in (2,6,0): return []
        channels={0:1,2:3,6:4}[ct]; raw=zlib.decompress(b''.join(idat))
        bpp=channels; stride=w*bpp; rows=[]; i=0; prev=[0]*stride
        for _ in range(h):
            if i >= len(raw): break
            filt=raw[i]; i+=1; cur=list(raw[i:i+stride]); i+=stride
            for x in range(stride):
                left=cur[x-bpp] if x>=bpp else 0; up=prev[x]; ul=prev[x-bpp] if x>=bpp else 0
                if filt==1: cur[x]=(cur[x]+left)&255
                elif filt==2: cur[x]=(cur[x]+up)&255
                elif filt==3: cur[x]=(cur[x]+((left+up)//2))&255
                elif filt==4:
                    pp=left+up-ul; pa=abs(pp-left); pb=abs(pp-up); pc=abs(pp-ul); pr=left if pa<=pb and pa<=pc else (up if pb<=pc else ul)
                    cur[x]=(cur[x]+pr)&255
            rows.extend(cur); prev=cur
            if len(rows)//channels > limit_pixels: break
        outs=[]
        chan_names=['r','g','b','a'][:channels]
        for bit in [0,1,2]:
            for ci,name in enumerate(chan_names):
                bits=''.join(str((rows[j]>>bit)&1) for j in range(ci, len(rows), channels))
                for idx,t in enumerate(_bits_to_text_variants(bits)[:4]): outs.append((f'png-lsb-{name}-bit{bit}-v{idx}', t))
            bits=''.join(str((v>>bit)&1) for v in rows)
            for idx,t in enumerate(_bits_to_text_variants(bits)[:4]): outs.append((f'png-lsb-all-bit{bit}-v{idx}', t))
        return outs[:80]
    except Exception:
        return []

def _wav_lsb_texts(data: bytes) -> list[tuple[str,str]]:
    if not (data[:4] == b'RIFF' and data[8:12] == b'WAVE'):
        return []
    try:
        pos=12; pcm=b''
        while pos+8 <= len(data):
            typ=data[pos:pos+4]; ln=int.from_bytes(data[pos+4:pos+8],'little'); chunk=data[pos+8:pos+8+ln]; pos += 8+ln+(ln&1)
            if typ == b'data': pcm=chunk[:1_500_000]; break
        outs=[]
        for bit in [0,1]:
            bits=''.join(str((b>>bit)&1) for b in pcm)
            for idx,t in enumerate(_bits_to_text_variants(bits)[:4]): outs.append((f'wav-lsb-bit{bit}-v{idx}', t))
        return outs[:20]
    except Exception:
        return []

def _decode_layers(report: dict, root: Path, label: str, data: bytes, depth: int, seen: set[bytes]) -> list[dict]:
    arts=[]
    if depth > 4 or not data: return arts
    sig=data[:64]
    if sig in seen: return arts
    seen.add(sig)
    for enc, txt in _candidate_texts(data):
        if scan_any_flags(report, txt, f"SLOPER v89 {label} {enc}", None, "Decoded text contained promoted alternate/strict flag.", 800):
            pass
        zws=_zero_width_variants(txt)
        if zws:
            payload=json.dumps([{"preview":z[:4000]} for z in zws[:80]],indent=2,ensure_ascii=False)
            a=artifact(root, report, f"v89_{safe_name(label)}_zero_width_candidates.json", payload, "sloper89_zero_width", "Zero-width bitstream decoded with multiple maps/offsets/endian modes.", 610)
            if a: arts.append(a)
            for zw in zws[:80]:
                scan_any_flags(report, zw, "SLOPER v89 zero-width", a.get('path') if a else None, "Zero-width channel produced flag-like token.", 850)
        # Classic transforms over evidence text
        # Classic ciphers are text-only. Keep bounded to avoid wasting time on binary blobs decoded as text.
        if quality_text(txt[:4000]) >= 35 or re.search(r"[{}A-Za-z0-9_]{8,}", txt[:4000]):
            chunks=[txt[:12000]] + [ln.strip() for ln in txt.splitlines()[:600] if 4 <= len(ln.strip()) <= 4000]
        else:
            chunks=[]
        outs=[]
        for ch in chunks[:450]:
            for n in range(1,26):
                out=_rot(ch,n)
                if scan_any_flags(report,out,f"SLOPER v89 ROT{n}",None,"Caesar/ROT transform produced a flag.",830): outs.append({"method":f"rot{n}","text":out[:2000]})
            out=_atbash(ch)
            if scan_any_flags(report,out,"SLOPER v89 atbash",None,"Atbash transform produced a flag.",830): outs.append({"method":"atbash","text":out[:2000]})
            if re.fullmatch(r"[.\-/| _\n\r\t]+", ch.strip()) and len(re.findall(r"[.-]+", ch)) >= 4:
                out=_morse_decode(ch)
                if out.strip():
                    norm = out.replace("?", "_")
                    m = re.search(r"CTF_?CS_([A-Z0-9_]+)_?$", norm)
                    if m:
                        out = "ctf_cs{" + m.group(1).strip("_").lower() + "}"
                    else:
                        m = re.search(r"CTF\s*_?\s*CS\s*_?\s*([A-Z0-9 _-]{4,80})", norm)
                        if m:
                            out = "ctf_cs{" + re.sub(r"[^a-z0-9]+", "_", m.group(1).lower()).strip("_") + "}"
                    if scan_any_flags(report,out,"SLOPER v89 morse",None,"Morse decode produced a flag.",840): outs.append({"method":"morse","text":out[:2000]})
            if len(re.findall(r"[ABab]{5}", ch)) >= 2:
                for inv in [False, True]:
                    out=_bacon_decode(ch,inv)
                    if "ctf_cs{}" in txt.lower() and re.fullmatch(r"[A-Z]{4,80}", out):
                        out = "ctf_cs{" + out.lower() + "}"
                    elif re.fullmatch(r"[A-Z]{6,80}", out) and re.search(r"FLAG|SECRET|CTF", out):
                        out = "ctf_cs{" + out.lower() + "}"
                    if scan_any_flags(report,out,"SLOPER v89 bacon",None,"Bacon A/B decode produced a flag.",835): outs.append({"method":"bacon_inv" if inv else "bacon","text":out[:2000]})
        if outs:
            a=artifact(root, report, f"v89_{safe_name(label)}_classic_candidates.json", json.dumps(outs[:200],indent=2,ensure_ascii=False), "sloper89_classic", "ROT/Morse/Bacon transforms that produced promoted flags.", 620)
            if a: arts.append(a)
        # Common textual encodings (base64/base32/hex/url/html/unicode escapes/reversed blobs).
        enc_outs=[]
        is_binary_text = re.fullmatch(r"[01\s]+", txt.strip()[:200000] or "") is not None
        blob_limit_text = txt[:300000] if (not is_binary_text and (quality_text(txt[:4000]) >= 30 or re.search(r"[A-Za-z0-9+/=]{16,}", txt[:4000]))) else ""
        blobs=re.findall(r"[A-Za-z0-9+/=_%-]{8,10000}", blob_limit_text)[:500]
        # Base85/Ascii85 often use punctuation, so add compact printable tokens separately.
        b85_blobs=re.findall(r"[!-~]{10,10000}", blob_limit_text)[:120]
        for blob in list(dict.fromkeys(blobs + b85_blobs)):
            tries=[('raw', blob), ('reverse', blob[::-1])]
            for tname, val in tries:
                for name, func in [
                    ('base64', lambda x: base64.b64decode(x + '='*((4-len(x)%4)%4), validate=False)),
                    ('base32', lambda x: base64.b32decode(x + '='*((8-len(x)%8)%8), casefold=True)),
                    ('hex', lambda x: binascii.unhexlify(re.sub(r'[^0-9a-fA-F]','',x)) if len(re.sub(r'[^0-9a-fA-F]','',x))%2==0 else b''),
                    ('base85', lambda x: base64.b85decode(x)),
                    ('ascii85', lambda x: base64.a85decode(x, adobe=False, ignorechars=b' \t\n\r\v')),
                ]:
                    try:
                        raw=func(val)
                        if raw and 2 <= len(raw) <= 200000:
                            t=raw.decode('utf-8','ignore')
                            hit = scan_any_flags(report,t,f"SLOPER v89 {tname}-{name}",None,"Textual encoding decoded to a flag.",835)
                            magic = raw.startswith((b'\x1f\x8b\x08', b'PK\x03\x04', b'BZh', b'\xfd7zXZ', b'\x78\x9c', b'\x78\xda'))
                            plausible = hit or magic or quality_text(t) >= 55 or re.search(r'[A-Za-z0-9+/=]{12,}', t)
                            if plausible and depth < 4:
                                subarts = _decode_layers(report, root, f"{label}_{tname}_{name}", raw, depth+1, seen)
                                if subarts or hit:
                                    enc_outs.append({'method':tname+'-'+name,'input':blob[:80],'preview':t[:2000]})
                                    arts += subarts
                    except Exception: pass
        try:
            u=bytes(txt, 'utf-8').decode('unicode_escape')
            if u != txt and scan_any_flags(report,u,'SLOPER v89 unicode_escape',None,'Unicode escape decoding produced a flag.',820): enc_outs.append({'method':'unicode_escape','preview':u[:2000]})
        except Exception: pass
        for dname, dtext, draw in _try_text_decoders(txt[:300000]):
            if scan_any_flags(report, dtext, f'SLOPER v89 {dname}', None, f'{dname} text transform produced a flag.', 825):
                enc_outs.append({'method':dname,'preview':dtext[:2000]})
            # Do not recursively rescan full-text reversible transforms; blob decoders handle chained encodings.
            # This avoids exponential reverse/url/html loops on normal readable text.
        if enc_outs:
            a=artifact(root, report, f"v89_{safe_name(label)}_textual_decoders.json", json.dumps(enc_outs[:240],indent=2,ensure_ascii=False), "sloper89_textual_decoders", "Base/hex/reverse/unicode decoders that produced flags.", 630)
            if a: arts.append(a)

        # Binary ASCII octets.
        if re.fullmatch(r"[01\s]+", txt.strip()[:200000]) and len(re.findall(r"[01]{8}", txt)) >= 3:
            raw=bytes(int(b,2) for b in re.findall(r"[01]{8}", txt[:200000]))
            t=raw.decode('utf-8','ignore')
            if scan_any_flags(report,t,'SLOPER v89 binary-ascii',None,'Binary octets decoded to text flag.',830):
                a=artifact(root, report, f"v89_{safe_name(label)}_binary_ascii.txt", t, "sloper89_binary_ascii", "Binary octets decoded as ASCII.", 610)
                if a: arts.append(a)

        # Single-byte XOR brute force for small opaque blobs.
        if len(data) <= 120000 and not data.startswith((b'\x89PNG', b'RIFF', b'PK\x03\x04', b'\x1f\x8b')):
            xor_hits=[]
            for k in range(1,256):
                raw=bytes(b ^ k for b in data[:80000])
                t=raw.decode('utf-8','ignore')
                if scan_any_flags(report,t,f"SLOPER v89 xor-key-{k:02x}",None,"Single-byte XOR produced a flag.",845):
                    xor_hits.append({'key':k,'preview':t[:2000]})
            if xor_hits:
                a=artifact(root, report, f"v89_{safe_name(label)}_single_byte_xor.json", json.dumps(xor_hits[:80],indent=2,ensure_ascii=False), "sloper89_xor", "Single-byte XOR keys that produced promoted flags.", 640)
                if a: arts.append(a)

        # CSV column/row joining.
        if ',' in txt and len(txt) <= 200000:
            try:
                rows=list(csv.reader(io.StringIO(txt)))[:3000]
                for col in range(min(8, max((len(r) for r in rows), default=0))):
                    joined=''.join((r[col] if col < len(r) else '') for r in rows)
                    joined2=''.join((r[col] if col < len(r) and not r[col].isdigit() else '') for r in rows)
                    scan_any_flags(report, joined, f"SLOPER v89 csv-col-{col}", None, "CSV column values joined into a flag.", 825)
                    scan_any_flags(report, joined2, f"SLOPER v89 csv-col-{col}-nondigits", None, "CSV nonnumeric column values joined into a flag.", 825)
            except Exception: pass

        # CSV / chunk joins / decimal offsets
        tokens=re.findall(r"[A-Za-z0-9_{}\-:+./=]{1,80}", txt)
        for sep in ["", "_", " "]:
            joined=sep.join(tokens[:500])
            scan_any_flags(report, joined, "SLOPER v89 token-join", None, "Separated tokens joined into a flag-like token.", 790)
        nums=[int(x) for x in re.findall(r"(?<![A-Za-z0-9])-?\d{2,5}(?![A-Za-z0-9])", txt[:200000])[:4000]]
        if nums:
            for off in [0,32,48,64,100,1000]:
                raw=bytes((n-off)&255 for n in nums if 0 <= n-off <= 255)
                if raw:
                    t=raw.decode('utf-8','ignore')
                    if scan_any_flags(report,t,f"SLOPER v89 numeric-minus-{off}",None,"Numeric byte table decoded with offset.",820):
                        a=artifact(root, report, f"v89_{safe_name(label)}_numeric_minus_{off}.txt", t[:200000], "sloper89_numeric", "Numeric byte table decoded with common offset.", 600)
                        if a: arts.append(a)
    # Image/audio LSB text channels (bounded, no external tools required).
    for mname, mt in _png_lsb_texts(data) + _wav_lsb_texts(data):
        if scan_any_flags(report, mt, f"SLOPER v89 {mname}", None, "Media LSB channel decoded to flag-like text.", 860):
            a=artifact(root, report, f"v89_{safe_name(label)}_{safe_name(mname)}.txt", mt[:200000], "sloper89_media_lsb", "PNG/WAV LSB decoded text candidate.", 660)
            if a: arts.append(a)

    # Compression / archive recursion, including appended streams.
    for off in [m.start() for m in re.finditer(b"\x1f\x8b\x08", data[:2_000_000])][:20]:
        try:
            raw=zlib.decompress(data[off:], 16+zlib.MAX_WBITS)
            a=artifact(root, report, f"v89_{safe_name(label)}_gzip_at_{off}.bin", raw, "sloper89_gzip", "Gzip stream carved and recursively scanned.", 650)
            if a: arts.append(a)
            arts += _decode_layers(report, root, f"{label}_gzip_{off}", raw, depth+1, seen)
        except Exception: pass
    if data.startswith(b"PK\x03\x04") or b"PK\x03\x04" in data[:4096]:
        try:
            bio=io.BytesIO(data[data.find(b"PK\x03\x04"):])
            with zipfile.ZipFile(bio) as z:
                for info in z.infolist()[:80]:
                    if info.is_dir() or info.file_size > 3_000_000: continue
                    raw=z.read(info)
                    a=artifact(root, report, f"v89_zip_{safe_name(info.filename)}", raw, "sloper89_zip_member", "ZIP member extracted and recursively scanned.", 640)
                    if a: arts.append(a)
                    arts += _decode_layers(report, root, f"zip_{info.filename}", raw, depth+1, seen)
        except Exception: pass
    for aname, opener in [
        ('bz2', lambda b: bz2.decompress(b)),
        ('xz', lambda b: lzma.decompress(b)),
        ('zlib', lambda b: zlib.decompress(b)),
    ]:
        try:
            raw=opener(data)
            if raw and raw != data:
                a=artifact(root, report, f"v89_{safe_name(label)}_{aname}.bin", raw, f"sloper89_{aname}", f"{aname} stream decompressed and recursively scanned.", 635)
                if a: arts.append(a)
                arts += _decode_layers(report, root, f"{label}_{aname}", raw, depth+1, seen)
        except Exception: pass
    try:
        # Avoid tarfile.is_tarfile on arbitrary streams; only try when TAR magic/header shape is present.
        looks_tar = len(data) >= 512 and (data[257:262] == b'ustar' or data[257:263] == b'ustar\0' or data[:100].rstrip(b'\0 '))
        if looks_tar and (len(data) % 512 == 0 or data[257:262] == b'ustar'):
            bio=io.BytesIO(data)
            with tarfile.open(fileobj=bio) as tf:
                for info in tf.getmembers()[:80]:
                    if not info.isfile() or info.size > 3_000_000: continue
                    fh=tf.extractfile(info)
                    if not fh: continue
                    raw=fh.read()
                    a=artifact(root, report, f"v89_tar_{safe_name(info.name)}", raw, "sloper89_tar_member", "TAR member extracted and recursively scanned.", 630)
                    if a: arts.append(a)
                    arts += _decode_layers(report, root, f"tar_{info.name}", raw, depth+1, seen)
    except Exception: pass
    return arts

def run_v89(report: dict, root: Path, data: bytes) -> list[dict]:
    report.setdefault("flags", []); report.setdefault("artifacts", []); report.setdefault("workflow_evidence", [])
    arts=[]
    try:
        arts += _decode_layers(report, Path(root), safe_name(report.get('name','input')), bytes(data or b''), 0, set())
    except Exception as e:
        agent_crash("v89 decode layers", e, report)
    # Re-scan generated text artifacts from older layers so strict-only outputs become promoted alternate flags.
    try:
        for a in list(report.get('artifacts', []))[:2000]:
            p=Path(a.get('path',''))
            if p.is_file() and p.stat().st_size <= 2_000_000:
                raw=p.read_bytes()
                txt=raw.decode('utf-8','ignore')
                scan_any_flags(report, txt, "SLOPER v89 artifact rescan", str(p), "Previous solver artifact contained an alternate-format/braced flag.", 815)
    except Exception as e:
        agent_crash("v89 artifact rescan", e, report)
    report['flags'] = [f for f in list(dict.fromkeys(report.get('flags', []))) if _body(f).lower() not in DECOY and _good_body(_body(f), str(f))][:200]
    report['alternate_flag_candidates'] = sorted(report.get('alternate_flag_candidates', []), key=lambda x:int(x.get('score',0)), reverse=True)[:300]
    if arts:
        report.setdefault('next_steps', []).insert(0,{"priority":110,"step":"Review v89 universal finishing artifacts first.","why":"v89 recursively decoded/compressed/alternate flag formats and promoted evidence-backed {bracket} flags."})
    return arts

def install(mod):
    old_run=getattr(mod,'sl_run_agents',None)
    def sl_run_agents(report, root, data):
        arts=[]
        if old_run:
            try:
                prev=old_run(report, root, data)
                if prev: arts+=prev
            except Exception as e:
                agent_crash('pre-v89 sl_run_agents', e, report)
        try:
            new=run_v89(report, Path(root), bytes(data or b''))
            if new: arts+=new
        except Exception as e:
            agent_crash('v89 universal layer', e, report)
        try:
            if hasattr(mod,'sl_finalize_report'): mod.sl_finalize_report(report)
        except Exception as e:
            agent_crash('v89 sl_finalize_report', e, report)
        return arts
    mod.sl_run_agents=sl_run_agents

    old_summary=getattr(mod,'project_summary',None)
    def project_summary(reports, meta):
        summary=old_summary(reports, meta) if old_summary else {'flags':[], 'artifacts':[]}
        flags=[]; alts=[]
        for r in reports:
            for f in r.get('flags',[]) or []:
                if isinstance(f,str) and f not in flags: flags.append(f)
            for a in r.get('alternate_flag_candidates',[]) or []:
                if isinstance(a,dict): alts.append(a)
        for f in flags:
            if f not in summary.get('flags',[]): summary.setdefault('flags',[]).append(f)
        seen=set(); out=[]
        for a in sorted(alts, key=lambda x:int(x.get('score',0)), reverse=True):
            val=a.get('value') or a.get('candidate')
            if val and val not in seen:
                out.append(a); seen.add(val)
        summary['alternate_flag_candidates']=out[:200]
        summary['sloper89_review_lanes']={'alternate_promoted_flags':len([f for f in flags if not str(f).lower().startswith('ctf_cs{')]), 'alternate_candidates':len(out)}
        return summary
    mod.project_summary=project_summary
    mod.sl89_run_universal=run_v89
    mod.sl89_scan_any_flags=scan_any_flags
    return mod
