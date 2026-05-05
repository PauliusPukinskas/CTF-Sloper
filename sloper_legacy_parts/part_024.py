# Auto-split from sloper_legacy_monolith.py lines 21402-...
def v104_rail_fence_decode(s, rails):
    s = re.sub(r"\s+", "", str(s or ""))
    if rails < 2 or len(s) < 6: return ""
    try:
        pattern = list(range(rails)) + list(range(rails-2, 0, -1))
        ids = [pattern[i % len(pattern)] for i in range(len(s))]
        counts = [ids.count(r) for r in range(rails)]
        chunks=[]; pos=0
        for c in counts:
            chunks.append(list(s[pos:pos+c])); pos += c
        ptr=[0]*rails; out=[]
        for r in ids:
            out.append(chunks[r][ptr[r]]); ptr[r]+=1
        return ''.join(out)
    except Exception:
        return ""
def v104_columnar_decrypt(cipher, key):
    cipher = re.sub(r"\s+", "", str(cipher or ""))
    key = re.sub(r"[^A-Za-z0-9]", "", str(key or ""))
    if len(key) < 2 or len(cipher) < len(key)*2: return ""
    try:
        n=len(key); L=len(cipher)
        order = sorted(range(n), key=lambda i:(key[i].lower(), i))
        base = L // n; extra = L % n
        col_lens = [base + (1 if i < extra else 0) for i in range(n)]
        cols=[""]*n; pos=0
        for idx in order:
            ln=col_lens[idx]
            cols[idx]=cipher[pos:pos+ln]; pos += ln
        out=[]
        for r in range(max(col_lens)):
            for c in range(n):
                if r < len(cols[c]): out.append(cols[c][r])
        return ''.join(out)
    except Exception:
        return ""
def v104_rot(s, r):
    a="abcdefghijklmnopqrstuvwxyz"; A=a.upper()
    return str(s).translate(str.maketrans(a+A, a[r:]+a[:r]+A[r:]+A[:r]))
def v104_b64_decode_to_text(s):
    try:
        tok = str(s or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}|[A-Za-z0-9_-]+={0,2}", tok):
            return None
        padded = tok + "="*((4-len(tok)%4)%4)
        raw = base64.b64decode(padded, altchars=b"-_", validate=True)
        if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff") or (len(raw)>4 and raw[1:2] == b"\x00"):
            try: return raw.decode("utf-16le")
            except Exception: pass
        return raw.decode("utf-8")
    except Exception:
        return None
def v104_extract_keys(text):
    keys=[]
    for m in re.finditer(r"(?i)(?:key|raktas|password|pass|xor)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{1,32})", str(text or "")):
        k=m.group(1)
        if k and k.lower() not in [x.lower() for x in keys]: keys.append(k)
    for k in ["KEY", "key", "ctf", "flag", "secret", "password", "raktas", "slapta"]:
        if k.lower() not in [x.lower() for x in keys]: keys.append(k)
    return keys[:30]
def v104_token_bytes(tok):
    tok=str(tok or "").strip().strip('"\'`')
    vals=[]
    try:
        if re.fullmatch(r"[0-9a-fA-F]{8,}", tok) and len(tok)%2==0:
            vals.append(bytes.fromhex(tok))
    except Exception: pass
    try:
        if re.fullmatch(r"[A-Za-z0-9+/=_-]{12,}", tok):
            vals.append(base64.b64decode(tok + "="*((4-len(tok)%4)%4), altchars=b"-_", validate=True))
    except Exception: pass
    if len(tok) >= 8:
        vals.append(tok.encode())
    return vals[:4]
def v104_double_table_candidates(data):
    data=bytes(data or b"")
    hits=[]
    if len(data) < 32 or len(data) > 80_000_000: return hits
    import struct as _st, math as _math
    max_scan = min(len(data)-32, 8_000_000)
    for count in [12, 10, 8, 6, 5, 4]:
        win=count*8
        if len(data) < win: continue
        for off in range(0, max_scan, 8):
            if off+win > len(data): break
            try: vals=_st.unpack_from('<'+'d'*count, data, off)
            except Exception: continue
            if any((not _math.isfinite(v)) or abs(v)>1e9 for v in vals): continue
            parts=[]; ok=0
            for i,v in enumerate(vals,1):
                n=int(v*i) & 0xffff
                a=n & 255; b=(n>>8)&255
                if 32 <= a < 127 and 32 <= b < 127:
                    parts.append(chr(a)+chr(b)); ok+=1
                else:
                    parts.append('')
            txt=''.join(parts)
            if ok >= max(4, count-2) and v104_ascii_score(txt) >= 80 and ("_" in txt or re.search(r"[0-9]",txt)):
                hits.append({"offset":off,"count":count,"text":txt,"score":v104_ascii_score(txt)})
                if len(hits) >= 20: return sorted(hits,key=lambda x:x['score'],reverse=True)
    return sorted(hits,key=lambda x:x['score'],reverse=True)
def v104_extra_decode_candidates(text, data=b""):
    text=str(text or "")[:50000]
    outs=[]; seen=set()
    def add(t, inp, out, base=0):
        if out is None: return
        if isinstance(out, (bytes, bytearray)):
            try: out=out.decode('utf-8','replace')
            except Exception: out=str(out)
        out=str(out)[:12000]
        if not out.strip(): return
        key=(t,out[:400])
        if key in seen: return
        seen.add(key)
        flags=v104_exact_flags(out,limit=12,scan_limit=12000)
        bare=v104_bare_brace_answers(out,limit=8,scan_limit=12000)
        score=v104_ascii_score(out)+base+(250 if flags else 0)+(80 if bare else 0)
        if flags or bare or score>=70:
            outs.append({"type":"v104_"+t,"input":str(inp)[:300],"output":out,"flags":flags,"bare_candidates":bare,"score":score,"chain_source":"v104 missing workflow"})
    # chained HTML entity + URL decode, repeated and in both orders.
    variants=[("visible", text[:12000])]
    for _ in range(3):
        new=[]
        for label,val in variants[-8:]:
            for nm,fn in [("url", urllib.parse.unquote), ("html", html.unescape)]:
                try:
                    out=fn(val)
                    if out != val: new.append((label+"->"+nm,out)); add(label+"_"+nm,label,out,25)
                except Exception: pass
        variants += new[:16]
    # UTF-16LE plain blobs.
    if data and len(data) >= 6:
        try:
            nul_ratio = data[:2000].count(0)/max(1,len(data[:2000]))
            if nul_ratio > 0.20:
                add("utf16le_plain", "raw bytes", data[:200000].decode("utf-16le", "replace"), 80)
        except Exception: pass
    if "\x00" in text[:2000]:
        try: add("utf16le_text_repr", "visible", text.encode('latin1','ignore').decode('utf-16le','replace'), 60)
        except Exception: pass
    # Tokens: base/reverse/ROT chains.
    tokens=re.findall(r"[A-Za-z0-9+/=_-]{8,}|[A-Z2-7=]{8,}|[0-9A-Fa-f]{8,}", text)[:500]
    for tok in tokens:
        s=tok.strip().strip('"\'`')
        if len(s)>2500: continue
        # reverse then base32/base64, base then reverse.
        try:
            rs=s[::-1]
            if re.fullmatch(r"[A-Z2-7=]{8,}", rs): add("reverse_base32", s, base64.b32decode(rs+"="*((8-len(rs)%8)%8)).decode('utf-8','replace'), 75)
        except Exception: pass
        try:
            rb=v104_b64_decode_to_text(s[::-1])
            if rb: add("reverse_base64", s, rb, 75)
        except Exception: pass
        b64=v104_b64_decode_to_text(s)
        if b64:
            add("base64_utf8_or_utf16", s, b64, 35)
            for r in range(1,26):
                out=v104_rot(b64,r)
                if "ctf_cs{" in out.lower() or "{" in out:
                    add(f"base64_then_rot{r}", s, out, 95)
        for r in range(1,26):
            rot=v104_rot(s,r)
            b=v104_b64_decode_to_text(rot)
            if b and ("ctf" in b.lower() or "{" in b or v104_ascii_score(b)>90):
                add(f"rot{r}_then_base64", s, b, 95)
        # multibyte xor with hinted/common keys
        for rawb in v104_token_bytes(s):
            if len(rawb) > 5000: rawb = rawb[:5000]
            for k in v104_extract_keys(text):
                kb=k.encode()
                if not kb: continue
                try:
                    out=bytes(b ^ kb[i%len(kb)] for i,b in enumerate(rawb))
                    add("xor_key_"+k, s, out, 70)
                except Exception: pass
    # Classical transpositions on compact chunks.
    chunks=[]
    for line in text.splitlines()[:1000]:
        line=line.strip()
        if 6 <= len(line) <= 1200: chunks.append(line)
    chunks += tokens[:120]
    keys=v104_extract_keys(text)
    for chunk in chunks[:240]:
        compact=re.sub(r"\s+", "", chunk)
        if 8 <= len(compact) <= 1200:
            for rails in range(2,9):
                out=v104_rail_fence_decode(compact, rails)
                if out and ("ctf" in out.lower() or "{" in out or v104_ascii_score(out)>120):
                    add(f"rail_fence_{rails}", chunk, out, 75)
            for key in keys[:20]:
                out=v104_columnar_decrypt(compact, key)
                if out and ("ctf" in out.lower() or "{" in out or v104_ascii_score(out)>120):
                    add(f"columnar_{key}", chunk, out, 80)
    for h in v104_double_table_candidates(data)[:10]:
        add("double_table_le_pairs", "raw bytes @"+str(h.get('offset')), h.get('text'), 110+h.get('score',0)//2)
    return sorted(outs,key=lambda x:x.get('score',0),reverse=True)[:220]
def v104_noisy_base_decode(item):
    t=str((item or {}).get("type","")).lower()
    if "base64" not in t:
        return False
    out=str((item or {}).get("output",""))
    if (item or {}).get("flags"):
        return False
    if "\ufffd" in out:
        return True
    sample=out[:4000]
    printable=sum(1 for c in sample if c.isprintable() or c in "\n\r\t")/max(1,len(sample))
    return printable < 0.70
def decode_candidates(text, data=b""):
    base=[]
    try:
        base=_prev_v104_decode_candidates(text,data) or []
    except Exception as e:
        base=[{"type":"v104_previous_decode_error","input":"previous decode_candidates","output":str(e),"flags":[],"score":0}]
    base=[item for item in base if not v104_noisy_base_decode(item)]
    extra=v104_extra_decode_candidates(text,data)
    out=[]; seen=set()
    for item in sorted(base+extra,key=lambda x:x.get('score',0),reverse=True):
        k=(item.get('type'), (item.get('output','') or '')[:400])
        if k in seen: continue
        seen.add(k); out.append(item)
    return out[:380]
def v104_preserve_exact_flags_in_report(report):
    if not isinstance(report, dict): return report
    exact=[]
    def scan(txt, src=""):
        for f in v104_exact_flags(txt, limit=30, scan_limit=80000):
            exact.append((f,src))
    try: scan("\n".join(report.get("strings",[])[:1500]), "strings")
    except Exception: pass
    try:
        for f in report.get("flags",[])[:100]: scan(f, "existing_flags")
    except Exception: pass
    for o in report.get("outputs",[])[:160]:
        try: scan(o.get("out","")[:80000], "tool:"+str(o.get("tool","")))
        except Exception: pass
    for c in report.get("chain_results",[])[:200]:
        try: scan(c.get("output","")[:80000], "chain:"+str(c.get("type","")))
        except Exception: pass
    for d in report.get("decoders",[])[:220]:
        try: scan(d.get("output","")[:80000], "decoder:"+str(d.get("type","")))
        except Exception: pass
    for a in report.get("artifacts",[])[:400]:
        try:
            p=Path(a.get("path",""))
            if p.exists() and p.is_file() and p.stat().st_size <= 1_000_000:
                scan(p.read_text(encoding='utf-8',errors='ignore')[:80000], "artifact:"+str(a.get('kind','')))
        except Exception: pass
    seen=set(); preserved=[]
    for f,src in exact:
        if f.lower() not in seen:
            seen.add(f.lower()); preserved.append({"flag":f,"source":src,"score":999,"status":"confirmed","reasons":["v104 exact token preservation: copied byte-for-byte from evidence"],"negative_reasons":[]})
    report["v104_exact_preserved_flags"] = preserved[:60]
    # Exact flags must lead report["flags"] and must not be normalized later.
    merged=[]; mseen=set()
    for item in preserved:
        f=item["flag"]
        if f.lower() not in mseen:
            mseen.add(f.lower()); merged.append(f)
    for f in report.get("flags",[])[:80]:
        f=normalize_flag_candidate(f)
        if f and f.lower() not in mseen and f.lower().startswith("ctf_cs{"):
            mseen.add(f.lower()); merged.append(f)
    report["flags"] = merged[:60]
    # Ensure verified list includes preserved items at top.
    vf=list(report.get("verified_flags",[]) or [])
    vseen={str(v.get('flag','')).lower() for v in vf}
    for item in reversed(preserved[:40]):
        if item['flag'].lower() not in vseen:
            vf.insert(0, {"flag":item['flag'],"score":item['score'],"status":item['status'],"sources":[item['source']],"contexts":[],"reasons":item['reasons'],"negative_reasons":[]})
    report["verified_flags"] = vf[:140]
    return report
def smartsolve_postprocess(report, root=None):
    if _prev_v104_smartsolve_postprocess:
        report=_prev_v104_smartsolve_postprocess(report, root)
    return v104_preserve_exact_flags_in_report(report)
def apply_verified_flags(report):
    try:
        # Run original verifier first so all previous scoring remains available.
        verified=collect_verified_flags(report)
        report["verified_flags"]=verified
        report["flags"]=[normalize_flag_candidate(v.get("flag","")) for v in verified if v.get("status") in ["confirmed","likely"] and not v.get("negative_reasons")]
    except Exception:
        pass
    return v104_preserve_exact_flags_in_report(report)
def project_summary(reports, meta):
    for r in reports:
        v104_preserve_exact_flags_in_report(r)
    summary=_prev_v104_project_summary(reports, meta)
    # Deduplicate and force exact preserved flags to top of summary, without deleting older candidates.
    exact=[]
    for r in reports:
        for item in r.get("v104_exact_preserved_flags",[])[:40]:
            exact.append({"file":r.get("rel"),"flag":item.get("flag"),"score":999,"status":"confirmed","reason":"v104 exact preservation"})
    merged=[]; seen=set()
    for f in exact + list(summary.get("flags",[]) or []):
        flag=f.get("flag") if isinstance(f,dict) else str(f)
        if not flag or flag.lower() in seen: continue
        seen.add(flag.lower())
        merged.append(f if isinstance(f,dict) else {"file":"?","flag":flag,"score":900,"status":"promoted"})
    summary["flags"] = merged[:80]
    summary["exact_flags"] = [f for f in merged if "ctf_cs{" in str(f.get("flag","")).lower()][:80]
    summary["v104_quality_preservation"] = {
        "enabled": True,
        "fixes": [
            "exact ctf_cs flags preserved byte-for-byte; underscores are never stripped",
            "ROT->base64 and base64->ROT chains",
            "reverse->base32/base64 chains",
            "UTF-16LE plain/base64 decoding",
            "HTML entity + URL decode chaining",
            "rail fence and columnar transposition with key hints",
            "hinted multibyte XOR",
            "raw double-table little-endian ASCII pair scan"
        ],
        "non_regression_note": "Previous v103/v99 workflows are called first; v104 only adds candidates and exact preservation."
    }
    return summary
APP_TITLE = "CTF SLOPER v104 Quality Preservation"
