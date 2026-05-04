# Auto-split from sloper_legacy_monolith.py lines 13243-...
def sl44_cmp_validation_agent(report, root, data):
    p=Path(report.get("path",""))
    if report.get("kind") not in ["binary","generic","python_bytecode"] and p.suffix.lower() not in [".elf",".exe",".bin",".so",".dll",""]:
        return []
    if not exists("objdump") or len(data)>30_000_000:
        return []
    try:
        r=run(["objdump","-d","-Mintel",str(p)],18)
        dis=r.get("out","")[:2_000_000]
    except Exception:
        return []
    groups=sl44_extract_cmp_immediates_from_objdump(dis)
    if not groups:
        return []
    candidates=[]
    for g in groups[:80]:
        seq=bytes(g["values"])
        # Try raw/reverse/xor/add/sub because validation often compares transformed input to immediates.
        transforms=[("raw",None,seq),("reverse",None,seq[::-1])]
        for k in range(256):
            transforms.append(("xor",k,bytes(b^k for b in seq)))
            if k<128:
                transforms.append(("sub",k,bytes((b-k)&255 for b in seq)))
                transforms.append(("add",k,bytes((b+k)&255 for b in seq)))
        for method,key,bs in transforms:
            txt=bs.decode("utf-8","ignore")
            sc=sl44_good_text(txt)
            if sc>=170:
                flags=vf_primary_flags(txt,limit=10,scan_limit=10000)
                candidates.append({"method":method,"key":key,"text":txt[:5000],"hex":bs.hex(),"score":sc,"flags":flags,"lines":g.get("lines",[])[:12]})
    if not candidates:
        return []
    best=[]; seen=set()
    for c in sorted(candidates,key=lambda x:x.get("score",0),reverse=True):
        k=(c["method"],c.get("key"),c["text"][:160])
        if k not in seen:
            seen.add(k); best.append(c)
        if len(best)>=120: break
    art=sl44_art(root,report,"reverse_cmp_validation_candidates.json",json.dumps(best,indent=2,ensure_ascii=False),"sloper44_reverse_cmp_validation",300,"Recovered and transformed immediate values from cmp validation instructions.")
    if art:
        for c in best[:40]:
            sl44_promote_text(report,c["text"],"SLOPER v44 CMP Validation",f"{c['method']} key={c.get('key')}",art.get("path"),320)
        return [art]
    return []
def sl44_find_dense_byte_arrays(data, max_arrays=90):
    """Find dense non-text-ish byte runs that may be encoded arrays in binary/rodata."""
    data=bytes(data or b"")
    arrays=[]
    # Search local windows around printable strings and nonzero runs.
    # Keep bounded: scan first 8MB.
    sample=data[:8_000_000]
    # Runs separated by 0x00, lengths 6..160, with enough nonzero variation.
    cur=[]; start=0
    for i,b in enumerate(sample):
        if b==0:
            if 6<=len(cur)<=180 and len(set(cur))>=4:
                arrays.append({"offset":start,"values":cur[:]})
                if len(arrays)>=max_arrays: break
            cur=[]; start=i+1
        else:
            if not cur: start=i
            cur.append(b)
            if len(cur)>180:
                if len(set(cur))>=4:
                    arrays.append({"offset":start,"values":cur[:180]})
                    if len(arrays)>=max_arrays: break
                cur=[]; start=i+1
    # Immediate-looking byte sequences from hex text embedded in binaries.
    text=sample.decode("latin1","ignore")
    for m in re.finditer(r"(?:0x[0-9a-fA-F]{1,2}[\s,;]+){6,80}",text):
        vals=[int(x,16) for x in re.findall(r"0x([0-9a-fA-F]{1,2})",m.group(0))]
        if 6<=len(vals)<=180 and len(set(vals))>=4:
            arrays.append({"offset":m.start(),"values":vals})
            if len(arrays)>=max_arrays: break
    out=[]; seen=set()
    for a in arrays:
        vals=tuple(a["values"])
        if vals not in seen:
            seen.add(vals); out.append(a)
    return out[:max_arrays]
def sl44_byte_array_combo_agent(report, root, data):
    p=Path(report.get("path",""))
    if report.get("kind") not in ["binary","generic","python_bytecode"] and p.suffix.lower() not in [".elf",".exe",".bin",".so",".dll",".dat"]:
        return []
    if len(data)>25_000_000:
        return []
    arrays=sl44_find_dense_byte_arrays(data, max_arrays=70)
    if not arrays:
        return []
    candidates=[]
    # Single array brute transforms.
    for a in arrays[:50]:
        seq=bytes(a["values"])
        for method,key,bs in [("raw",None,seq),("reverse",None,seq[::-1]),("not",None,bytes((~b)&255 for b in seq))]:
            txt=bs.decode("utf-8","ignore")
            sc=sl44_good_text(txt)
            if sc>=165:
                candidates.append({"source":"single","offset":a["offset"],"method":method,"key":key,"text":txt[:5000],"hex":bs.hex(),"score":sc})
        for k in range(256):
            for method,bs in [("xor",bytes(b^k for b in seq)),("sub",bytes((b-k)&255 for b in seq)),("add",bytes((b+k)&255 for b in seq))]:
                txt=bs.decode("utf-8","ignore")
                sc=sl44_good_text(txt)
                if sc>=190:
                    candidates.append({"source":"single","offset":a["offset"],"method":method,"key":k,"text":txt[:5000],"hex":bs.hex(),"score":sc})
    # Pairwise arrays: common pattern key-array XOR data-array or add/sub masks.
    for i,a in enumerate(arrays[:24]):
        for b in arrays[i+1:24]:
            av=bytes(a["values"]); bv=bytes(b["values"])
            n=min(len(av),len(bv),160)
            if n<6: continue
            pairs=[
                ("xor_pair",bytes(av[j]^bv[j] for j in range(n))),
                ("sub_pair",bytes((av[j]-bv[j])&255 for j in range(n))),
                ("add_pair",bytes((av[j]+bv[j])&255 for j in range(n))),
                ("xor_pair_rev",bytes(av[j]^bv[n-1-j] for j in range(n))),
            ]
            for method,bs in pairs:
                txt=bs.decode("utf-8","ignore")
                sc=sl44_good_text(txt)
                if sc>=190:
                    candidates.append({"source":"pair","offset_a":a["offset"],"offset_b":b["offset"],"method":method,"text":txt[:5000],"hex":bs.hex(),"score":sc})
    if not candidates:
        return []
    best=[]; seen=set()
    for c in sorted(candidates,key=lambda x:x.get("score",0),reverse=True):
        k=(c["method"],c.get("key"),c["text"][:180])
        if k not in seen:
            seen.add(k); best.append(c)
        if len(best)>=150: break
    art=sl44_art(root,report,"byte_array_transform_candidates.json",json.dumps(best,indent=2,ensure_ascii=False),"sloper44_byte_array_transforms",270,"Decoded binary byte arrays using raw/reverse/xor/add/sub/not and pairwise array transforms.")
    if art:
        for c in best[:50]:
            sl44_promote_text(report,c["text"],"SLOPER v44 ByteArray",c["method"],art.get("path"),290)
        return [art]
    return []
def sl44_image_transform_agent(report, root, data):
    p=Path(report.get("path",""))
    if report.get("kind")!="image" and p.suffix.lower() not in [".png",".jpg",".jpeg",".bmp",".gif",".webp",".tif",".tiff"]:
        return []
    if len(data)>8_000_000:
        return []
    try:
        from PIL import Image, ImageOps, ImageEnhance
    except Exception:
        sl44_trace(report,"ImageTransform","Pillow unavailable",0)
        return []
    arts=[]
    try:
        img=Image.open(p)
        img.load()
    except Exception as e:
        sl44_trace(report,"ImageTransform failed",str(e),0)
        return []
    # Bound dimensions.
    max_side=1200
    if max(img.size)>max_side:
        img.thumbnail((max_side,max_side))
    outdir=root/"generated"/"sloper44"/safe(report.get("name","file"))/"image_transforms"
    outdir.mkdir(parents=True,exist_ok=True)
    transforms=[]
    try:
        gray=ImageOps.grayscale(img)
        transforms += [
            ("gray",gray),
            ("invert",ImageOps.invert(gray)),
            ("autocontrast",ImageOps.autocontrast(gray)),
            ("threshold_96",gray.point(lambda x:255 if x>96 else 0)),
            ("threshold_128",gray.point(lambda x:255 if x>128 else 0)),
            ("threshold_160",gray.point(lambda x:255 if x>160 else 0)),
            ("contrast2",ImageEnhance.Contrast(gray).enhance(2.0)),
            ("contrast4",ImageEnhance.Contrast(gray).enhance(4.0)),
        ]
        for angle in [90,180,270]:
            transforms.append((f"rotate_{angle}",gray.rotate(angle,expand=True)))
        # Channels and bitplanes.
        rgba=img.convert("RGBA")
        for idx,chname in enumerate(["r","g","b","a"]):
            ch=rgba.getchannel(idx)
            transforms.append((f"channel_{chname}",ch))
            for bit in range(8):
                bp=ch.point(lambda x,bit=bit:255 if (x>>bit)&1 else 0)
                transforms.append((f"bitplane_{chname}{bit}",bp))
    except Exception as e:
        sl44_trace(report,"ImageTransform build failed",str(e),0)
    # Save bounded count.
    saved=[]
    for name,im in transforms[:48]:
        try:
            out=outdir/(safe(name)+".png")
            im.save(out)
            art={"kind":"sloper44_image_transform","name":out.name,"path":str(out),"url":"/api/raw?path="+str(out),"source":"CTF SLOPER v44","score":210,"note":f"Image transform: {name}. OCR/QR attempted when tools exist.","exists":True,"size":out.stat().st_size,"file":report.get("rel","")}
            report.setdefault("artifacts",[]).append(art); report.setdefault("transformations",[]).append(art); arts.append(art); saved.append(out)
        except Exception:
            pass
    # OCR/QR transformed outputs with tools.
    ocr_hits=[]
    for out in saved[:48]:
        try:
            if exists("zbarimg"):
                r=run(["zbarimg","--quiet",str(out)],8)
                txt=r.get("out","").strip()
                if txt:
                    ocr_hits.append({"tool":"zbarimg","image":out.name,"text":txt})
                    sl44_promote_text(report,txt,"SLOPER v44 TransformQR",out.name,str(out),270)
            # Tesseract only for fewer likely transforms to keep performance sane.
            if exists("tesseract") and any(k in out.name for k in ["threshold","invert","autocontrast","rotate","bitplane_a","bitplane_r0","bitplane_g0","bitplane_b0"]):
                r=run(["tesseract",str(out),"stdout","--psm","6"],10)
                txt=r.get("out","").strip()
                if txt and sl44_good_text(txt)>=115:
                    ocr_hits.append({"tool":"tesseract","image":out.name,"text":txt[:3000]})
                    sl44_promote_text(report,txt,"SLOPER v44 TransformOCR",out.name,str(out),210)
        except Exception:
            pass
    if ocr_hits:
        art=sl44_art(root,report,"image_transform_ocr_qr_hits.json",json.dumps(ocr_hits,indent=2,ensure_ascii=False),"sloper44_image_transform_ocr_hits",260,"OCR/QR results from generated image transforms.")
        if art: arts.append(art)
    if arts:
        sl44_trace(report,"ImageTransform",f"{len(saved)} transform images generated; {len(ocr_hits)} OCR/QR hits",240,arts[0].get("path"))
    return arts
def sl44_rail_fence_decode(s, rails):
    if rails<=1: return s
    pattern=list(range(rails))+list(range(rails-2,0,-1))
    plen=len(pattern)
    rail_counts=[0]*rails
    for i in range(len(s)):
        rail_counts[pattern[i%plen]]+=1
    rails_data=[]; pos=0
    for c in rail_counts:
        rails_data.append(list(s[pos:pos+c])); pos+=c
    out=[]
    idx=[0]*rails
    for i in range(len(s)):
        r=pattern[i%plen]
        out.append(rails_data[r][idx[r]])
        idx[r]+=1
    return "".join(out)
def sl44_vigenere_decode(s,key):
    out=[]; ki=0
    key=[ord(c.lower())-97 for c in key if c.isalpha()]
    if not key: return s
    for ch in s:
        if ch.isalpha():
            base=65 if ch.isupper() else 97
            out.append(chr((ord(ch)-base-key[ki%len(key)])%26+base))
            ki+=1
        else:
            out.append(ch)
    return "".join(out)
def sl44_bacon_decode(s):
    bits=[]
    for ch in str(s):
        if ch in "aA0. ": bits.append("0")
        elif ch in "bB1-_": bits.append("1")
    if len(bits)<25: return ""
    alpha="abcdefghijklmnopqrstuvwxyz"
    out=[]
    for i in range(0,len(bits)-4,5):
        v=int("".join(bits[i:i+5]),2)
        out.append(alpha[v] if v<26 else "?")
    return "".join(out)
def sl44_every_nth_candidates(s):
    outs=[]
    s=str(s)
    if not (12<=len(s)<=5000): return outs
    for n in range(2,min(18,len(s)//3)+1):
        for off in range(n):
            dec=s[off::n]
            if len(dec)>=6 and sl44_good_text(dec)>=150:
                outs.append({"method":f"every_{n}_offset_{off}","output":dec,"score":sl44_good_text(dec)})
    # interleave split halves
    for n in range(2,8):
        chunks=[s[i::n] for i in range(n)]
        for order in [chunks, list(reversed(chunks))]:
            dec="".join(order)
            if sl44_good_text(dec)>=150:
                outs.append({"method":f"deinterleave_{n}","output":dec,"score":sl44_good_text(dec)})
    return outs
def sl44_classic_crypto_agent(report, root, data):
    if report.get("kind") not in ["text","generic"] and Path(report.get("path","")).suffix.lower() not in [".txt",".log",".md",".csv",".json",".dat",".enc"]:
        return []
    text=data[:300000].decode("utf-8","ignore")
    if not text.strip(): return []
    hint=(ux_statement_text(report)+" "+Path(report.get("path","")).name+" "+text[:1500]).lower()
    lines=[x.strip() for x in text.splitlines() if 6<=len(x.strip())<=2000]
    outs=[]
    # Only run broadly on clue-ish or compact text, otherwise bounded.
    broad=any(k in hint for k in ["crypto","cipher","šifr","sifr","rail","bacon","vigenere","key","raktas","kas antr","every","route"])
    for line in lines[:80 if broad else 25]:
        # Rail fence
        for rails in range(2,9):
            dec=sl44_rail_fence_decode(line,rails)
            sc=sl44_good_text(dec)
            if sc>=155: outs.append({"method":f"rail_fence_{rails}","input":line,"output":dec,"score":sc})
        # Every nth/deinterleave
        outs += [{"method":x["method"],"input":line,"output":x["output"],"score":x["score"]} for x in sl44_every_nth_candidates(line)]
        # Bacon
        dec=sl44_bacon_decode(line)
        if dec and sl44_good_text(dec)>=130:
            outs.append({"method":"bacon","input":line,"output":dec,"score":sl44_good_text(dec)})
        # Vigenere with project clues / common CTF keys
        keys=["key","secret","raktas","slapta","ctf","cyber","sprint"]
        try:
            for c in sl42_extract_clue_values(sl42_report_text_blob(report))[:20]:
                v=c.get("value","")
                if v.isalpha() and 2<=len(v)<=24:
                    keys.append(v)
        except Exception:
            pass
        for key in list(dict.fromkeys(keys))[:40]:
            dec=sl44_vigenere_decode(line,key)
            sc=sl44_good_text(dec)
            if sc>=170:
                outs.append({"method":f"vigenere_{key}","input":line,"output":dec,"score":sc})
    if not outs: return []
    best=[]; seen=set()
    for x in sorted(outs,key=lambda y:y.get("score",0),reverse=True):
        k=(x["method"],x["output"][:180])
        if k not in seen:
            seen.add(k); best.append(x)
        if len(best)>=180: break
    art=sl44_art(root,report,"classic_crypto_candidates.json",json.dumps(best,indent=2,ensure_ascii=False),"sloper44_classic_crypto",235,"Rail fence, every-nth, deinterleave, Bacon and Vigenere candidates.")
    if art:
        for x in best[:60]:
            sl44_promote_text(report,x["output"],"SLOPER v44 ClassicCrypto",x["method"],art.get("path"),250)
        return [art]
    return []
def sl44_run_agents(report, root, data):
    arts=[]
    try: arts += sl44_cmp_validation_agent(report,root,data)
    except Exception as e: sl44_trace(report,"CMPValidation failed",str(e),0)
    try: arts += sl44_byte_array_combo_agent(report,root,data)
    except Exception as e: sl44_trace(report,"ByteArrayCombo failed",str(e),0)
    try: arts += sl44_image_transform_agent(report,root,data)
    except Exception as e: sl44_trace(report,"ImageTransform failed",str(e),0)
    try: arts += sl44_classic_crypto_agent(report,root,data)
    except Exception as e: sl44_trace(report,"ClassicCrypto failed",str(e),0)
    try: sl_finalize_report(report)
    except Exception: pass
    return arts
_prev_sl_run_agents_v44 = sl_run_agents
def sl_run_agents(report, root, data):
    arts=[]
    try:
        prev=_prev_sl_run_agents_v44(report,root,data)
        if prev: arts += prev
    except Exception as e:
        sl44_trace(report,"previous agents failed",str(e),0)
    try:
        arts += sl44_run_agents(report,root,data) or []
    except Exception as e:
        sl44_trace(report,"v44 agents failed",str(e),0)
    return arts
_prev_sl43_artifact_should_autopass_v44 = sl43_artifact_should_autopass
def sl43_artifact_should_autopass(a):
    try:
        kind=str(a.get("kind","")).lower()
        name=str(a.get("name","")).lower()
        if "sloper44" in kind and any(k in kind+name for k in ["ocr","decoded","extract","payload","classic","byte_array","cmp","text"]):
            p=Path(a.get("path",""))
            return p.exists() and p.is_file() and 0<p.stat().st_size<5_000_000
    except Exception:
        pass
    return _prev_sl43_artifact_should_autopass_v44(a)
_prev_project_summary_v44 = project_summary
def project_summary(reports, meta):
    summary=_prev_project_summary_v44(reports, meta)
    # v44 artifact priority and capability counters.
    caps={"reverse":0,"stego_image":0,"crypto":0,"autopass":0}
    for a in summary.get("artifacts",[]):
        txt=(str(a.get("source",""))+" "+str(a.get("kind",""))+" "+str(a.get("name",""))).lower()
        if "cmp" in txt or "byte_array" in txt or "reverse" in txt: caps["reverse"]+=1
        if "image_transform" in txt or "ocr" in txt or "qr" in txt: caps["stego_image"]+=1
        if "classic_crypto" in txt or "decode_chain" in txt or "xor" in txt or "rsa" in txt: caps["crypto"]+=1
        if "autopass" in txt: caps["autopass"]+=1
    summary["sloper44_capability_hits"]=caps
    def pri(a):
        s=int(a.get("score",0) or 0)
        txt=(str(a.get("source",""))+" "+str(a.get("kind",""))+" "+str(a.get("name",""))).lower()
        if "sloper44" in txt or "v44" in txt: s+=2600
        if "sloper43" in txt or "v43" in txt: s+=2000
        if "sloper42" in txt or "v42" in txt: s+=1300
        if any(k in txt for k in ["cmp","byte_array","image_transform","ocr","classic_crypto","rail","vigenere","bacon"]): s+=500
        return (bool(a.get("exists",False)),s,int(a.get("size",0) or 0))
    summary["artifacts"]=sorted(summary.get("artifacts",[]),key=pri,reverse=True)[:2800]
    na=summary.get("sloper43_next_actions",[]) or summary.get("sloper42_next_actions",[]) or []
    if any(caps.values()):
        na.insert(0,{"priority":96,"step":"Review v44 capability artifacts.","why":"v44 generated stronger reverse/stego/crypto artifacts that may contain the next solve step."})
    summary["sloper44_next_actions"]=na[:20]
    summary["workflow_steps"]=na[:20]+summary.get("workflow_steps",[])[:20]
    return summary
APP_TITLE = "CTF SLOPER v44"
def sl44_has_promoted_flag(report):
    try:
        return bool([f for f in report.get("flags",[]) if smartsolve_strict_target_flag_ok(f)])
    except Exception:
        return bool(report.get("flags"))
def sl44_visual_hint(report):
    hint=(ux_statement_text(report)+" "+str(report.get("name",""))).lower()
    return any(k in hint for k in [
        "stego","lsb","filtr","filter","vaizd","image","paveiksl","nuotrauk",
        "matosi","raid", "ocr", "qr", "bitplane", "alpha", "kanal", "spalv",
        "piet", "tile", "paslepta vaizde", "hidden in image"
    ])
_prev_sl44_image_transform_agent_perf = sl44_image_transform_agent
def sl44_image_transform_agent(report, root, data):
    # If the project already has a strong flag from embedded payload / decode, avoid slow visual brute.
    if sl44_has_promoted_flag(report) and not sl44_visual_hint(report):
        sl44_trace(report,"ImageTransform skipped","Promoted flag already exists; skipped heavy visual transforms.",120)
        return []
    return _prev_sl44_image_transform_agent_perf(report,root,data)
_prev_sl44_run_agents_perf = sl44_run_agents
def sl44_run_agents(report, root, data):
    arts=[]
    # Reverse/byte-array can still be useful for binary, but skip expensive optional extras after solved.
    try:
        arts += sl44_cmp_validation_agent(report,root,data)
    except Exception as e: sl44_trace(report,"CMPValidation failed",str(e),0)
    try:
        if not sl44_has_promoted_flag(report):
            arts += sl44_byte_array_combo_agent(report,root,data)
    except Exception as e: sl44_trace(report,"ByteArrayCombo failed",str(e),0)
    try:
        arts += sl44_image_transform_agent(report,root,data)
    except Exception as e: sl44_trace(report,"ImageTransform failed",str(e),0)
    try:
        if not sl44_has_promoted_flag(report):
            arts += sl44_classic_crypto_agent(report,root,data)
    except Exception as e: sl44_trace(report,"ClassicCrypto failed",str(e),0)
    try: sl_finalize_report(report)
    except Exception: pass
    return arts
def sl45_trace(report, stage, detail, confidence=0, artifact=None, flag=None):
    try:
        sl44_trace(report, "v45:"+str(stage), detail, confidence, artifact, flag)
    except Exception:
        report.setdefault("solve_trace", []).append({
            "stage":"SLOPER v45:"+str(stage),
            "detail":str(detail)[:1200],
            "confidence":int(confidence or 0),
            "artifact":artifact or "",
            "flag":flag or ""
        })
def sl45_art(root, report, name, content, kind="sloper45_artifact", score=160, note=""):
    outdir=root/"generated"/"sloper45"/safe(report.get("name","file"))
    outdir.mkdir(parents=True, exist_ok=True)
    p=outdir/safe(name)
    try:
        if isinstance(content,(bytes,bytearray)):
            p.write_bytes(content)
        else:
            p.write_text(str(content),encoding="utf-8",errors="ignore")
        art={"kind":kind,"name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"CTF SLOPER v45","score":int(score),"note":note or kind,"exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
        report.setdefault("artifacts",[]).append(art)
        report.setdefault("transformations",[]).append(art)
        sl45_trace(report,"artifact",f"{kind}: {p.name}",score,str(p))
        return art
    except Exception as e:
        sl45_trace(report,"artifact failed",f"{name}: {e}",0)
        return None
def sl45_text_from_bytes(raw):
    raw=bytes(raw or b"")
    for enc in ["utf-8","latin1"]:
        try:
            return raw.decode(enc,"ignore")
        except Exception:
            pass
    return ""
def sl45_promote_answer_markers(report, text, source, artifact=None, score=310):
    text=str(text or "")
    found=0
    # Strict flags first.
    try:
        found += sl_promote_text(report,text,source,"strict ctf_cs or braced body in answer text",artifact,score)
    except Exception:
        pass
    # FLAG: body / VELIAVA: body / ANSWER: body style.
    marker_re=r"(?im)^\s*(?:FLAG|VELIAVA|VĖLIAVA|ANSWER|ATSAKYMAS)\s*[:=]\s*([A-Za-z0-9_\-:.+]{4,180})\s*$"
    for m in re.finditer(marker_re,text):
        body=m.group(1).strip().strip("{}")
        if not body:
            continue
        cand=f"ctf_cs{{{body}}}"
        if smartsolve_strict_target_flag_ok(cand) and not sl42_is_bad_wrapper_body(body):
            if cand not in report.setdefault("flags",[]):
                report["flags"].append(cand)
            report.setdefault("answer_candidates",[]).append({"value":body,"source":source,"why":"FLAG/ANSWER marker body wrapped with ctf_cs{...}.","score":score})
            report.setdefault("flag_wrapping_helpers",[]).append({"answer":body,"suggested_flag":cand,"source":source,"score":score,"why":"FLAG/ANSWER marker body."})
            sl45_trace(report,"AnswerMarker",f"{m.group(0).strip()} -> {cand}",score,artifact,cand)
            found+=1
    return found
def sl45_decode_morse_variants(text):
    vals=[]
    text=str(text or "")
    for line in text.splitlines():
        # Extract chunks containing dots/dashes/spaces/slashes.
        chunks=re.findall(r"(?:[.\-]{1,6}(?:\s+|/|$)){3,}",line)
        for ch in chunks:
            try:
                dec=sl42_decode_morse(ch)
            except Exception:
                dec=""
            if dec:
                vals.append(dec.strip())
                vals.append(dec.strip().replace(" ","_"))
                vals.append(dec.strip().upper().replace(" ",""))
                vals.append(dec.strip().lower().replace(" ",""))
    out=[]; seen=set()
    for v in vals:
        v=str(v).strip()
        if 2<=len(v)<=120 and v.lower() not in seen:
            seen.add(v.lower()); out.append(v)
    return out
def sl45_collect_passwords(report, extra_text=""):
    vals=[]
    # Existing v42 clue extractor.
    try:
        vals += [c.get("value","") for c in sl42_extract_clue_values(sl42_report_text_blob(report)+"\n"+str(extra_text))]
    except Exception:
        pass
    text=(sl42_report_text_blob(report) if "sl42_report_text_blob" in globals() else "")+"\n"+str(extra_text)
    vals += sl45_decode_morse_variants(text)
    # Direct EXIF/comment patterns can contain Morse or password-like values.
    for m in re.finditer(r"(?i)(?:comment|description|important|note|password|pass|pwd|key|raktas)\s*[:=]\s*([^\n\r]{3,160})",text):
        val=m.group(1).strip().strip("'\"")
        vals.append(val)
        vals += sl45_decode_morse_variants(val)
    # More variants.
    expanded=[]
    for v in vals:
        v=str(v).strip()
        if not v or len(v)>160: continue
        expanded += [
            v, v.lower(), v.upper(),
            v.replace(" ",""), v.replace(" ","_"),
            v.replace("_",""), v.replace("_","-"), v.replace("-","_"),
            v.title().replace(" ","")
        ]
    expanded += ["", "password","secret","slapta","raktas","ctf","cyber","sprint","LIETUVA","lietuva","Lietuva"]
    out=[]; seen=set()
    for v in expanded:
        v=str(v).strip()
        if len(v)<=160 and v.lower() not in seen:
            seen.add(v.lower()); out.append(v)
    return out[:350]
def sl45_exif_comment_agent(report, root, path):
    p=Path(path)
    if not p.exists() or not exists("exiftool"):
        return []
    arts=[]
    try:
        r=run(["exiftool",str(p)],12)
        out=r.get("out","")[:120000]
        if out.strip():
            report.setdefault("outputs",[]).append({"tool":"sloper45_exiftool_full","ok":r.get("ok"),"cmd":r.get("cmd"),"out":out[:60000]})
            art=sl45_art(root,report,"exiftool_full.txt",out,"sloper45_exif_metadata",210,"Full EXIF/metadata output used for clues.")
            if art: arts.append(art)
            # Morse decode in comments.
            vals=sl45_decode_morse_variants(out)
            if vals:
                mart=sl45_art(root,report,"exif_morse_decoded_passwords.json",json.dumps(vals,indent=2,ensure_ascii=False),"sloper45_exif_morse_passwords",260,"Morse decoded from EXIF/comment fields.")
                if mart: arts.append(mart)
                for v in vals:
                    report.setdefault("answer_candidates",[]).append({"value":v,"source":"SLOPER v45 EXIF Morse","why":"Morse decoded from image metadata/comment. May be password or answer body.","score":230})
                sl45_trace(report,"EXIF Morse",f"decoded passwords/clues: {vals[:8]}",260,mart.get("path") if mart else "")
    except Exception as e:
        sl45_trace(report,"EXIF failed",str(e),0)
    return arts
def sl45_extract_targz_agent(report, root, data):
    p=Path(report.get("path",""))
    name=p.name.lower()
    if not (name.endswith(".tar.gz") or name.endswith(".tgz") or name.endswith(".tar") or data[:3]==b"\x1f\x8b\x08"):
        return []
    import tarfile, gzip as _gzip, io as _io
    arts=[]
    raw=bytes(data or b"")
    # If gzip may contain tar, try tarfile directly and via decompressed bytes.
    tar_blobs=[]
    try:
        if tarfile.is_tarfile(p):
            tar_blobs.append(("file",str(p)))
    except Exception:
        pass
    try:
        if data[:3]==b"\x1f\x8b\x08":
            dec=_gzip.decompress(raw)
            tar_blobs.append(("bytes",dec))
            dart=sl45_art(root,report,"gzip_decompressed.bin",dec,"sloper45_gzip_decompressed",180,"Gzip decompressed bytes; checked for TAR/children.")
            if dart: arts.append(dart)
    except Exception:
        pass
    outdir=root/"generated"/"sloper45"/safe(report.get("name","file"))/"tar_extract"
    outdir.mkdir(parents=True,exist_ok=True)
    extracted=[]
    for kind,obj in tar_blobs:
        try:
            tf = tarfile.open(obj, mode="r:*") if kind=="file" else tarfile.open(fileobj=_io.BytesIO(obj), mode="r:*")
            for m in tf.getmembers()[:300]:
                if not m.isfile(): continue
                # Skip AppleDouble resource fork noise unless it is the only useful file.
                base=Path(m.name).name
                if base.startswith("._"):
                    meta={"name":m.name,"size":m.size,"skipped":"AppleDouble resource fork"}
                    extracted.append(meta)
                    continue
                f=tf.extractfile(m)
                if not f: continue
                child=f.read(20_000_000)
                out=outdir/safe(m.name)
                out.parent.mkdir(parents=True,exist_ok=True)
                out.write_bytes(child)
                art={"kind":"sloper45_tar_child","name":out.name,"path":str(out),"url":"/api/raw?path="+str(out),"source":"CTF SLOPER v45","score":260,"note":f"Extracted TAR/TGZ child: {m.name}","exists":True,"size":out.stat().st_size,"file":report.get("rel","")}
                report.setdefault("artifacts",[]).append(art); report.setdefault("transformations",[]).append(art); arts.append(art)
                extracted.append({"name":m.name,"size":m.size,"path":str(out)})
                # Immediate child analysis helpers for image/archive/text.
                txt=sl45_text_from_bytes(child[:400000])
                sl45_promote_answer_markers(report,txt,"SLOPER v45 TAR child",str(out),280)
                try:
                    # embedded compression in child
                    sf_embedded_compression_agent(report,root,child)
                except Exception:
                    pass
                try:
                    # EXIF/Morse + embedded encrypted zip for image child
                    sl45_exif_comment_agent(report,root,out)
                    sl45_embedded_zip_password_agent(report,root,child, child_path=out)
                except Exception as e:
                    sl45_trace(report,"TAR child chained analysis failed",f"{out.name}: {e}",0)
        except Exception as e:
            sl45_trace(report,"TAR extract failed",str(e),0)
    if extracted:
        manifest=sl45_art(root,report,"tar_extract_manifest.json",json.dumps(extracted,indent=2,ensure_ascii=False),"sloper45_tar_manifest",230,"TAR/TGZ extraction manifest.")
        if manifest: arts.append(manifest)
        sl45_trace(report,"TAR/TGZ",f"extracted/scanned {len(extracted)} members",260,manifest.get("path") if manifest else "")
    return arts
def sl45_embedded_zip_password_agent(report, root, data, child_path=None):
    import zipfile as _zipfile, io as _io
    data=bytes(data or b"")
    arts=[]
    positions=[m.start() for m in re.finditer(b"PK\x03\x04",data)]
    if not positions:
        return []
    extra=""
    try:
        if child_path:
            extra += "\n"+Path(child_path).read_bytes()[:300000].decode("utf-8","ignore")
    except Exception:
        pass
    passwords=sl45_collect_passwords(report, extra_text=extra)
    outbase=root/"generated"/"sloper45"/safe(report.get("name","file"))/"embedded_zip_passwords"
    outbase.mkdir(parents=True,exist_ok=True)
    manifests=[]
    for off in positions[:40]:
        blob=data[off:]
        bio=_io.BytesIO(blob)
        if not _zipfile.is_zipfile(bio):
            continue
        try:
            bio.seek(0)
            with _zipfile.ZipFile(bio) as z:
                names=z.namelist()
                zmanifest={"offset":off,"names":names,"passwords_tried":0,"success_password":None,"extracted":[]}
                # Save carved zip itself.
                zpath=outbase/f"embedded_{off}.zip"
                if not zpath.exists():
                    zpath.write_bytes(blob)
                zart={"kind":"sloper45_embedded_zip_carved","name":zpath.name,"path":str(zpath),"url":"/api/raw?path="+str(zpath),"source":"CTF SLOPER v45","score":250,"note":f"Embedded ZIP carved at byte offset {off}.","exists":True,"size":zpath.stat().st_size,"file":report.get("rel","")}
                report.setdefault("artifacts",[]).append(zart); report.setdefault("transformations",[]).append(zart); arts.append(zart)
                # Try passwords. Empty first for unencrypted.
                for pw in passwords[:180]:
                    ok_any=False
                    zmanifest["passwords_tried"]+=1
                    for n in names[:80]:
                        try:
                            raw=z.read(n,pwd=(pw.encode() if pw else None))
                            outdir=outbase/(f"embedded_{off}_pw_"+safe(pw or "empty"))
                            outdir.mkdir(parents=True,exist_ok=True)
                            out=outdir/safe(n)
                            out.parent.mkdir(parents=True,exist_ok=True)
                            out.write_bytes(raw)
                            ok_any=True
                            zmanifest["success_password"]=pw
                            zmanifest["extracted"].append({"name":n,"size":len(raw),"path":str(out)})
                            cart={"kind":"sloper45_embedded_zip_extracted_child","name":out.name,"path":str(out),"url":"/api/raw?path="+str(out),"source":"CTF SLOPER v45","score":330,"note":f"Extracted embedded ZIP file {n} using password {pw!r}.","exists":True,"size":out.stat().st_size,"file":report.get("rel","")}
                            report.setdefault("artifacts",[]).append(cart); report.setdefault("transformations",[]).append(cart); arts.append(cart)
                            txt=sl45_text_from_bytes(raw[:500000])
                            sl45_promote_answer_markers(report,txt,"SLOPER v45 Embedded ZIP",str(out),360)
                            try: sf_embedded_compression_agent(report,root,raw)
                            except Exception: pass
                        except RuntimeError:
                            # encrypted / bad password
                            pass
                        except Exception:
                            pass
                    if ok_any:
                        sl45_trace(report,"Embedded ZIP password",f"offset {off} extracted with password {pw!r}",340,str(zpath))
                        break
                manifests.append(zmanifest)
        except Exception as e:
            sl45_trace(report,"Embedded ZIP failed",f"offset {off}: {e}",0)
    if manifests:
        mart=sl45_art(root,report,"embedded_zip_password_manifest.json",json.dumps(manifests,indent=2,ensure_ascii=False),"sloper45_embedded_zip_password_manifest",300,"Embedded ZIP password extraction manifest.")
        if mart: arts.append(mart)
    return arts
def sl45_chain_agent(report, root, data):
    arts=[]
    p=Path(report.get("path",""))
    # Metadata/Morse clues first for images and archives.
    try:
        if p.exists():
            arts += sl45_exif_comment_agent(report,root,p)
    except Exception as e:
        sl45_trace(report,"metadata failed",str(e),0)
    try:
        arts += sl45_extract_targz_agent(report,root,data)
    except Exception as e:
        sl45_trace(report,"targz failed",str(e),0)
    try:
        arts += sl45_embedded_zip_password_agent(report,root,data,child_path=p)
    except Exception as e:
        sl45_trace(report,"embedded zip password failed",str(e),0)
    # Answer marker from the raw file if text-like.
    try:
        txt=sl45_text_from_bytes(data[:500000])
        sl45_promote_answer_markers(report,txt,"SLOPER v45 direct answer marker",str(p),280)
    except Exception:
        pass
    try: sl_finalize_report(report)
    except Exception: pass
    return arts
_prev_sl_run_agents_v45 = sl_run_agents
def sl_run_agents(report, root, data):
    arts=[]
    try:
        prev=_prev_sl_run_agents_v45(report,root,data)
        if prev: arts += prev
    except Exception as e:
        sl45_trace(report,"previous agents failed",str(e),0)
    try:
        arts += sl45_chain_agent(report,root,data) or []
    except Exception as e:
        sl45_trace(report,"v45 chain failed",str(e),0)
    return arts
_prev_project_summary_v45 = project_summary
def project_summary(reports, meta):
    summary=_prev_project_summary_v45(reports, meta)
    # v45 capability counters.
    caps=summary.get("sloper44_capability_hits",{}) or {}
    caps["archive_chain"]=0
    caps["exif_morse"]=0
    caps["embedded_zip_password"]=0
    for a in summary.get("artifacts",[]):
        txt=(str(a.get("source",""))+" "+str(a.get("kind",""))+" "+str(a.get("name",""))).lower()
        if "tar" in txt or "targz" in txt or "gzip" in txt: caps["archive_chain"]+=1
        if "morse" in txt or "exif" in txt: caps["exif_morse"]+=1
        if "embedded_zip" in txt or "password_manifest" in txt: caps["embedded_zip_password"]+=1
    summary["sloper45_capability_hits"]=caps
    def pri(a):
        s=int(a.get("score",0) or 0)
        txt=(str(a.get("source",""))+" "+str(a.get("kind",""))+" "+str(a.get("name",""))).lower()
        if "sloper45" in txt or "v45" in txt: s+=3200
        if "sloper44" in txt or "v44" in txt: s+=2400
        if "sloper43" in txt or "v43" in txt: s+=1900
        if any(k in txt for k in ["embedded_zip","password","morse","exif","tar_child","answer"]): s+=650
        return (bool(a.get("exists",False)),s,int(a.get("size",0) or 0))
    summary["artifacts"]=sorted(summary.get("artifacts",[]),key=pri,reverse=True)[:3200]
    na=summary.get("sloper44_next_actions",[]) or summary.get("sloper43_next_actions",[]) or summary.get("sloper42_next_actions",[]) or []
    if caps.get("embedded_zip_password") or caps.get("exif_morse"):
        na.insert(0,{"priority":98,"step":"Review v45 archive/password chain artifacts.","why":"v45 found metadata/Morse/password or embedded archive evidence."})
    summary["sloper45_next_actions"]=na[:24]
    summary["workflow_steps"]=na[:24]+summary.get("workflow_steps",[])[:20]
    return summary
APP_TITLE = "CTF SLOPER v45"
def sl45_promote_answer_markers(report, text, source, artifact=None, score=310):
    text=str(text or "")
    found=0
    try:
        found += sl_promote_text(report,text,source,"strict ctf_cs or braced body in answer text",artifact,score)
    except Exception:
        pass
    # Handles:
    # FLAG: abc
    # ║   FLAG: abc   ║
    # [FLAG] abc
    marker_re=r"(?im)(?:^|[^A-Za-z0-9_])(?:FLAG|VELIAVA|VĖLIAVA|ANSWER|ATSAKYMAS)\s*[\]:= -]+\s*([A-Za-z0-9_\-:.+]{4,180})"
    for m in re.finditer(marker_re,text):
        body=m.group(1).strip().strip("{}").strip(".,;|║│ ")
        if not body:
            continue
        cand=f"ctf_cs{{{body}}}"
        if smartsolve_strict_target_flag_ok(cand) and not sl42_is_bad_wrapper_body(body):
            if cand not in report.setdefault("flags",[]):
                report["flags"].append(cand)
            report.setdefault("answer_candidates",[]).append({"value":body,"source":source,"why":"Decorated FLAG/ANSWER marker body wrapped with ctf_cs{...}.","score":score})
            report.setdefault("flag_wrapping_helpers",[]).append({"answer":body,"suggested_flag":cand,"source":source,"score":score,"why":"Decorated FLAG/ANSWER marker body."})
            sl45_trace(report,"AnswerMarker",f"{m.group(0).strip()} -> {cand}",score,artifact,cand)
            found+=1
    return found
def sl45_is_fast_archive_path(p):
    name=Path(p).name.lower()
    return name.endswith(".tgz") or name.endswith(".tar.gz") or name.endswith(".tar")
def sl45_fast_archive_analyze_file(pid, path, root, i, total):
    p=Path(path)
    data=p.read_bytes()
    rel=str(p.relative_to(root)) if str(p).startswith(str(root)) else p.name
    report={
        "id":uuid.uuid4().hex[:10],"name":p.name,"path":str(p),"rel":rel,"kind":"archive",
        "size":len(data),"sha256":hashlib.sha256(data).hexdigest(),"md5":hashlib.md5(data).hexdigest(),"magic":data[:32].hex(),
        "flags":[],"weak_flag_candidates":[],"verified_flags":[],"verified_flags_visible":[],"strings":[],"outputs":[],"previews":[],
        "commands":[],"decoders":[],"chain_results":[],"intermediate_files":[],"artifacts":[],"transformations":[],"findings":[],
        "next_steps":[],"solve_trace":[],"agent_trace":[],"answer_candidates":[],"flag_wrapping_helpers":[],"evidence_scored_candidates":[]
    }
    try: report["strings"]=py_strings(data,limit=1200)
    except Exception: report["strings"]=[]
    # Lightweight metadata only.
    try:
        if exists("file"):
            r=run(["file",str(p)],4)
            report["outputs"].append({"tool":"file","ok":r.get("ok"),"cmd":r.get("cmd"),"out":r.get("out","")[:12000]})
    except Exception:
        pass
    # Direct flag scan, then v45 archive/stego chain.
    try:
        sl45_promote_answer_markers(report,"\n".join(report.get("strings",[])),"SLOPER v45 fast archive strings",str(p),230)
    except Exception:
        pass
    try:
        sl45_chain_agent(report,root,data)
    except Exception as e:
        sl45_trace(report,"fast archive chain failed",str(e),0)
    try:
        sl_finalize_report(report)
    except Exception:
        pass
    if report.get("flags"):
        report["findings"].insert(0,{"score":560,"type":"sloper45_fast_archive_flag","value":report["flags"][0],"why":"Fast archive chain recovered evidence-backed ctf_cs flag."})
    else:
        report["next_steps"].append({"priority":92,"step":"Inspect v45 archive chain artifacts.","why":"Fast archive path extracted child files and scanned metadata/password clues."})
    return report
_prev_analyze_file_v45_fast_archive = analyze_file
def analyze_file(pid, path, root, i, total):
    try:
        p=Path(path)
        if sl45_is_fast_archive_path(p):
            return sl45_fast_archive_analyze_file(pid,path,root,i,total)
    except Exception:
        pass
    return _prev_analyze_file_v45_fast_archive(pid,path,root,i,total)
