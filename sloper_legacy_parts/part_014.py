# Auto-split from sloper_legacy_monolith.py lines 12338-...
def sl42_archive_password_agent(report, root, data):
    """Collect clues from current report and try them on local/embedded archives."""
    arts=[]
    blob=sl42_report_text_blob(report)
    clues=sl42_extract_clue_values(blob)
    # Also read exiftool/comment outputs if file is image/archive and exiftool exists
    try:
        p=Path(report.get("path",""))
        if p.exists() and exists("exiftool"):
            r=run(["exiftool",str(p)],10)
            ex=r.get("out","")
            report.setdefault("outputs",[]).append({"tool":"sloper42_exiftool_clues","ok":r.get("ok"),"cmd":r.get("cmd"),"out":ex[:50000]})
            clues += sl42_extract_clue_values(ex)
    except Exception:
        pass
    # Save clue list
    if clues:
        art=sl42_art(root,report,"clue_password_candidates.json",json.dumps(clues,indent=2,ensure_ascii=False),"sloper42_clue_passwords",220,"Password/key candidates from labels, Morse, comments, decoded text and metadata.")
        if art: arts.append(art)
    # Try current archive and embedded zip artifacts
    paths=[]
    p=Path(report.get("path",""))
    if p.exists() and p.suffix.lower() in [".zip",".7z",".rar",".tgz",".tar",".gz"]:
        paths.append(p)
    for a in report.get("artifacts",[])[:300]:
        pp=Path(a.get("path",""))
        if pp.exists() and pp.suffix.lower() in [".zip",".7z",".rar",".tgz",".tar",".gz"]:
            paths.append(pp)
    for pp in list(dict.fromkeys(paths))[:30]:
        arts += sl42_try_extract_archive_with_passwords(report,root,pp,clues,pp.stem)
    return arts
def sl42_stego_password_agent(report, root, data):
    """Use clue passwords with steghide/stegseek on JPEG/WAV when present."""
    p=Path(report.get("path",""))
    if p.suffix.lower() not in [".jpg",".jpeg",".wav",".au",".bmp"]:
        return []
    arts=[]
    blob=sl42_report_text_blob(report)
    clues=sl42_extract_clue_values(blob)
    # Save wordlist
    words=[]
    for c in clues:
        v=str(c.get("value","")).strip()
        if v and v not in words:
            words += [v, v.lower(), v.upper(), v.replace("_",""), v.replace("_","-")]
    words += ["", "password","secret","slapta","raktas","ctf","cyber","sprint"]
    words=list(dict.fromkeys([w for w in words if len(w)<=120]))[:300]
    if not words: return []
    wordfile=root/"generated"/"sloper42"/safe(report.get("name","file"))/"stego_password_candidates.txt"
    wordfile.parent.mkdir(parents=True,exist_ok=True)
    wordfile.write_text("\n".join(words),encoding="utf-8")
    art=sl42_art(root,report,"stego_password_candidates.txt","\n".join(words),"sloper42_stego_passwords",190,"Password candidates for steghide/stegseek.")
    if art: arts.append(art)
    # Try steghide with top candidates
    if exists("steghide"):
        for pw in words[:80]:
            try:
                outdir=root/"generated"/"sloper42"/safe(report.get("name","file"))/"steghide_extract"
                outdir.mkdir(parents=True,exist_ok=True)
                before=set(outdir.rglob("*"))
                r=run(["steghide","extract","-sf",str(p),"-p",pw,"-xf",str(outdir/"extracted.bin"),"-f"],12)
                if r.get("ok") and (outdir/"extracted.bin").exists():
                    raw=(outdir/"extracted.bin").read_bytes()
                    cart={"kind":"sloper42_steghide_extract","name":"extracted.bin","path":str(outdir/"extracted.bin"),"url":"/api/raw?path="+str(outdir/"extracted.bin"),"source":"CTF SLOPER v42","score":310,"note":f"steghide extracted with password {pw!r}.","exists":True,"size":(outdir/"extracted.bin").stat().st_size,"file":report.get("rel","")}
                    report.setdefault("artifacts",[]).append(cart); report.setdefault("transformations",[]).append(cart); arts.append(cart)
                    txt=raw[:300000].decode("utf-8","ignore")
                    sl_promote_text(report,txt,"SLOPER v42 Steghide",f"steghide password {pw!r}",cart["path"],330)
                    sl42_trace(report,"Steghide",f"extracted with password {pw!r}",330,cart["path"])
                    break
            except Exception:
                pass
    # Try stegseek if installed with generated wordlist
    if exists("stegseek") and p.suffix.lower() in [".jpg",".jpeg"]:
        try:
            out=root/"generated"/"sloper42"/safe(report.get("name","file"))/"stegseek_extracted.bin"
            out.parent.mkdir(parents=True,exist_ok=True)
            r=run(["stegseek",str(p),str(wordfile),str(out)],25)
            if out.exists():
                raw=out.read_bytes()
                cart={"kind":"sloper42_stegseek_extract","name":out.name,"path":str(out),"url":"/api/raw?path="+str(out),"source":"CTF SLOPER v42","score":320,"note":"stegseek extracted using generated clue wordlist.","exists":True,"size":out.stat().st_size,"file":report.get("rel","")}
                report.setdefault("artifacts",[]).append(cart); report.setdefault("transformations",[]).append(cart); arts.append(cart)
                txt=raw[:300000].decode("utf-8","ignore")
                sl_promote_text(report,txt,"SLOPER v42 Stegseek","generated clue wordlist",cart["path"],330)
        except Exception:
            pass
    return arts
def sl42_pcap_covert_agent(report, root, data):
    p=Path(report.get("path",""))
    if p.suffix.lower() not in [".pcap",".pcapng"] and report.get("kind")!="pcap":
        return []
    if not exists("tshark"):
        return []
    arts=[]
    # More focused covert channels.
    fields=[
        ("ip_id_srcdst",["tshark","-r",str(p),"-T","fields","-e","frame.number","-e","ip.src","-e","ip.dst","-e","ip.id","-e","ip.ttl","-e","ip.len"]),
        ("tcp_seq_ack",["tshark","-r",str(p),"-Y","tcp","-T","fields","-e","frame.number","-e","tcp.seq","-e","tcp.ack","-e","tcp.window_size_value","-e","tcp.payload"]),
        ("icmp_payload",["tshark","-r",str(p),"-Y","icmp","-T","fields","-e","frame.number","-e","ip.id","-e","data.data"]),
        ("dns_labels",["tshark","-r",str(p),"-Y","dns","-T","fields","-e","dns.qry.name","-e","dns.txt"]),
    ]
    for name,cmd in fields:
        try:
            r=run(cmd,25)
            out=r.get("out","")[:800000]
            if not out.strip(): continue
            art=sl42_art(root,report,f"pcap_{name}.txt",out,"sloper42_pcap_fields",190,f"PCAP covert extraction fields: {name}")
            if art: arts.append(art)
            # decode hex payloads
            hex_ascii=[]
            for line in out.splitlines()[:5000]:
                for hx in re.findall(r"(?:[0-9a-fA-F]{2}:?){4,}",line):
                    h=re.sub(r"[^0-9a-fA-F]","",hx)
                    if len(h)%2==0:
                        try:
                            dec=bytes.fromhex(h).decode("utf-8","ignore")
                            if dec.strip(): hex_ascii.append(dec)
                        except Exception: pass
            if hex_ascii:
                txt="\n".join(hex_ascii)
                hart=sl42_art(root,report,f"pcap_{name}_hex_ascii.txt",txt,"sloper42_pcap_hex_ascii",260,f"Decoded hex payload fields from {name}.")
                if hart: arts.append(hart)
                sl_promote_text(report,txt,"SLOPER v42 PCAP",f"{name} hex payload ascii",hart.get("path") if hart else "",280)
            # scalar low-byte and delta
            nums=[]
            for tok in re.findall(r"0x[0-9a-fA-F]+|\b\d+\b",out):
                try: nums.append(int(tok,0))
                except Exception: pass
            if nums:
                variants={}
                variants["low8"]="".join(chr(n&255) if 32<=n&255<127 else "." for n in nums[:8000])
                variants["high8"]="".join(chr((n>>8)&255) if 32<=((n>>8)&255)<127 else "." for n in nums[:8000])
                variants["delta_low8"]="".join(chr((nums[i]-nums[i-1])&255) if 32<=((nums[i]-nums[i-1])&255)<127 else "." for i in range(1,min(len(nums),8000)))
                variants["xor_prev_low8"]="".join(chr((nums[i]^nums[i-1])&255) if 32<=((nums[i]^nums[i-1])&255)<127 else "." for i in range(1,min(len(nums),8000)))
                vart=sl42_art(root,report,f"pcap_{name}_scalar_variants.json",json.dumps({"count":len(nums),"variants":variants},indent=2),"sloper42_pcap_scalar",230,f"Scalar low/high/delta/xor variants from {name}.")
                if vart: arts.append(vart)
                for label,txt in variants.items():
                    sl_promote_text(report,txt,"SLOPER v42 PCAP Scalar",f"{name} {label}",vart.get("path") if vart else "",230)
            # DNS subdomains: base32/base64 labels
            if name=="dns_labels":
                labels=[]
                for fqdn in re.findall(r"[A-Za-z0-9_\-]{6,}(?:\.[A-Za-z0-9_\-]{2,})+",out):
                    labels += fqdn.split(".")
                decs=[]
                for lab in labels[:2000]:
                    decs += [x["text"] for x in sl42_decode_chain_text(lab,2) if x["method"]!="raw"]
                if decs:
                    dtxt="\n".join(decs)
                    dart=sl42_art(root,report,"pcap_dns_label_decodes.txt",dtxt,"sloper42_dns_label_decodes",240,"Decoded base/hex/url-like DNS labels.")
                    if dart: arts.append(dart)
                    sl_promote_text(report,dtxt,"SLOPER v42 DNS", "decoded DNS labels", dart.get("path") if dart else "",260)
        except Exception:
            pass
    if arts:
        sl42_trace(report,"PCAPCovert",f"{len(arts)} pcap covert artifacts",260,arts[0].get("path"))
    return arts
def sl42_apply_agents(report, root, data):
    arts=[]
    try: arts += sl42_archive_password_agent(report,root,data)
    except Exception as e: sl42_trace(report,"ArchivePassword failed",str(e),0)
    try: arts += sl42_stego_password_agent(report,root,data)
    except Exception as e: sl42_trace(report,"StegoPassword failed",str(e),0)
    try: arts += sl42_pcap_covert_agent(report,root,data)
    except Exception as e: sl42_trace(report,"PCAPCovert failed",str(e),0)
    # decode chain artifact from current text blob
    try:
        blob=sl42_report_text_blob(report)
        decs=sl42_decode_chain_text(blob[:200000],3)
        strong=[d for d in decs if vf_primary_flags(d["text"],limit=1,scan_limit=20000) or sf_is_compact_answer_text(d["text"]) or re.search(r"\{[A-Za-z0-9_\-:.+]{4,120}\}",d["text"])]
        if strong:
            art=sl42_art(root,report,"decode_chain_strong_candidates.json",json.dumps(strong[:200],indent=2,ensure_ascii=False),"sloper42_decode_chain",240,"Strong recursive decode-chain candidates.")
            if art: arts.append(art)
            for d in strong[:50]:
                sl_promote_text(report,d["text"],"SLOPER v42 DecodeChain",d["method"],art.get("path") if art else "",250)
    except Exception as e:
        sl42_trace(report,"DecodeChain failed",str(e),0)
    sl_finalize_report(report)
    return arts
_prev_sl_run_agents_v42 = sl_run_agents
def sl_run_agents(report, root, data):
    arts=[]
    try: arts += _prev_sl_run_agents_v42(report,root,data) or []
    except Exception as e: sl_trace(report,"previous sl agents failed",str(e),0)
    try: arts += sl42_apply_agents(report,root,data) or []
    except Exception as e: sl42_trace(report,"v42 agents failed",str(e),0)
    return arts
_prev_project_summary_v42 = project_summary
def project_summary(reports, meta):
    summary=_prev_project_summary_v42(reports, meta)
    # Project-level key propagation after file reports are collected.
    # If one file contains clue passwords and another archive/stego artifact exists,
    # make this visible in project summary.
    all_clues=[]
    all_archives=[]
    for r in reports:
        blob=sl42_report_text_blob(r) if isinstance(r,dict) else ""
        all_clues += sl42_extract_clue_values(blob)
        for a in r.get("artifacts",[]) if isinstance(r,dict) else []:
            if Path(a.get("path","")).suffix.lower() in [".zip",".7z",".rar",".tgz",".tar",".gz"]:
                all_archives.append(a)
    # Dedupe clues
    cseen=set(); clues=[]
    for c in sorted(all_clues,key=lambda x:x.get("score",0),reverse=True):
        k=c.get("value","").lower()
        if k and k not in cseen:
            cseen.add(k); clues.append(c)
    summary["sloper42_project_clues"]=clues[:80]
    summary["sloper42_archive_targets"]=all_archives[:80]
    # Prioritize v42 artifacts and add next-action lanes.
    def pri(a):
        s=int(a.get("score",0) or 0)
        txt=(str(a.get("source",""))+" "+str(a.get("kind",""))+" "+str(a.get("name",""))).lower()
        if "sloper42" in txt or "v42" in txt: s+=1600
        if "sloper" in txt: s+=900
        if any(k in txt for k in ["pcap","password","stego","decode_chain","dns","archive","extract"]): s+=350
        return (bool(a.get("exists",False)),s,int(a.get("size",0) or 0))
    summary["artifacts"]=sorted(summary.get("artifacts",[]),key=pri,reverse=True)[:2200]
    next_actions=[]
    if summary.get("flags"):
        next_actions.append({"priority":100,"step":"Submit or verify promoted ctf_cs flag.","why":"A primary-format flag has artifact/trace evidence."})
    if summary.get("flag_wrapping_helpers"):
        next_actions.append({"priority":95,"step":"Review Wrapper Hints.","why":"Likely answer bodies were found but may require ctf_cs{...}."})
    if clues and all_archives:
        next_actions.append({"priority":92,"step":"Try project clue passwords on archives/stego.","why":"The project contains password-like clues and archive-like artifacts."})
    if summary.get("artifacts"):
        next_actions.append({"priority":88,"step":"Inspect priority artifacts.","why":"Generated artifacts often contain decoded text, carved files or payloads."})
    summary["sloper42_next_actions"]=next_actions
    summary.setdefault("workflow_steps",[])
    summary["workflow_steps"]=next_actions+summary["workflow_steps"][:20]
    return summary
APP_TITLE = "CTF SLOPER v42"
TECHNICAL_WRAPPER_DENY = set("""
AWAVAUATSH AUATSH ATUSH H= SH IDAT IDATS IHDR IEND PLTE pHYs tEXt zTXt iTXt
googleusercontent applicationx-www-form-urlencoded x-www-form-urlencoded
VirtualProtect_failed_with_code_0xx ___lc_codepage_func
Admin_passwordnn_Returns JWT_session_tokennn_Returns
Raktas.txt key google com http https www png jpg jpeg pcap tcp udp dns http2
""".split())
def sl42_is_bad_wrapper_body(body):
    b=str(body or "").strip().strip("{}")
    low=b.lower()
    if not b or len(b)<8:
        return True
    if b in TECHNICAL_WRAPPER_DENY or low in {x.lower() for x in TECHNICAL_WRAPPER_DENY}:
        return True
    if re.fullmatch(r"[A-Z]{5,16}", b):
        return True
    if re.fullmatch(r"[A-Za-z]{4,18}", b) and "_" not in b and not any(ch.isdigit() for ch in b):
        # single plain English/technical word is usually not a CTF body
        if low not in ["password","secret"]:
            return True
    if any(x in low for x in ["googleusercontent","urlencoded","virtualprotect","lc_codepage","idat","ihdr","iend","tcp","udp","dns"]):
        return True
    if low.endswith(".txt") or low.endswith(".png") or low.endswith(".jpg"):
        return True
    return False
_prev_ff_candidate_to_flag_helpers_v42 = ff_candidate_to_flag_helpers
def ff_candidate_to_flag_helpers(report):
    helpers=_prev_ff_candidate_to_flag_helpers_v42(report)
    clean=[]; seen=set()
    for h in helpers:
        sugg=str(h.get("suggested_flag",""))
        m=re.match(r"(?i)^ctf_cs\{(.+)\}$",sugg)
        body=m.group(1) if m else sugg
        if sl42_is_bad_wrapper_body(body):
            continue
        k=sugg.lower()
        if k not in seen:
            seen.add(k); clean.append(h)
    return clean[:80]
_prev_vf_collect_answer_candidates_v42 = vf_collect_answer_candidates
def vf_collect_answer_candidates(report):
    items=_prev_vf_collect_answer_candidates_v42(report)
    clean=[]; seen=set()
    for a in items:
        v=str(a.get("value",""))
        m=re.match(r"(?i)^ctf_cs\{(.+)\}$",v)
        if m and sl42_is_bad_wrapper_body(m.group(1)):
            continue
        # Also drop obvious binary prologue all-caps technical tokens as answers.
        if sl42_is_bad_wrapper_body(v) and int(a.get("score",0) or 0)<260:
            continue
        k=v.lower()
        if k not in seen:
            seen.add(k); clean.append(a)
    return clean[:240]
_prev_sl_collect_candidate_flags_v42 = sl_collect_candidate_flags
def sl_collect_candidate_flags(report):
    flags=_prev_sl_collect_candidate_flags_v42(report)
    out=[]
    for f in flags:
        m=re.match(r"(?i)^ctf_cs\{(.+)\}$",f)
        if m and sl42_is_bad_wrapper_body(m.group(1)):
            continue
        out.append(f)
    return out
def sl43_trace(report, stage, detail, confidence=0, artifact=None, flag=None):
    try:
        sl42_trace(report, "v43:"+str(stage), detail, confidence, artifact, flag)
    except Exception:
        report.setdefault("solve_trace", []).append({
            "stage":"SLOPER v43:"+str(stage),
            "detail":str(detail)[:1100],
            "confidence":int(confidence or 0),
            "artifact":artifact or "",
            "flag":flag or ""
        })
def sl43_art(root, report, name, content, kind="sloper43_artifact", score=140, note=""):
    outdir=root/"generated"/"sloper43"/safe(report.get("name","file"))
    outdir.mkdir(parents=True, exist_ok=True)
    p=outdir/safe(name)
    try:
        if isinstance(content,(bytes,bytearray)):
            p.write_bytes(content)
        else:
            p.write_text(str(content),encoding="utf-8",errors="ignore")
        art={"kind":kind,"name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"CTF SLOPER v43","score":int(score),"note":note or kind,"exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
        report.setdefault("artifacts",[]).append(art)
        report.setdefault("transformations",[]).append(art)
        sl43_trace(report,"artifact",f"{kind}: {p.name}",score,str(p))
        return art
    except Exception as e:
        sl43_trace(report,"artifact failed",f"{name}: {e}",0)
        return None
def sl43_text_quality(s):
    s=str(s or "")
    if not s: return 0
    printable=sum(1 for c in s if 32<=ord(c)<127 or c in "\n\r\t")
    ratio=printable/max(1,len(s))
    low=s.lower()
    score=int(ratio*100)
    if vf_primary_flags(s,limit=1,scan_limit=20000): score+=500
    if re.search(r"\{[A-Za-z0-9_\-:.+]{4,160}\}",s): score+=260
    if re.search(r"[a-z0-9]{2,}_[a-z0-9_]{2,}",low): score+=110
    if any(w in low for w in ["flag","ctf","secret","password","raktas","slapta","token","admin","cyber","sprint","calc","you","cwe"]): score+=60
    if len(s)<6: score-=60
    if "�" in s: score-=90
    return score
def sl43_safe_decode_bytes(raw):
    try: return bytes(raw).decode("utf-8","ignore")
    except Exception: return ""
def sl43_decode_jwt(token):
    import base64, json
    parts=str(token).split(".")
    if len(parts)<2: return []
    outs=[]
    for i,part in enumerate(parts[:2]):
        try:
            pad=part+"="*((4-len(part)%4)%4)
            raw=base64.urlsafe_b64decode(pad.encode())
            txt=raw.decode("utf-8","ignore")
            if txt: outs.append(f"JWT part {i}: {txt}")
        except Exception: pass
    return outs
def sl43_zero_width_decode(text):
    # Common zero-width binary encodings.
    bits=[]
    mapping={"\u200b":"0","\u200c":"1","\u200d":"1","\ufeff":"0","\u2060":"0"}
    for ch in str(text):
        if ch in mapping: bits.append(mapping[ch])
    if len(bits)<8: return ""
    out=[]
    for i in range(0,len(bits)-7,8):
        b="".join(bits[i:i+8])
        try:
            v=int(b,2)
            out.append(chr(v) if 32<=v<127 else ".")
        except Exception: pass
    s="".join(out)
    return s if sl43_text_quality(s)>80 else ""
def sl43_decode_chain_text(text, max_rounds=3):
    import base64, html as _html, codecs, binascii
    start=str(text or "")
    queue=[start]
    seen=set()
    results=[]
    def add(depth,method,s,nxt):
        s=str(s or "")
        if not s or s in seen or len(s)>400000: return
        seen.add(s)
        results.append({"depth":depth,"method":method,"text":s})
        if nxt: queue_next.append(s)
    for depth in range(max_rounds):
        queue_next=[]
        for s in queue[:300]:
            if s not in seen:
                seen.add(s)
                results.append({"depth":depth,"method":"raw","text":s})
            # JWT
            for tok in re.findall(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?",s):
                for dec in sl43_decode_jwt(tok):
                    add(depth+1,"jwt",dec,True)
            # Morse
            mor=sl42_decode_morse(s) if "sl42_decode_morse" in globals() else ""
            if mor: add(depth+1,"morse",mor,True)
            # HTML entities
            if "&" in s:
                dec=_html.unescape(s)
                if dec!=s: add(depth+1,"html_entities",dec,True)
            # URL percent
            if "%" in s:
                try:
                    from urllib.parse import unquote
                    dec=unquote(s)
                    if dec!=s: add(depth+1,"url_percent",dec,True)
                except Exception: pass
            # zero width
            zw=sl43_zero_width_decode(s)
            if zw: add(depth+1,"zero_width",zw,True)
            # base64/base32/base85 tokens
            tokens=re.findall(r"[A-Za-z0-9+/=_-]{8,}",s)
            for tok in tokens[:200]:
                if len(tok)>5000: continue
                pad=tok+"="*((4-len(tok)%4)%4)
                for mode,fn in [
                    ("base64",lambda x:base64.b64decode(x.encode(),validate=False)),
                    ("base64url",lambda x:base64.urlsafe_b64decode(x.encode())),
                ]:
                    try:
                        raw=fn(pad)
                        dec=raw.decode("utf-8","ignore")
                        if sl43_text_quality(dec)>80: add(depth+1,mode,dec,True)
                    except Exception: pass
                # base32
                try:
                    p32=tok.upper()+"="*((8-len(tok)%8)%8)
                    raw=base64.b32decode(p32.encode(),casefold=True)
                    dec=raw.decode("utf-8","ignore")
                    if sl43_text_quality(dec)>80: add(depth+1,"base32",dec,True)
                except Exception: pass
                # base85/ascii85
                for mode,fn in [("base85",base64.b85decode),("ascii85",base64.a85decode)]:
                    try:
                        raw=fn(tok.encode())
                        dec=raw.decode("utf-8","ignore")
                        if sl43_text_quality(dec)>90: add(depth+1,mode,dec,True)
                    except Exception: pass
            # hex
            for hx in re.findall(r"(?:0x)?(?:[0-9a-fA-F]{2}[\s,:-]*){4,}",s)[:120]:
                h=re.sub(r"[^0-9a-fA-F]","",hx)
                if len(h)>=8 and len(h)%2==0 and len(h)<20000:
                    try:
                        dec=bytes.fromhex(h).decode("utf-8","ignore")
                        if sl43_text_quality(dec)>70: add(depth+1,"hex",dec,True)
                    except Exception: pass
            # binary groups
            for m in re.findall(r"(?:[01]{8}[\s,]*){3,}",s)[:80]:
                bits=re.findall(r"[01]{8}",m)
                try:
                    dec="".join(chr(int(b,2)) for b in bits)
                    if sl43_text_quality(dec)>70: add(depth+1,"binary_ascii",dec,True)
                except Exception: pass
            # decimal/octal ascii sequences
            nums=re.findall(r"\b\d{2,3}\b",s)
            if 3<=len(nums)<=2000:
                for base,label in [(10,"decimal_ascii"),(8,"octal_ascii")]:
                    try:
                        vals=[int(x,base) for x in nums]
                        dec="".join(chr(v) if 0<=v<256 else "." for v in vals)
                        if sl43_text_quality(dec)>85: add(depth+1,label,dec,True)
                    except Exception: pass
            # ROT13 and Atbash for likely text
            try:
                dec=codecs.decode(s,"rot_13")
                if dec!=s and any(w in dec.lower() for w in ["ctf","flag","secret","password","slapta","raktas"]):
                    add(depth+1,"rot13",dec,True)
            except Exception: pass
            try:
                abc="abcdefghijklmnopqrstuvwxyz"; trans=str.maketrans(abc+abc.upper(),abc[::-1]+abc[::-1].upper())
                dec=s.translate(trans)
                if dec!=s and any(w in dec.lower() for w in ["ctf","flag","secret","password","slapta","raktas"]):
                    add(depth+1,"atbash",dec,True)
            except Exception: pass
        queue=queue_next[:300]
    # Dedup by text
    out=[]; seen2=set()
    for r in results:
        t=r["text"].strip()
        if t and t not in seen2:
            seen2.add(t); out.append({**r,"text":t,"score":sl43_text_quality(t)})
    return sorted(out,key=lambda x:x.get("score",0),reverse=True)[:800]
sl42_decode_chain_text = sl43_decode_chain_text
def sl43_caesar_atbash_agent(report, root, text):
    import codecs
    text=str(text or "")
    lines=[x.strip() for x in text.splitlines() if 6<=len(x.strip())<=500]
    outs=[]
    def caesar(s,shift):
        out=[]
        for ch in s:
            if "a"<=ch<="z": out.append(chr((ord(ch)-97+shift)%26+97))
            elif "A"<=ch<="Z": out.append(chr((ord(ch)-65+shift)%26+65))
            else: out.append(ch)
        return "".join(out)
    abc="abcdefghijklmnopqrstuvwxyz"; trans=str.maketrans(abc+abc.upper(),abc[::-1]+abc[::-1].upper())
    for line in lines[:60]:
        for sh in range(1,26):
            dec=caesar(line,sh)
            sc=sl43_text_quality(dec)
            if sc>=160: outs.append({"method":f"caesar_{sh}","input":line,"output":dec,"score":sc})
        dec=line.translate(trans)
        sc=sl43_text_quality(dec)
        if sc>=160: outs.append({"method":"atbash","input":line,"output":dec,"score":sc})
    if not outs: return []
    out=[]; seen=set()
    for x in sorted(outs,key=lambda y:y.get("score",0),reverse=True):
        k=x["output"]
        if k not in seen:
            seen.add(k); out.append(x)
        if len(out)>=100: break
    art=sl43_art(root,report,"caesar_atbash_candidates.json",json.dumps(out,indent=2,ensure_ascii=False),"sloper43_caesar_atbash",180,"Caesar and Atbash candidates from text lines.")
    if art:
        for x in out[:30]:
            sl_promote_text(report,x["output"],"SLOPER v43 Caesar/Atbash",x["method"],art.get("path"),200)
        return [art]
    return []
def sl43_xor_single_byte_agent(report, root, data):
    data=bytes(data or b"")
    if not data or len(data)>2_000_000: return []
    # Skip normal image/binary unless statement hints XOR or data has high entropy text-like chunk.
    hint=(ux_statement_text(report)+" "+str(report.get("name",""))).lower()
    if not any(k in hint for k in ["xor","šif","sif","cipher","encoded","užkodu","uzkodu","key"]) and report.get("kind") in ["image","pcap","pdf"]:
        return []
    outs=[]
    sample=data[:500000]
    for k in range(256):
        dec=bytes(b^k for b in sample)
        txt=dec.decode("utf-8","ignore")
        sc=sl43_text_quality(txt)
        if sc>=170:
            outs.append({"method":"xor_single_byte","key":k,"key_hex":hex(k),"text":txt[:20000],"score":sc,"flags":vf_primary_flags(txt,limit=10,scan_limit=30000)})
    if not outs: return []
    outs=sorted(outs,key=lambda x:x.get("score",0),reverse=True)[:60]
    art=sl43_art(root,report,"xor_single_byte_candidates.json",json.dumps(outs,indent=2,ensure_ascii=False),"sloper43_xor_single_byte",220,"Single-byte XOR candidates.")
    if art:
        for x in outs[:20]:
            sl_promote_text(report,x["text"],"SLOPER v43 XOR",f"key={x.get('key_hex')}",art.get("path"),240)
        return [art]
    return []
def sl43_rsa_small_agent(report, root, text):
    text=str(text or "")
    # Find n/e/c assignments.
    vals={}
    for name in ["n","e","c","ct","cipher","ciphertext"]:
        m=re.search(rf"\b{name}\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)",text,re.I)
        if m:
            vals[name.lower()]=int(m.group(1),0)
    if "c" not in vals and "ct" in vals: vals["c"]=vals["ct"]
    if "c" not in vals and "cipher" in vals: vals["c"]=vals["cipher"]
    if "c" not in vals and "ciphertext" in vals: vals["c"]=vals["ciphertext"]
    if not all(k in vals for k in ["n","e","c"]):
        return []
    n,e,c=vals["n"],vals["e"],vals["c"]
    if n.bit_length()>80:
        return []
    # Trial divide / Fermat for small n.
    def egcd(a,b):
        if b==0: return (a,1,0)
        g,x1,y1=egcd(b,a%b); return (g,y1,x1-(a//b)*y1)
    def invmod(a,m):
        g,x,y=egcd(a,m)
        return x%m if g==1 else None
    p=q=None
    i=2
    while i*i<=n and i<5_000_000:
        if n%i==0:
            p=i; q=n//i; break
        i+=1 if i==2 else 2
    if not p: return []
    phi=(p-1)*(q-1)
    d=invmod(e,phi)
    if not d: return []
    m=pow(c,d,n)
    raw=m.to_bytes((m.bit_length()+7)//8 or 1,"big")
    txt=raw.decode("utf-8","ignore")
    obj={"n":n,"e":e,"c":c,"p":p,"q":q,"d":d,"plaintext_hex":raw.hex(),"plaintext":txt}
    art=sl43_art(root,report,"rsa_small_solution.json",json.dumps(obj,indent=2,ensure_ascii=False),"sloper43_rsa_small",300,"Small RSA modulus factored and decrypted.")
    if art:
        sl_promote_text(report,txt,"SLOPER v43 RSA","small n factorization",art.get("path"),330)
        return [art]
    return []
def sl43_decode_chain_agent(report, root):
    blob=sl42_report_text_blob(report) if "sl42_report_text_blob" in globals() else "\n".join(report.get("strings",[]))
    if not blob.strip(): return []
    decs=sl43_decode_chain_text(blob[:250000],3)
    strong=[d for d in decs if d.get("score",0)>=170 or vf_primary_flags(d["text"],limit=1,scan_limit=30000) or re.search(r"\{[A-Za-z0-9_\-:.+]{4,160}\}",d["text"])]
    if not strong: return []
    art=sl43_art(root,report,"decode_chain_v43_candidates.json",json.dumps(strong[:300],indent=2,ensure_ascii=False),"sloper43_decode_chain",250,"Recursive decode chain candidates: base64/base32/base85/hex/binary/decimal/octal/JWT/zero-width/HTML/URL/ROT13/Atbash.")
    if art:
        for d in strong[:80]:
            sl_promote_text(report,d["text"],"SLOPER v43 DecodeChain",d["method"],art.get("path"),260)
        return [art]
    return []
def sl43_run_extra_agents(report, root, data):
    arts=[]
    text=data[:800000].decode("utf-8","ignore")
    try: arts += sl43_decode_chain_agent(report,root)
    except Exception as e: sl43_trace(report,"DecodeChain failed",str(e),0)
    try: arts += sl43_caesar_atbash_agent(report,root,text)
    except Exception as e: sl43_trace(report,"CaesarAtbash failed",str(e),0)
    try: arts += sl43_xor_single_byte_agent(report,root,data)
    except Exception as e: sl43_trace(report,"XOR failed",str(e),0)
    try: arts += sl43_rsa_small_agent(report,root,text+"\n"+sl42_report_text_blob(report))
    except Exception as e: sl43_trace(report,"RSA failed",str(e),0)
    try: sl_finalize_report(report)
    except Exception: pass
    return arts
_prev_sl_run_agents_v43 = sl_run_agents
def sl_run_agents(report, root, data):
    arts=[]
    try:
        prev=_prev_sl_run_agents_v43(report,root,data)
        if prev: arts += prev
    except Exception as e:
        sl43_trace(report,"previous agents failed",str(e),0)
    try:
        arts += sl43_run_extra_agents(report,root,data) or []
    except Exception as e:
        sl43_trace(report,"v43 extra agents failed",str(e),0)
    return arts
def sl43_artifact_should_autopass(a):
    try:
        p=Path(a.get("path",""))
        if not p.exists() or not p.is_file(): return False
        if p.stat().st_size<=0 or p.stat().st_size>8_000_000: return False
        name=p.name.lower()
        kind=str(a.get("kind","")).lower()
        # Avoid re-analyzing internal manifests/candidate lists unless they likely contain decoded text.
        if name.endswith((".json",".txt",".log",".xml",".csv",".md")):
            return any(k in kind+name for k in ["decoded","extracted","carved","payload","child","ooxml","pcap","constants","reconstructed","text"])
        # Always analyze real child files / archive/image/binary-ish payloads.
        if p.suffix.lower() in [".zip",".7z",".rar",".tar",".gz",".tgz",".bz2",".xz",".zst",".png",".jpg",".jpeg",".gif",".bmp",".webp",".pcap",".pcapng",".pyc",".pdf",".docx",".bin",".elf",".exe",".so",".dll",".wav"]:
            return True
        return any(k in kind for k in ["extracted_child","embedded_zip_file","steghide_extract","stegseek_extract","carved_zip_entry","payload"])
    except Exception:
        return False
def sl43_copy_artifact_to_files(root, artifact, pass_no):
    import hashlib, shutil as _shutil
    p=Path(artifact.get("path",""))
    h=hashlib.sha256(str(p).encode()+b"|" + (p.read_bytes()[:4096] if p.exists() else b"")).hexdigest()[:12]
    destdir=root/"files"/"_sloper43_autopass"/f"pass_{pass_no}"
    destdir.mkdir(parents=True,exist_ok=True)
    suffix=p.suffix or ".bin"
    dest=destdir/(h+"_"+safe(p.stem)+suffix)
    if not dest.exists():
        _shutil.copy2(p,dest)
    return dest
_prev_analyze_project_v43 = analyze_project
def analyze_project(pid):
    # First run normal pipeline.
    _prev_analyze_project_v43(pid)
    root=pdir(pid); meta=jread(meta_path(pid),{})
    rep=jread(report_path(pid),{})
    reports=rep.get("files",[])
    analyzed_paths=set(str(Path(r.get("path",""))) for r in reports if r.get("path"))
    # Recursive artifact autopass: copy strong child artifacts into files/_sloper43_autopass and analyze them.
    for pass_no in range(1,4):
        candidates=[]
        for r in reports:
            for a in r.get("artifacts",[])[:500]:
                if sl43_artifact_should_autopass(a):
                    try:
                        dest=sl43_copy_artifact_to_files(root,a,pass_no)
                        if str(dest) not in analyzed_paths:
                            candidates.append(dest)
                    except Exception as e:
                        log(pid,f"v43 autopass copy failed: {e}")
        # Bound per pass.
        uniq=[]
        seen=set()
        for c in candidates:
            k=str(c)
            if k not in seen:
                seen.add(k); uniq.append(c)
        if not uniq:
            break
        uniq=uniq[:35]
        log(pid,f"SLOPER v43 autopass {pass_no}: analyzing {len(uniq)} child artifacts")
        total=max(1,len(uniq))
        for i,p in enumerate(uniq,1):
            analyzed_paths.add(str(p))
            try:
                progress(pid,min(98,86+pass_no*3),f"v43 child autopass {i}/{total}: {p.name}")
                child=analyze_file(pid,p,root,i,total)
                child.setdefault("solve_trace",[]).insert(0,{"stage":"SLOPER v43 autopass","detail":"Analyzed extracted/generated child artifact as a first-class file.","confidence":230,"artifact":str(p),"flag":""})
                reports.append(child)
            except Exception as e:
                reports.append({"id":uuid.uuid4().hex[:10],"name":p.name,"path":str(p),"rel":str(p.relative_to(root)),"kind":"error","error":str(e),"flags":[],"strings":[],"outputs":[],"previews":[],"commands":[],"decoders":[],"chain_results":[],"intermediate_files":[],"artifacts":[],"findings":[{"score":20,"type":"v43_autopass_error","value":str(e),"why":"Child autopass failed."}],"next_steps":[{"priority":20,"step":"Inspect child artifact manually.","why":str(e)}]})
            jwrite(report_path(pid),{"project":meta,"files":reports,"summary":project_summary(reports,meta),"ai_prompt":ai_prompt(meta,reports),"updated":now()})
    progress(pid,99,"v43 project-level clue propagation")
    # Add final project-level summary and write.
    jwrite(report_path(pid),{"project":meta,"files":reports,"summary":project_summary(reports,meta),"ai_prompt":ai_prompt(meta,reports),"updated":now()})
    progress(pid,100,"Done")
    with LOCK: JOBS.setdefault(pid,{})["status"]="done"
_prev_project_summary_v43 = project_summary
def project_summary(reports, meta):
    summary=_prev_project_summary_v43(reports, meta)
    # Build an evidence timeline for human review.
    timeline=[]
    for r in reports:
        rel=r.get("rel","")
        for t in r.get("solve_trace",[])[:80]:
            if isinstance(t,dict) and (t.get("confidence",0)>=140 or t.get("flag")):
                timeline.append({"file":rel,"stage":t.get("stage",""),"detail":t.get("detail",""),"confidence":t.get("confidence",0),"artifact":t.get("artifact",""),"flag":t.get("flag","")})
        for a in r.get("artifacts",[])[:80]:
            if int(a.get("score",0) or 0)>=220:
                timeline.append({"file":rel,"stage":"artifact","detail":a.get("kind","")+" "+a.get("name",""),"confidence":a.get("score",0),"artifact":a.get("path",""),"flag":""})
    timeline=sorted(timeline,key=lambda x:int(x.get("confidence",0) or 0),reverse=True)[:250]
    summary["sloper43_evidence_timeline"]=timeline
    summary["sloper43_autopass_note"]="Generated child artifacts are recursively re-analyzed up to 3 bounded passes."
    # Prioritize v43 artifacts.
    def pri(a):
        s=int(a.get("score",0) or 0)
        txt=(str(a.get("source",""))+" "+str(a.get("kind",""))+" "+str(a.get("name",""))).lower()
        if "sloper43" in txt or "v43" in txt: s+=2200
        if "sloper42" in txt or "v42" in txt: s+=1500
        if "sloper" in txt: s+=900
        if any(k in txt for k in ["decode_chain","xor","rsa","caesar","autopass","extracted","payload","pcap","password"]): s+=400
        return (bool(a.get("exists",False)),s,int(a.get("size",0) or 0))
    summary["artifacts"]=sorted(summary.get("artifacts",[]),key=pri,reverse=True)[:2500]
    next_actions=summary.get("sloper42_next_actions",[]) or []
    if timeline:
        next_actions.insert(0,{"priority":97,"step":"Review Evidence Timeline.","why":"v43 ranked the strongest trace/artifact steps across all files."})
    summary["sloper43_next_actions"]=next_actions[:20]
    summary["workflow_steps"]=next_actions[:20]+summary.get("workflow_steps",[])[:20]
    return summary
APP_TITLE = "CTF SLOPER v43"
def sl43_fast_bytes_text_score(bs):
    bs=bytes(bs or b"")
    if not bs: return 0
    sample=bs[:60000]
    printable=sum(1 for b in sample if 32<=b<127 or b in [9,10,13])
    ratio=printable/max(1,len(sample))
    score=int(ratio*100)
    txt=sample.decode("utf-8","ignore").lower()
    if "ctf_cs{" in txt: score+=500
    if re.search(r"\{[a-z0-9_\-:.+]{4,160}\}",txt): score+=250
    if re.search(r"[a-z0-9]{2,}_[a-z0-9_]{2,}",txt): score+=100
    if any(w in txt for w in ["flag","secret","password","raktas","slapta","cyber","sprint","token"]): score+=60
    return score
def sl43_xor_single_byte_agent(report, root, data):
    data=bytes(data or b"")
    if not data or len(data)>1_000_000:
        return []
    p=Path(report.get("path",""))
    hint=(ux_statement_text(report)+" "+str(report.get("name",""))+" "+"\n".join(report.get("strings",[])[:40])).lower()
    strong_hint=any(k in hint for k in ["xor","single-byte","single byte","šif","sif","cipher","encoded","užkodu","uzkodu","key xor","xor key"])
    # Avoid expensive brute on common non-XOR file classes unless explicitly hinted.
    if not strong_hint:
        if report.get("kind") in ["image","pcap","pdf","archive","binary","python_bytecode"]:
            return []
        if p.suffix.lower() not in [".txt",".dat",".bin",".raw",".enc",".cipher",".out"] and len(data)>120000:
            return []
        if len(data)>160000:
            return []
    sample=data[:90000 if strong_hint else 45000]
    outs=[]
    for k in range(256):
        dec=bytes(b^k for b in sample)
        sc=sl43_fast_bytes_text_score(dec)
        if sc>=185:
            txt=dec.decode("utf-8","ignore")
            outs.append({"method":"xor_single_byte","key":k,"key_hex":hex(k),"text":txt[:18000],"score":sc,"flags":vf_primary_flags(txt,limit=10,scan_limit=25000)})
    if not outs:
        return []
    outs=sorted(outs,key=lambda x:x.get("score",0),reverse=True)[:40]
    art=sl43_art(root,report,"xor_single_byte_candidates.json",json.dumps(outs,indent=2,ensure_ascii=False),"sloper43_xor_single_byte",220,"Single-byte XOR candidates, bounded by hint/size.")
    if art:
        for x in outs[:15]:
            sl_promote_text(report,x["text"],"SLOPER v43 XOR",f"key={x.get('key_hex')}",art.get("path"),240)
        return [art]
    return []
def sl44_trace(report, stage, detail, confidence=0, artifact=None, flag=None):
    try:
        sl43_trace(report, "v44:"+str(stage), detail, confidence, artifact, flag)
    except Exception:
        report.setdefault("solve_trace", []).append({
            "stage":"SLOPER v44:"+str(stage),
            "detail":str(detail)[:1200],
            "confidence":int(confidence or 0),
            "artifact":artifact or "",
            "flag":flag or ""
        })
def sl44_art(root, report, name, content, kind="sloper44_artifact", score=150, note=""):
    outdir=root/"generated"/"sloper44"/safe(report.get("name","file"))
    outdir.mkdir(parents=True, exist_ok=True)
    p=outdir/safe(name)
    try:
        if isinstance(content,(bytes,bytearray)):
            p.write_bytes(content)
        else:
            p.write_text(str(content),encoding="utf-8",errors="ignore")
        art={"kind":kind,"name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"CTF SLOPER v44","score":int(score),"note":note or kind,"exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
        report.setdefault("artifacts",[]).append(art)
        report.setdefault("transformations",[]).append(art)
        sl44_trace(report,"artifact",f"{kind}: {p.name}",score,str(p))
        return art
    except Exception as e:
        sl44_trace(report,"artifact failed",f"{name}: {e}",0)
        return None
def sl44_promote_text(report, text, source, why="", artifact=None, score=270):
    try:
        return sl_promote_text(report,text,source,why,artifact,score)
    except Exception:
        return 0
def sl44_good_text(s):
    try:
        return sl43_text_quality(s) if "sl43_text_quality" in globals() else sf_text_score(s)
    except Exception:
        return 0
def sl44_extract_cmp_immediates_from_objdump(text):
    vals=[]
    lines=str(text or "").splitlines()
    for line in lines:
        asm=line.split("\t")[-1] if "\t" in line else line
        # cmp BYTE PTR [..],0xNN or cmp al,0xNN
        m=re.search(r"\bcmp\b[^,]{0,80},\s*(0x[0-9a-fA-F]{1,2}|\d{1,3})\b",asm,re.I)
        if m:
            try:
                v=int(m.group(1),0)
                if 0<=v<=255:
                    vals.append({"value":v,"line":line.strip()})
            except Exception:
                pass
        # mov/cmp patterns can include char literals
        m2=re.search(r"\bcmp\b[^,]{0,80},\s*'([^'])'",asm,re.I)
        if m2:
            vals.append({"value":ord(m2.group(1)[0])&255,"line":line.strip()})
    # group consecutive cmp immediates by proximity in listing order
    groups=[]
    cur=[]
    for item in vals:
        if len(cur)<256:
            cur.append(item)
        if len(cur)>=6:
            # keep sliding groups; later dedupe
            groups.append(cur[-80:].copy())
    out=[]; seen=set()
    for g in groups:
        seq=tuple(x["value"] for x in g)
        if len(seq)>=6 and seq not in seen:
            seen.add(seq); out.append({"type":"cmp_immediates","values":list(seq),"lines":[x["line"] for x in g[-30:]]})
    return out[-120:]
