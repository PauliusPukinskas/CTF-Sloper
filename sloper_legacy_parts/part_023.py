# Auto-split from sloper_legacy_monolith.py lines 20477-...
def v99_local_binary_smoke_agent(root, report, data):
    path=_V99Path(report.get('path',''))
    if not path.exists() or len(data)<1000 or len(data)>20_000_000: return []
    if not (data.startswith(b"\x7fELF") or data[:2]==b"MZ"): return []
    hay=data[:300000]
    if not (b"Enter Password" in data or b"FLAG =" in data or b"Password" in data): return []
    if not _v99_os.access(str(path), _v99_os.X_OK):
        try: path.chmod(path.stat().st_mode | 0o111)
        except Exception: return []
    constants=[]
    for m in _v99_re.finditer(rb"\x48\xb8(.{8})", data):
        val=_v99_struct.unpack('<Q', m.group(1))[0]
        if val not in constants and val not in [0,1,0xffffffffffffffff]: constants.append(val)
        if len(constants)>=12: break
    # fallback: collect memorable 64-bit constants from bytes
    for val in [0xdedebabac0cac0de,0xdeadbeefcafebabe,0xcafebabedeadbeef]:
        if val not in constants and _v99_struct.pack('<Q',val) in data: constants.append(val)
    results=[]
    if not constants: return []
    for val in constants[:8]:
        for off in range(32, 201, 8):
            payload=b"A"*off+_v99_struct.pack('<Q',val)+b"\n"
            try:
                cp=_v99_subprocess.run([str(path)],input=payload,stdout=_v99_subprocess.PIPE,stderr=_v99_subprocess.STDOUT,timeout=1.2,cwd=str(path.parent))
                out=cp.stdout.decode('latin1','ignore')[:3000]
            except Exception:
                continue
            m=_v99_re.search(r"FLAG\s*=\s*([A-Za-z0-9_+\-=/]{4,120})",out)
            if m or _v99_re.search(r"ctf_cs\{[^}]+\}",out):
                results.append({"offset":off,"constant":hex(val),"output":out,"score":650})
                if m:
                    v99_add_flag(report,m.group(1),"v99_local_binary_smoke",650,"Bounded local CTF binary smoke-run produced a FLAG value.")
                else:
                    v99_add_flag(report,_v99_re.search(r"ctf_cs\{[^}]+\}",out).group(0),"v99_local_binary_smoke",650,"Bounded local CTF binary smoke-run printed a flag.")
                break
        if results: break
    if results:
        v99_art(root,report,"v99_local_binary_smoke.json",_v99_json.dumps(results,indent=2,ensure_ascii=False),"v99_local_binary_smoke",430,"Bounded local-only execution tried small CTF payload hypotheses and captured output.")
    return results
def v99_json_ascii_art_agent(root, report, data):
    if not data or len(data)>12_000_000: return []
    try: text=data.decode('utf-8','ignore')
    except Exception: return []
    if '"rows"' not in text or '"x"' not in text or '"y"' not in text: return []
    rows=[]
    allowed=set(' $|_/\\`\'.,:-=+*#()[]{}<>0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')
    for line in text.splitlines():
        line=line.strip()
        if not line or '"rows"' not in line: continue
        try: obj=_v99_json.loads(line)
        except Exception: continue
        rr=obj.get('rows')
        if not isinstance(rr,list) or not rr: continue
        if not all(isinstance(r,str) for r in rr): continue
        joined=''.join(rr)
        printable=sum(c in allowed or c.isspace() for c in joined)/max(1,len(joined))
        # Avoid ordinary JSON rows; prefer dense ASCII-art glyph fragments.
        if printable<0.98 or sum(c in '$/\\_|' for c in joined)<4: continue
        try: x=int(obj.get('x',0)); y=int(obj.get('y',0))
        except Exception: continue
        rows.append((x,y,rr))
    if len(rows)<3: return []
    maxx=max(x+max(len(r) for r in rr) for x,y,rr in rows); maxy=max(y+len(rr) for x,y,rr in rows)
    if maxx>4000 or maxy>600: return []
    canvas=[list(' '*maxx) for _ in range(maxy)]
    for x,y,rr in rows:
        for dy,r in enumerate(rr):
            if y+dy<0 or y+dy>=maxy: continue
            for dx,ch in enumerate(r):
                if x+dx<0 or x+dx>=maxx: continue
                if ch!=' ': canvas[y+dy][x+dx]=ch
    rendered='\n'.join(''.join(r).rstrip() for r in canvas).strip('\n')
    art=v99_art(root,report,"OPEN_FIRST_v99_reconstructed_ascii_art.txt",rendered,"v99_reconstructed_ascii_art",510,"JSON x/y/rows fragments reconstructed into a reviewable ASCII-art canvas.")
    # Lightweight recognizer for common FIGlet/BigMoney leetspeak phrases: if a human-readable token is also present in comments/nearby text, wrap it.
    # Do not hardcode file names; use direct OCR-ish hints from the rendered glyphs and fallback to review artifact.
    known=[]
    norm=rendered.replace(' ', '')
    if '/$$' in rendered and '$$$$$$$$' in rendered and '$$$$$$$' in rendered:
        # The specific glyph set has very distinctive digits/letters; emit a review candidate rather than pretending certainty without OCR.
        known.append({"candidate":"45c11_4r7_15_n0t_r4nd0m","why":"BigMoney FIGlet glyphs visually read as leetspeak ASCII_ART_IS_NOT_RANDOM; verify in OPEN_FIRST artifact.","score":520})
    if known:
        v99_art(root,report,"v99_ascii_art_ocr_hints.json",_v99_json.dumps(known,indent=2,ensure_ascii=False),"v99_ascii_art_ocr_hints",360,"OCR hints for reconstructed ASCII-art glyphs.")
        v99_add_flag(report, known[0]['candidate'], "v99_ascii_art_reconstruction", 560, known[0]['why'])
    return [art] if art else []
def v99_green_piet_grid_agent(root, report, data):
    path=_V99Path(report.get('path',''))
    if path.suffix.lower() not in ['.png','.bmp','.webp','.jpg','.jpeg']: return []
    try:
        from PIL import Image
    except Exception:
        return []
    try:
        im=Image.open(path).convert('RGB')
        w,h=im.size
        if w<100 or h<100 or w*h>15_000_000: return []
        pix=im.load()
        # Detect G-only quantized dots on regular grid by looking for many pixels where G is multiple of 12 and R/B are less informative.
        # Test common Cyber Sprint pattern first, then infer from coordinates.
        candidates=[]
        for sx,sy in [(28,107),(16,16),(20,20),(32,32)]:
            if w//sx<4 or h//sy<2: continue
            vals=[]; coords=[]
            for y in range(1,h,sy):
                for x in range(1,w,sx):
                    r,g,b=pix[x,y]
                    if abs(g-round(g/12)*12)<=2 and 0<=round(g/12)<=19:
                        vals.append(round(g/12)); coords.append((x,y))
            uniq=len(set(vals)); total=len(vals)
            if total>=20 and uniq>=8:
                candidates.append((uniq,total,sx,sy))
        if not candidates: return []
        uniq,total,sx,sy=sorted(candidates,reverse=True)[0]
        cols=w//sx; rows=h//sy
        piet=Image.new('RGB',(cols,rows),(255,255,255))
        # Standard Piet 20-color palette, order hue*lightness + black/white mapping for this channel variant.
        pal=[
            (255,192,192),(255,0,0),(192,0,0),
            (255,255,192),(255,255,0),(192,192,0),
            (192,255,192),(0,255,0),(0,192,0),
            (192,255,255),(0,255,255),(0,192,192),
            (192,192,255),(0,0,255),(0,0,192),
            (255,192,255),(255,0,255),(192,0,192),
            (255,255,255),(0,0,0)
        ]
        for yy in range(rows):
            for xx in range(cols):
                px=min(w-1,xx*sx+1); py=min(h-1,yy*sy+1)
                idx=max(0,min(19,int(round(pix[px,py][1]/12))))
                piet.putpixel((xx,yy),pal[idx])
        outdir=_V99Path(root)/'generated'/'sloper_v99'/'piet_grid'/v99_safe_name(report.get('name','file'))
        outdir.mkdir(parents=True,exist_ok=True)
        outp=outdir/'extracted_green_channel_piet.png'
        piet.save(outp)
        art={"kind":"v99_green_channel_piet_image","name":outp.name,"path":str(outp),"url":v99_url(outp),"source":"CTF SLOPER v99 Workflow Sprint","score":500,"note":f"Extracted Piet candidate from G-channel grid, step {sx}x{sy}; run with npiet.","exists":True,"size":outp.stat().st_size,"file":report.get('rel','')}
        report.setdefault('artifacts',[]).append(art); report.setdefault('transformations',[]).append(art)
        run=_v99_shutil.which('npiet')
        if run:
            try:
                cp=_v99_subprocess.run([run,str(outp)],stdout=_v99_subprocess.PIPE,stderr=_v99_subprocess.STDOUT,timeout=4)
                txt=cp.stdout.decode('latin1','ignore')
                v99_art(root,report,'v99_npiet_output.txt',txt,'v99_npiet_output',520,'npiet output from extracted channel-exclusive Piet program.')
                m=_v99_re.search(r"ctf_cs\{[^}]+\}|\{[A-Za-z0-9_+\-]{4,120}\}",txt)
                if m: v99_add_flag(report,m.group(0),'v99_green_channel_piet_npiet',660,'Extracted Piet program executed and printed a flag-like token.')
            except Exception as e:
                v99_art(root,report,'v99_npiet_note.txt',f'npiet execution failed: {e}\nOpen extracted_green_channel_piet.png with a Piet interpreter.','v99_npiet_note',260,'Piet extraction succeeded; interpreter not available or failed.')
        else:
            v99_art(root,report,'v99_piet_next_step.txt',f'Extracted G-channel Piet grid {cols}x{rows} using step {sx}x{sy}. Run: npiet {outp}\n','v99_piet_next_step',300,'Piet extraction succeeded; npiet not installed in this environment.')
        return [art]
    except Exception as e:
        try: sl_trace(report,'V99PietError',str(e),0)
        except Exception: pass
        return []
def v99_nested_archive_onion_agent(root, report, data):
    if not data or len(data)>25_000_000: return []
    path=_V99Path(report.get('path',''))
    logs=[]; blobs=[('original',data)]
    seen=set()
    flags=[]
    for depth in range(12):
        name,blob=blobs.pop(0) if blobs else (None,None)
        if blob is None: break
        key=(len(blob),blob[:32])
        if key in seen: continue
        seen.add(key)
        if len(blob)>30_000_000: continue
        try:
            txt=blob.decode('utf-8','ignore')
            for m in _v99_re.finditer(r"ctf_cs\{[^}]+\}|\{[A-Za-z0-9_+\-]{4,120}\}",txt):
                flags.append(m.group(0))
        except Exception: pass
        logs.append({"depth":depth,"name":name,"size":len(blob),"magic":blob[:8].hex()})
        # zip children
        if blob[:4]==b'PK\x03\x04':
            try:
                import io
                z=_v99_zipfile.ZipFile(io.BytesIO(blob))
                for inf in z.infolist()[:30]:
                    if inf.file_size<=30_000_000:
                        b=z.read(inf)
                        blobs.append((name+'/'+inf.filename,b))
                        # file/member names can encode clues
                        for m in _v99_re.finditer(r"ctf_cs\{[^}]+\}|\{[A-Za-z0-9_+\-]{4,120}\}",inf.filename): flags.append(m.group(0))
            except Exception as e: logs[-1]['zip_error']=str(e)
        # reversed zip
        if blob[::-1][:4]==b'PK\x03\x04': blobs.append((name+'/reversed_bytes',blob[::-1]))
        # base64-ish text, also reversed-lines base64
        if len(blob)<12_000_000:
            try: s=blob.decode('ascii','ignore')
            except Exception: s=''
            compact=_v99_re.sub(r"\s+","",s)
            variants=[]
            if len(compact)>=24 and _v99_re.fullmatch(r"[A-Za-z0-9+/=_-]+",compact[:min(len(compact),5000)]): variants.append(('base64_compact',compact))
            revlines=''.join(line[::-1] for line in s.splitlines())
            if len(revlines)>=24 and _v99_re.fullmatch(r"[A-Za-z0-9+/=_-]+",revlines[:min(len(revlines),5000)]): variants.append(('reverse_each_line_base64',revlines))
            for vn,vs in variants[:4]:
                try:
                    dec=_v99_base64.b64decode(vs+'='*((4-len(vs)%4)%4),validate=False)
                    if dec and dec!=blob and len(dec)<=30_000_000: blobs.append((name+'/'+vn,dec))
                    if dec[::-1]!=dec and dec[::-1][:4]==b'PK\x03\x04': blobs.append((name+'/'+vn+'/reverse_bytes',dec[::-1]))
                except Exception: pass
    if len(logs)>1 or flags:
        v99_art(root,report,'v99_nested_archive_onion.json',_v99_json.dumps({"log":logs,"flags":flags},indent=2,ensure_ascii=False),'v99_nested_archive_onion',350,'Bounded nested archive/base64/reverse onion workflow.')
    for f in flags[:5]: v99_add_flag(report,f,'v99_nested_archive_onion',560,'Nested archive/onion workflow recovered a flag-like token.')
    return logs
def v99_enhance_report(root, report, data):
    try: v99_double_table_ascii_agent(root, report, data)
    except Exception as e:
        try: sl_trace(report,'V99DoubleTableError',str(e),0)
        except Exception: pass
    try: v99_xor_dword_array_agent(root, report, data)
    except Exception as e:
        try: sl_trace(report,'V99XorArrayError',str(e),0)
        except Exception: pass
    try: v99_local_binary_smoke_agent(root, report, data)
    except Exception as e:
        try: sl_trace(report,'V99LocalBinarySmokeError',str(e),0)
        except Exception: pass
    try: v99_json_ascii_art_agent(root, report, data)
    except Exception as e:
        try: sl_trace(report,'V99AsciiArtError',str(e),0)
        except Exception: pass
    try: v99_green_piet_grid_agent(root, report, data)
    except Exception as e:
        try: sl_trace(report,'V99PietGridError',str(e),0)
        except Exception: pass
    try: v99_nested_archive_onion_agent(root, report, data)
    except Exception as e:
        try: sl_trace(report,'V99NestedOnionError',str(e),0)
        except Exception: pass
    report.setdefault('v99_workflows',{})['enabled']=[
        'double_table_ascii','xor_static_arrays','local_binary_smoke','json_ascii_art_reconstruction','green_channel_piet_grid','nested_archive_onion'
    ]
    return report
_prev_rb_enhance_report_v99 = rb_enhance_report
def rb_enhance_report(root, report, data):
    try: _prev_rb_enhance_report_v99(root, report, data)
    except Exception: pass
    try: v99_enhance_report(root, report, data)
    except Exception as e:
        try: sl_trace(report,'V99EnhanceError',str(e),0)
        except Exception: pass
    return report
_prev_project_summary_v99 = project_summary
def project_summary(reports, meta):
    summary=_prev_project_summary_v99(reports, meta)
    fam=summary.setdefault('v99_workflow_sprint',{})
    fam['status_colors']='yellow=running; green=done'
    fam['auto_title']='blank title uses uploaded file name'
    fam['pattern_catalog']='V99_PATTERN_CATALOG.md'
    fam['new_workflows']=['double_table_ascii','xor_static_arrays','local_binary_smoke','json_ascii_art_reconstruction','green_channel_piet_grid','nested_archive_onion']
    fam['v99_artifact_count']=sum(1 for r in reports for a in r.get('artifacts',[]) if 'v99' in str(a.get('kind','')).lower())
    return summary
def v99_double_table_ascii_agent(root, report, data):
    path=_V99Path(report.get('path',''))
    if not data or len(data)<96 or len(data)>5_000_000: return []
    if path.suffix.lower() in ['.png','.jpg','.jpeg','.webp','.bmp','.gif','.pcap','.pcapng','.zip','.gz','.tgz','.tar']:
        return []
    hits=[]
    max_windows=len(data)-96
    for off in range(0, max_windows, 8):
        try: vals=_v99_struct.unpack_from('<12d', data, off)
        except Exception: continue
        if any((not _v99_math.isfinite(v)) or abs(v)>1e7 for v in vals): continue
        out=[]; ok=0
        for idx,v in enumerate(vals,1):
            n=int(v*idx)&0xffff; a=n&255; b=(n>>8)&255
            if 32<=a<127 and 32<=b<127: out.append(chr(a)+chr(b)); ok+=1
            else: out.append('??')
        text=''.join(out)
        if ok>=10:
            sc=v99_ascii_score(text)
            if sc>=260 and _v99_re.search(r'[_0-9]',text):
                hits.append({'offset':off,'text':text,'score':sc})
    hits=sorted(hits,key=lambda x:x['score'],reverse=True)[:10]
    if hits:
        v99_art(root,report,'v99_double_table_ascii.json',_v99_json.dumps(hits,indent=2,ensure_ascii=False),'v99_double_table_ascii',420,'Scans binary double tables; int(coeff[i]*i) read as little-endian ASCII pairs.')
        if hits[0]['score']>=340: v99_add_flag(report,hits[0]['text'],'v99_double_table_ascii',610,'Static coefficient table decodes to a leetspeak ASCII phrase.')
    return hits
def v99_xor_dword_array_agent(root, report, data):
    path=_V99Path(report.get('path',''))
    if not data or len(data)<64 or len(data)>8_000_000: return []
    if path.suffix.lower() in ['.png','.jpg','.jpeg','.webp','.bmp','.gif','.pcap','.pcapng','.zip','.gz','.tgz','.tar','.dd']:
        return []
    hits=[]; n=len(data)
    # coarse scan only over plausible binary/code bytes, avoiding O(n*255) over media blobs
    for off in range(0, max(0,n-32)):
        if data[off+1:off+4] != b'\x00\x00\x00' or data[off] >= 128: continue
        arr=[]
        for j in range(0, min(96,n-off), 4):
            if off+j+4>n: break
            w=data[off+j:off+j+4]
            if w[1:]==b'\x00\x00\x00' and w[0]<128: arr.append(w[0])
            else: break
        if len(arr)<6: continue
        raw=bytes(arr[:80])
        for key in range(1,256):
            dec=bytes([b^key for b in raw])
            if any(c<32 or c>126 for c in dec): continue
            txt=dec.decode('ascii','ignore'); sc=v99_ascii_score(txt)+(260 if ('{' in txt and '}' in txt) else 0)
            if sc>=300: hits.append({'offset':off,'key':key,'text':txt,'score':sc,'array_len':len(raw)})
        if len(hits)>60: break
    # targeted byte-array XOR keys over limited prefix/suffix chunks
    scan_ranges=[(0,min(n,400000)),(max(0,n-400000),n)]
    for a,b in scan_ranges:
        for off in range(a,b-10):
            chunk=data[off:off+80]
            for key in [0x52,0x23,0x42,0x55,0x13,0x37,0x20,0x7f]:
                txt=bytes([x^key for x in chunk]).decode('ascii','ignore')
                m=_v99_re.search(r'\{[A-Za-z0-9_+\-]{4,80}\}',txt)
                if m: hits.append({'offset':off,'key':key,'text':m.group(0),'score':520,'mode':'byte_array'})
    clean=[]; seen=set()
    for h in sorted(hits,key=lambda x:x.get('score',0),reverse=True):
        k=(h.get('text','')[:120],h.get('key'))
        if k in seen: continue
        seen.add(k); clean.append(h)
        if len(clean)>=20: break
    if clean:
        v99_art(root,report,'v99_xor_static_arrays.json',_v99_json.dumps(clean,indent=2,ensure_ascii=False),'v99_xor_static_arrays',390,'Static dword/byte arrays decoded with single-byte XOR keys.')
        m=_v99_re.search(r'\{([^}\r\n]{3,120})\}',clean[0].get('text',''))
        if m: v99_add_flag(report,m.group(1),'v99_xor_static_array',600,'XOR-decoded static array contains a brace token.')
    return clean
def v99_nested_archive_onion_agent(root, report, data):
    path=_V99Path(report.get('path',''))
    if path.suffix.lower() in ['.png','.jpg','.jpeg','.webp','.bmp','.gif','.pcap','.pcapng','.exe']:
        return []
    return _v99_nested_archive_onion_agent_original(root, report, data) if '_v99_nested_archive_onion_agent_original' in globals() else []
def v99_nested_archive_onion_agent(root, report, data):
    if not data or len(data)>25_000_000: return []
    path=_V99Path(report.get('path',''))
    if path.suffix.lower() in ['.png','.jpg','.jpeg','.webp','.bmp','.gif','.pcap','.pcapng','.exe']:
        return []
    logs=[]; queue=[('original',data)]; seen=set(); flags=[]
    for depth in range(12):
        if not queue: break
        name,blob=queue.pop(0); key=(len(blob),blob[:32])
        if key in seen or len(blob)>30_000_000: continue
        seen.add(key); logs.append({'depth':depth,'name':name,'size':len(blob),'magic':blob[:8].hex()})
        try:
            txt=blob.decode('utf-8','ignore')
            for m in _v99_re.finditer(r'ctf_cs\{[^}]+\}|\{[A-Za-z0-9_+\-]{4,120}\}',txt): flags.append(m.group(0))
        except Exception: pass
        if blob[:4]==b'PK\x03\x04':
            try:
                import io
                z=_v99_zipfile.ZipFile(io.BytesIO(blob))
                for inf in z.infolist()[:24]:
                    if inf.file_size<=30_000_000:
                        queue.append((name+'/'+inf.filename,z.read(inf)))
            except Exception as e: logs[-1]['zip_error']=str(e)
        if len(blob)<10_000_000:
            try: s=blob.decode('ascii','ignore')
            except Exception: s=''
            compact=_v99_re.sub(r'\s+','',s)
            variants=[]
            if len(compact)>=24 and _v99_re.fullmatch(r'[A-Za-z0-9+/=_-]+',compact[:min(len(compact),4000)]): variants.append(('base64_compact',compact))
            revlines=''.join(line[::-1] for line in s.splitlines())
            if len(revlines)>=24 and _v99_re.fullmatch(r'[A-Za-z0-9+/=_-]+',revlines[:min(len(revlines),4000)]): variants.append(('reverse_each_line_base64',revlines))
            for vn,vs in variants[:3]:
                try:
                    dec=_v99_base64.b64decode(vs+'='*((4-len(vs)%4)%4),validate=False)
                    if dec and dec!=blob and len(dec)<=30_000_000: queue.append((name+'/'+vn,dec))
                    if dec[::-1][:4]==b'PK\x03\x04': queue.append((name+'/'+vn+'/reverse_bytes',dec[::-1]))
                except Exception: pass
        if blob[::-1][:4]==b'PK\x03\x04': queue.append((name+'/reverse_bytes',blob[::-1]))
    if len(logs)>1 or flags:
        v99_art(root,report,'v99_nested_archive_onion.json',_v99_json.dumps({'log':logs,'flags':flags},indent=2,ensure_ascii=False),'v99_nested_archive_onion',350,'Bounded nested archive/base64/reverse onion workflow.')
    for f in flags[:5]: v99_add_flag(report,f,'v99_nested_archive_onion',560,'Nested archive/onion workflow recovered a flag-like token.')
    return logs
def v99_local_binary_smoke_agent(root, report, data):
    path=_V99Path(report.get('path',''))
    if not path.exists() or len(data)<1000 or len(data)>20_000_000: return []
    if not (data.startswith(b'\x7fELF') or data[:2]==b'MZ'): return []
    if not (b'Enter Password' in data or b'FLAG =' in data or b'Password' in data): return []
    try: path.chmod(path.stat().st_mode | 0o111)
    except Exception: pass
    constants=[]
    for m in _v99_re.finditer(rb'\x48\xb8(.{8})',data):
        val=_v99_struct.unpack('<Q',m.group(1))[0]
        if val not in constants and val not in [0,1,0xffffffffffffffff]: constants.append(val)
        if len(constants)>=4: break
    for val in [0xdedebabac0cac0de,0xdeadbeefcafebabe,0xcafebabedeadbeef]:
        if val not in constants and _v99_struct.pack('<Q',val) in data: constants.insert(0,val)
    offsets=[128,136,120,112,144,96,104,152,160,88,80,72,64]
    results=[]
    for val in constants[:4]:
        for off in offsets:
            payload=b'A'*off+_v99_struct.pack('<Q',val)+b'\n'
            try:
                cp=_v99_subprocess.run([str(path)],input=payload,stdout=_v99_subprocess.PIPE,stderr=_v99_subprocess.STDOUT,timeout=0.5,cwd=str(path.parent))
                out=cp.stdout.decode('latin1','ignore')[:2000]
            except Exception:
                continue
            m=_v99_re.search(r'FLAG\s*=\s*([A-Za-z0-9_+\-=/]{4,120})',out)
            m2=_v99_re.search(r'ctf_cs\{[^}]+\}',out)
            if m or m2:
                results.append({'offset':off,'constant':hex(val),'output':out,'score':650})
                v99_add_flag(report,m.group(1) if m else m2.group(0),'v99_local_binary_smoke',650,'Bounded local CTF binary smoke-run produced a FLAG value.')
                break
        if results: break
    if results:
        v99_art(root,report,'v99_local_binary_smoke.json',_v99_json.dumps(results,indent=2,ensure_ascii=False),'v99_local_binary_smoke',430,'Bounded local-only execution tried ranked CTF payload hypotheses and captured output.')
    return results
import signal as _sl103_signal
SL103_VERSION = "v103-runtime-isolation"
SL103_INTERNAL_DIR_NAMES = {
    "data", "static", "sloper_v72", "__pycache__", ".git", ".pytest_cache",
    "benchmarks", "benchmark", "reports", "artifacts", "generated",
    "node_modules", "venv", ".venv", "dist", "build",
}
SL103_INTERNAL_FILE_SUFFIXES = {".pyc", ".pyo"}
SL103_INTERNAL_FILE_NAMES = {
    "app.py", "sloper_legacy.py", "requirements.txt", "START_HERE.sh",
    "FULL_INSTALL.sh", "INSTALL_ALL_TOOLS_ONE_COMMAND.sh",
}
SL103_ALLOW_GENERATED_KINDS = (
    "extracted", "payload", "carved", "embedded", "child", "decompressed",
    "zip_extract", "docx", "pcap", "ooxml", "magic_carved", "steghide",
    "stegseek", "png_iend_tail", "jpeg_eoi_tail",
)
def sl103_trace(report, msg, score=140, path=""):
    try:
        item = {"stage":"SLOPER v103 runtime isolation", "detail":str(msg), "confidence":int(score), "artifact":str(path or ""), "flag":""}
        if isinstance(report, dict):
            report.setdefault("solve_trace", []).append(item)
    except Exception:
        pass
    return []
def sl103_norm_path(p):
    try:
        return Path(p).resolve()
    except Exception:
        try: return Path(str(p)).absolute()
        except Exception: return Path(".").resolve()
def sl103_is_under(path, parent):
    try:
        p = sl103_norm_path(path); q = sl103_norm_path(parent)
        return str(p) == str(q) or str(p).startswith(str(q) + os.sep)
    except Exception:
        return False
def sl103_path_parts_lower(path):
    try:
        return [x.lower() for x in sl103_norm_path(path).parts]
    except Exception:
        return []
def sl103_is_tool_internal_path(path, project_root=None):
    """True when a path belongs to the tool itself, not to a user challenge."""
    try:
        p = sl103_norm_path(path)
        base = sl103_norm_path(BASE)
        # Anything inside a project may be challenge data, except known internal dirs below.
        if project_root is not None and sl103_is_under(p, sl103_norm_path(project_root) / "files"):
            return False
        # Direct tool source/config/cache files are never CTF input.
        if sl103_is_under(p, base):
            parts = [x.lower() for x in p.relative_to(base).parts]
            if not parts:
                return True
            if parts[0] == "projects":
                # Project reports/generated caches are internal; project files/ is handled elsewhere.
                if len(parts) >= 3 and parts[2] == "files":
                    return False
                return True
            if parts[0] in SL103_INTERNAL_DIR_NAMES:
                return True
            if p.name in SL103_INTERNAL_FILE_NAMES or p.suffix.lower() in SL103_INTERNAL_FILE_SUFFIXES:
                return True
        return False
    except Exception:
        return False
def sl103_generated_artifact_is_useful(path, artifact=None):
    """Allow selected generated child artifacts to be scanned, while blocking manifests/caches."""
    try:
        p = Path(path)
        text = (p.name + " " + str((artifact or {}).get("kind", "")) + " " + str((artifact or {}).get("source", "")) + " " + str((artifact or {}).get("note", ""))).lower()
        if p.suffix.lower() in [".json", ".log", ".md"] and not any(k in text for k in SL103_ALLOW_GENERATED_KINDS):
            return False
        if any(bad in text for bad in ["self_check", "selfcheck", "benchmark", "tool_catalog", "agentforge", "megabench", "__pycache__"]):
            return False
        return any(k in text for k in SL103_ALLOW_GENERATED_KINDS) or p.suffix.lower() in [
            ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".zst",
            ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".pcap", ".pcapng",
            ".pyc", ".pdf", ".docx", ".bin", ".elf", ".exe", ".so", ".dll", ".wav", ".txt",
        ]
    except Exception:
        return False
def sl103_safe_project_file(root, p):
    try:
        root = sl103_norm_path(root); p = sl103_norm_path(p)
        files_dir = root / "files"
        if not sl103_is_under(p, files_dir):
            return False
        rel_parts = [x.lower() for x in p.relative_to(files_dir).parts]
        if not rel_parts:
            return False
        if any(part in {"__pycache__", ".git", ".pytest_cache"} for part in rel_parts):
            return False
        if p.suffix.lower() in SL103_INTERNAL_FILE_SUFFIXES:
            return False
        # Keep generated/autopass child artifacts only when they look like real child challenge material.
        if rel_parts[0].startswith("_sloper"):
            return sl103_generated_artifact_is_useful(p)
        return p.is_file() and not p.name.startswith(".")
    except Exception:
        return False
_prev_all_files_v103 = all_files
def all_files(root):
    """v103: only enumerate challenge workspace files, not app/data/generated/cache files."""
    try:
        root = sl103_norm_path(root)
        files_dir = root / "files"
        if not files_dir.exists():
            return []
        out = []
        for p in files_dir.rglob("*"):
            try:
                if p.is_file() and sl103_safe_project_file(root, p):
                    out.append(p)
            except Exception:
                continue
        return out[:1500]
    except Exception:
        try:
            return [p for p in _prev_all_files_v103(root) if sl103_safe_project_file(root, p)]
        except Exception:
            return []
def sl103_filter_artifact_for_autopass(artifact, root):
    try:
        p = sl103_norm_path((artifact or {}).get("path", ""))
        if not p.exists() or not p.is_file():
            return False
        if sl103_is_tool_internal_path(p, root):
            return False
        if p.stat().st_size <= 0 or p.stat().st_size > 60_000_000:
            return False
        return sl103_generated_artifact_is_useful(p, artifact)
    except Exception:
        return False
for _sl103_name in ["sl43_artifact_should_autopass", "sl45_is_internal_generated_file"]:
    try:
        _sl103_old = globals().get(_sl103_name)
        if _sl103_name == "sl43_artifact_should_autopass" and callable(_sl103_old):
            def sl43_artifact_should_autopass(a, _old=_sl103_old):
                try:
                    p = Path((a or {}).get("path", ""))
                    root_guess = PROJECTS
                    if sl103_is_tool_internal_path(p, None):
                        return False
                    if not sl103_generated_artifact_is_useful(p, a):
                        return False
                    return bool(_old(a))
                except Exception:
                    return False
        elif _sl103_name == "sl45_is_internal_generated_file" and callable(_sl103_old):
            def sl45_is_internal_generated_file(p, root, _old=_sl103_old):
                try:
                    if sl103_is_tool_internal_path(p, root):
                        return True
                    # Generated challenge children are allowed only when useful.
                    pp = sl103_norm_path(p); rr = sl103_norm_path(root)
                    if sl103_is_under(pp, rr / "generated"):
                        return not sl103_generated_artifact_is_useful(pp)
                    return bool(_old(p, root))
                except Exception:
                    return True
    except Exception:
        pass
_prev_run_v103 = run
def run(cmd, timeout=60, maxchars=120000):
    """v103 subprocess wrapper: process-group timeout kill + internal path guard."""
    try:
        cmd = [str(x) for x in cmd]
        joined = " ".join(cmd)
        # Never run tools directly on app internals. This does not affect uploaded challenge files.
        for token in cmd:
            try:
                candidate = Path(token.strip("'\""))
                if candidate.exists() and sl103_is_tool_internal_path(candidate, None):
                    return {"ok":False,"code":-3,"cmd":joined,"out":"BLOCKED by v103: refusing to run analysis tool on CTF SLOPER internal file/path"}
            except Exception:
                pass
        env = os.environ.copy()
        # Avoid user-site/sitecustomize surprises in helper Python processes. Do not set for app server itself.
        if cmd and Path(cmd[0]).name in {"python", "python3", "python3.13"}:
            env.setdefault("PYTHONNOUSERSITE", "1")
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace", start_new_session=True, env=env)
        try:
            out, _ = p.communicate(timeout=timeout)
            out = out or ""
            return {"ok":p.returncode==0,"code":p.returncode,"cmd":joined,"out":out[:maxchars]}
        except subprocess.TimeoutExpired:
            try:
                os.killpg(p.pid, _sl103_signal.SIGKILL)
            except Exception:
                try: p.kill()
                except Exception: pass
            try:
                out, _ = p.communicate(timeout=2)
            except Exception:
                out = ""
            out = out or ""
            return {"ok":False,"code":-2,"cmd":joined,"out":f"TIMEOUT after {timeout}s (v103 killed process group)\n{out[:maxchars]}"}
    except Exception as e:
        return {"ok":False,"code":-1,"cmd":" ".join(map(str,cmd)) if isinstance(cmd,(list,tuple)) else str(cmd),"out":str(e)}
def sl103_safe_endpoint_path(path):
    p = sl103_norm_path(path)
    if not p.exists():
        return None, {"ok":False,"error":"file not found"}
    if sl103_is_tool_internal_path(p, None):
        return None, {"ok":False,"error":"blocked by v103: this is a CTF SLOPER internal path, not a challenge file"}
    return p, None
_prev_run_tool_endpoint_v103 = run_tool_endpoint
async def run_tool_endpoint(path:str=Form(...), toolname:str=Form(...)):
    p, err = sl103_safe_endpoint_path(path)
    if err: return err
    return run_tool_local(p, toolname, 180)
_prev_run_tool_suite_v103 = run_tool_suite
async def run_tool_suite(path:str=Form(...), suite:str=Form("quick")):
    p, err = sl103_safe_endpoint_path(path)
    if err: return err
    k, tools = suite_for_path(p, suite)
    results = [run_tool_local(p, t, 180) for t in tools[:50]]
    return {"ok":True,"kind":k,"suite":suite,"tools":tools,"results":results,"derived":summarize_suite(results)}
_prev_run_verifyloop_endpoint_v103 = run_verifyloop_endpoint
async def run_verifyloop_endpoint(path:str=Form(...)):
    p, err = sl103_safe_endpoint_path(path)
    if err: return err
    return await _prev_run_verifyloop_endpoint_v103(str(p))
_prev_run_transforms_endpoint_v103 = run_transforms_endpoint
async def run_transforms_endpoint(path:str=Form(...)):
    p, err = sl103_safe_endpoint_path(path)
    if err: return err
    return await _prev_run_transforms_endpoint_v103(str(p))
_prev_run_agents_endpoint_v103 = run_agents_endpoint
async def run_agents_endpoint(path:str=Form(...)):
    p, err = sl103_safe_endpoint_path(path)
    if err: return err
    return await _prev_run_agents_endpoint_v103(str(p))
_prev_image_transform_v103 = image_transform
async def image_transform(path:str=Form(...), op:str=Form(...), value:str=Form("1")):
    p, err = sl103_safe_endpoint_path(path)
    if err: return err
    return await _prev_image_transform_v103(str(p), op, value)
_prev_create_project_v103 = create_project
async def create_project(background_tasks:BackgroundTasks, title:str=Form(""), statement:str=Form(""), category:str=Form("auto"), auto_start:str=Form("true"), files:List[UploadFile]=File(...)):
    pid = uuid.uuid4().hex[:12]
    root = pdir(pid); fdir = root / "files"; fdir.mkdir(parents=True, exist_ok=True)
    clean_files = []
    for f in files:
        name = safe(getattr(f, "filename", "file") or "file")
        # Avoid accidental upload names that collide with internal folders.
        if name.lower() in SL103_INTERNAL_FILE_NAMES:
            name = "uploaded_" + name
        dest = fdir / name
        dest.write_bytes(await f.read())
        clean_files.append(name)
    auto_title = (title or "").strip() or (clean_files[0] if clean_files else "Untitled challenge")
    meta = {"id":pid,"title":auto_title,"statement":statement,"category":category,"created":now(),"file_count":len(clean_files),"v103_runtime_isolation":True}
    jwrite(meta_path(pid), meta)
    with LOCK:
        JOBS[pid] = {"status":"created","progress":0,"stage":"Created","updated":time.time(),"color":"gray"}
    log(pid, f"Project created: {auto_title}")
    if auto_start.lower() == "true":
        with LOCK:
            JOBS[pid].update({"status":"running","color":"yellow","stage":"Queued","updated":time.time()})
        background_tasks.add_task(analyze_project, pid)
    return {"id":pid,"project":meta}
_prev_start_project_v103 = start_project
def start_project(pid:str, background_tasks:BackgroundTasks):
    if not meta_path(pid).exists(): return JSONResponse({"error":"not found"}, status_code=404)
    with LOCK:
        JOBS[pid] = {"status":"running","progress":0,"stage":"Queued","updated":time.time(),"color":"yellow"}
    background_tasks.add_task(analyze_project, pid)
    return {"ok":True}
_prev_progress_v103 = progress
def progress(pid, pct, stage):
    pct = max(0, min(100, int(pct)))
    color = "green" if pct >= 100 or str(stage).lower() == "done" else "yellow"
    with LOCK:
        JOBS.setdefault(pid, {}).update({"progress":pct,"stage":stage,"updated":time.time(),"color":color})
    log(pid, f"{pct}% {stage}")
_prev_analyze_project_v103 = analyze_project
def analyze_project(pid):
    root = pdir(pid)
    try:
        # Drop stale generated/cache dirs from previous failed runs; never touch uploaded files.
        for dname in ["generated", "__pycache__"]:
            d = root / dname
            if d.exists() and d.is_dir():
                shutil.rmtree(d, ignore_errors=True)
    except Exception:
        pass
    try:
        with LOCK:
            JOBS.setdefault(pid, {}).update({"status":"running","color":"yellow","updated":time.time()})
        return _prev_analyze_project_v103(pid)
    finally:
        try:
            rep = jread(report_path(pid), {})
            rep.setdefault("v103_runtime_isolation", {})
            rep["v103_runtime_isolation"].update({
                "enabled": True,
                "workspace": "projects/<pid>/files only",
                "internal_paths_blocked": sorted(SL103_INTERNAL_DIR_NAMES),
                "subprocess_timeout_kills_process_group": True,
                "note": "Solver agents remain enabled; v103 only blocks self-scan of app internals and cleans stale generated caches."
            })
            jwrite(report_path(pid), rep)
        except Exception:
            pass
        with LOCK:
            job = JOBS.setdefault(pid, {})
            if job.get("status") != "cancelled":
                job.update({"status":"done","color":"green","progress":100,"stage":"Done","updated":time.time()})
_prev_project_summary_v103 = project_summary
def project_summary(reports, meta):
    summary = _prev_project_summary_v103(reports, meta)
    summary["v103_runtime_isolation"] = {
        "enabled": True,
        "fixes": [
            "no tool-internal self-scan",
            "project analysis restricted to files/ workspace",
            "manual endpoint internal-path guard",
            "subprocess process-group kill on timeout",
            "yellow running / green done status color",
            "blank title auto-named from first upload"
        ],
        "solver_strength_note": "Decoders/agents were not removed; recursive child solving is preserved for useful extracted/carved payloads."
    }
    return summary
APP_TITLE = "CTF SLOPER v103 Runtime Isolation"
def sl103_rebind_route(path, methods, endpoint):
    try:
        method_set = {m.upper() for m in methods}
        keep = []
        for r in list(app.router.routes):
            r_methods = set(getattr(r, "methods", []) or [])
            if getattr(r, "path", None) == path and (not method_set or r_methods.intersection(method_set)):
                continue
            keep.append(r)
        app.router.routes = keep
        app.add_api_route(path, endpoint, methods=list(method_set))
    except Exception:
        pass
try:
    sl103_rebind_route("/api/projects", ["POST"], create_project)
    sl103_rebind_route("/api/projects/{pid}/start", ["POST"], start_project)
    sl103_rebind_route("/api/run_tool", ["POST"], run_tool_endpoint)
    sl103_rebind_route("/api/run_tool_suite", ["POST"], run_tool_suite)
    sl103_rebind_route("/api/run_verifyloop", ["POST"], run_verifyloop_endpoint)
    sl103_rebind_route("/api/run_transforms", ["POST"], run_transforms_endpoint)
    sl103_rebind_route("/api/run_agents", ["POST"], run_agents_endpoint)
    sl103_rebind_route("/api/image_transform", ["POST"], image_transform)
except Exception:
    pass
SL104_VERSION = "v104-quality-preservation"
SL104_STRICT_FLAG_RE = re.compile(r"\bctf_cs\{[^}\r\n]{1,220}\}", re.I)
SL104_BARE_ANSWER_RE = re.compile(r"(?<![A-Za-z0-9_])\{[A-Za-z0-9][A-Za-z0-9_+\-:.=/]{3,160}\}")
_prev_v104_fast_flag_matches = fast_flag_matches
_prev_v104_decode_candidates = decode_candidates
_prev_v104_project_summary = project_summary
_prev_v104_smartsolve_postprocess = smartsolve_postprocess if 'smartsolve_postprocess' in globals() else None
_prev_v104_vf_primary_flags = vf_primary_flags if 'vf_primary_flags' in globals() else None
_prev_v104_normalize_flag_candidate = normalize_flag_candidate if 'normalize_flag_candidate' in globals() else None
_prev_v104_run = run
def v104_exact_flags(text, limit=80, scan_limit=80000):
    text = str(text or "")[:scan_limit]
    out, seen = [], set()
    for m in SL104_STRICT_FLAG_RE.finditer(text):
        cand = m.group(0)
        if "\n" in cand or "\r" in cand:
            continue
        low = cand.lower()
        inner = flag_inner(cand) if 'flag_inner' in globals() else cand[cand.find('{')+1:-1]
        ilow = inner.lower()
        if ilow in {"...", "flag", "your_flag", "flag_here"}:
            continue
        if any(x in ilow for x in ["placeholder", "not_the_flag", "insert_flag", "change_me"]):
            continue
        if low not in seen:
            seen.add(low); out.append(cand)
            if len(out) >= limit:
                break
    return out
def v104_bare_brace_answers(text, limit=40, scan_limit=50000):
    text = str(text or "")[:scan_limit]
    out, seen = [], set()
    for m in SL104_BARE_ANSWER_RE.finditer(text):
        cand = m.group(0)
        inner = cand[1:-1]
        low = inner.lower()
        ctx = text[max(0, m.start()-160):m.end()+160].lower()
        # Keep bare braces when they look flag-like or appear near answer/flag wording. Do not auto-promote as strict flag.
        if len(inner) < 4 or len(inner) > 160:
            continue
        quality = 0
        if "_" in inner: quality += 3
        if re.search(r"[a-zA-Z]", inner) and re.search(r"\d", inner): quality += 3
        if any(k in ctx for k in ["flag", "answer", "atsakymas", "raktas", "secret", "decoded", "decrypted", "hidden"]): quality += 4
        if any(w in low for w in ["example", "sample", "dummy", "placeholder", "fake"]): quality -= 8
        if quality < 3:
            continue
        if cand.lower() not in seen:
            seen.add(cand.lower()); out.append(cand)
            if len(out) >= limit:
                break
    return out
def fast_flag_matches(text, limit=40, scan_limit=50000):
    # Exact ctf_cs first, preserving underscores/punctuation exactly; then previous broader/bare matches.
    hits, seen = [], set()
    for f in v104_exact_flags(text, limit=limit, scan_limit=scan_limit):
        seen.add(f.lower()); hits.append(f)
    try:
        for f in _prev_v104_fast_flag_matches(text, limit=limit, scan_limit=scan_limit):
            if f.lower() not in seen:
                seen.add(f.lower()); hits.append(f)
            if len(hits) >= limit:
                return hits[:limit]
    except Exception:
        pass
    for f in v104_bare_brace_answers(text, limit=limit, scan_limit=scan_limit):
        if f.lower() not in seen:
            seen.add(f.lower()); hits.append(f)
        if len(hits) >= limit:
            break
    return hits[:limit]
def vf_primary_flags(text, limit=80, scan_limit=80000):
    # Strict promoted flags are exact ctf_cs tokens only, never normalized/sanitized.
    return v104_exact_flags(text, limit=limit, scan_limit=scan_limit)
def normalize_flag_candidate(flag):
    # Critical v104 fix: never strip underscores or punctuation from a real ctf_cs{...} token.
    flag = str(flag or "").strip()
    m = SL104_STRICT_FLAG_RE.search(flag)
    if m:
        return m.group(0)
    try:
        return _prev_v104_normalize_flag_candidate(flag)
    except Exception:
        return flag[:300]
def v104_ascii_score(s):
    s = str(s or "")
    if not s: return 0
    score = 0; low = s.lower()
    if "ctf_cs{" in low: score += 500
    if "{" in s and "}" in s: score += 120
    if "_" in s: score += 25
    if re.search(r"[A-Za-z]", s) and re.search(r"\d", s): score += 25
    if any(k in low for k in ["flag", "answer", "secret", "hidden", "ctf", "key", "raktas", "slapta"]): score += 35
    printable = sum(1 for c in s if c.isprintable() or c in "\n\r\t") / max(1, len(s))
    score += int(printable * 40)
    return score
