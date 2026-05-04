# Auto-split from sloper_legacy_monolith.py lines 19599-...
def sl92_art(root, report, name, content, kind="sloper_v92_artifact", score=100, note="", binary=False, subdir="visual_first"):
    outdir = root / "generated" / "sloper_v92" / subdir / safe(report.get("name", "file"))
    outdir.mkdir(parents=True, exist_ok=True)
    path = outdir / safe(name)
    try:
        if binary:
            path.write_bytes(content if isinstance(content, (bytes, bytearray)) else bytes(content))
        else:
            path.write_text(str(content), encoding="utf-8", errors="ignore")
        art = {
            "kind": kind,
            "name": path.name,
            "path": str(path),
            "url": sl92_url(path),
            "source": "CTF SLOPER v92 VisualFirst",
            "score": int(score or 0),
            "note": note or kind,
            "exists": True,
            "size": path.stat().st_size,
            "file": report.get("rel", ""),
        }
        report.setdefault("artifacts", []).append(art)
        report.setdefault("transformations", []).append(art)
        try: sl_trace(report, "V92Artifact", f"{kind}: {path.name}", score, str(path))
        except Exception: pass
        return art
    except Exception as e:
        try: sl_trace(report, "V92ArtifactError", f"{name}: {e}", 0)
        except Exception: pass
        return None
def sl92_save_image(root, report, outdir, name, img, score=100, note=""):
    try:
        outdir.mkdir(parents=True, exist_ok=True)
        path = outdir / safe(name if name.lower().endswith(".png") else name + ".png")
        # Keep visual artifacts reasonably light for UI.
        im = img.copy()
        try:
            if max(im.size) > 2200:
                im.thumbnail((2200, 2200))
        except Exception:
            pass
        if getattr(im, "mode", "RGB") not in ["RGB", "RGBA", "L", "1"]:
            im = im.convert("RGB")
        im.save(path)
        art = {
            "kind": "sloper_v92_visual_image",
            "name": path.name,
            "path": str(path),
            "url": sl92_url(path),
            "source": "CTF SLOPER v92 VisualFirst",
            "score": int(score or 0),
            "note": note or name,
            "exists": True,
            "size": path.stat().st_size,
            "file": report.get("rel", ""),
        }
        report.setdefault("artifacts", []).append(art)
        report.setdefault("transformations", []).append(art)
        report.setdefault("previews", []).append({"name": "v92_" + path.stem, "url": art["url"], "path": art["path"], "score": score, "ocr": "", "qr": "", "flags": []})
        return art
    except Exception as e:
        try: sl_trace(report, "V92ImageSaveError", f"{name}: {e}", 0)
        except Exception: pass
        return None
def sl92_text_quality(s):
    s = str(s or "")
    if not s:
        return 0
    printable = sum((32 <= ord(c) < 127) or c in "\n\r\t" for c in s) / max(1, len(s))
    words = len(re.findall(r"[A-Za-z]{3,}", s))
    braces = 60 if ("{" in s and "}" in s) else 0
    ctfish = 50 if re.search(r"ctf|flag|secret|hidden|slapta|raktas|veliava", s, re.I) else 0
    return int(printable * 70 + min(words, 20) * 2 + braces + ctfish)
def sl92_bits_to_text(bits, max_bytes=350000):
    out = bytearray()
    n = min(len(bits) // 8, max_bytes)
    for i in range(n):
        b = 0
        base = i * 8
        for bit in bits[base:base+8]:
            b = (b << 1) | (int(bit) & 1)
        out.append(b)
    try:
        return out.decode("utf-8", "replace")
    except Exception:
        return bytes(out).decode("latin1", "replace")
def sl92_extract_lsb_texts(img_rgba):
    """Bounded LSB text variants. Produces reviewable text, not just hidden internal candidates."""
    variants = []
    try:
        small = img_rgba.copy()
        # LSB extraction from the original pixels can be huge; cap by pixel count.
        pixels = list(small.getdata())[:900000]
        orders = [
            ("RGB", (0,1,2)), ("BGR", (2,1,0)), ("RGBA", (0,1,2,3)),
            ("ARGB", (3,0,1,2)), ("A", (3,)), ("R", (0,)), ("G", (1,)), ("B", (2,)),
        ]
        for bit in [0, 1, 7]:
            for name, idxs in orders:
                bits = []
                for px in pixels:
                    for idx in idxs:
                        bits.append((px[idx] >> bit) & 1)
                if len(bits) < 16:
                    continue
                txt = sl92_bits_to_text(bits)
                q = sl92_text_quality(txt)
                flags = fast_flag_matches(txt, limit=10, scan_limit=50000) if "fast_flag_matches" in globals() else []
                if q >= 35 or flags:
                    variants.append({"name": f"lsb_bit{bit}_{name}", "text": txt[:50000], "score": q + (180 if flags else 0), "flags": flags})
                # Some tools pack low-bit streams reversed.
                if bit == 0 and name in ["RGB", "BGR", "RGBA", "A"]:
                    rtxt = sl92_bits_to_text(list(reversed(bits)))
                    rq = sl92_text_quality(rtxt)
                    rflags = fast_flag_matches(rtxt, limit=10, scan_limit=50000) if "fast_flag_matches" in globals() else []
                    if rq >= 45 or rflags:
                        variants.append({"name": f"lsb_bit{bit}_{name}_reversed", "text": rtxt[:50000], "score": rq + (180 if rflags else 0), "flags": rflags})
    except Exception as e:
        variants.append({"name": "lsb_error", "text": str(e), "score": 0, "flags": []})
    return sorted(variants, key=lambda x: x.get("score", 0), reverse=True)[:36]
def sl92_channel_bitplane_images(root, report, img_rgba, outdir):
    arts=[]
    try:
        channels = img_rgba.split()
        names = ["R", "G", "B", "A"]
        # Always save alpha if non-flat; for RGB save low bits and high bit for visible masks.
        for ci, ch in enumerate(channels):
            extrema = ch.getextrema()
            if names[ci] == "A" and extrema[0] == extrema[1] == 255:
                continue
            base_score = 175 if names[ci] == "A" and extrema[0] != extrema[1] else 120
            arts.append(sl92_save_image(root, report, outdir, f"channel_{names[ci]}_autocontrast", ImageOps.autocontrast(ch), base_score, f"{names[ci]} channel autocontrast"))
            bits_to_save = range(8) if names[ci] == "A" and extrema[0] != extrema[1] else [0,1,2,7]
            for b in bits_to_save:
                bp = ch.point(lambda x, b=b: 255 if ((x >> b) & 1) else 0)
                arts.append(sl92_save_image(root, report, outdir, f"bitplane_{names[ci]}_{b}", bp, base_score + (20 if b == 0 else 0), f"{names[ci]} bitplane {b}; open visually for hidden text/QR"))
        # Difference/XOR style helpers: common when hidden text is only visible between channels.
        r,g,b,a = channels
        for nm, im in [
            ("diff_R_G", ImageChops.difference(r,g)),
            ("diff_R_B", ImageChops.difference(r,b)),
            ("diff_G_B", ImageChops.difference(g,b)),
        ]:
            arts.append(sl92_save_image(root, report, outdir, nm, ImageOps.autocontrast(im), 115, "channel difference / hidden contrast"))
    except Exception as e:
        try: sl_trace(report, "V92BitplaneError", str(e), 0)
        except Exception: pass
    return [x for x in arts if x]
def sl92_contact_sheet(root, report, outdir, arts, name="00_OPEN_FIRST_visual_contact_sheet.png"):
    try:
        imgs = [a for a in arts if a and Path(a.get("path","")).exists() and str(a.get("path","")).lower().endswith((".png",".jpg",".jpeg",".bmp",".webp"))]
        # Prioritize what a human should open first.
        def pri(a):
            txt=(str(a.get("name",""))+" "+str(a.get("note",""))+" "+str(a.get("kind",""))).lower()
            bonus=0
            if "contact" in txt: bonus+=500
            if "alpha" in txt or "bitplane_a" in txt: bonus+=260
            if "lsb" in txt or "bitplane" in txt: bonus+=160
            if "threshold" in txt or "qr" in txt: bonus+=120
            return int(a.get("score",0))+bonus
        imgs = sorted(imgs, key=pri, reverse=True)[:48]
        if not imgs:
            return None
        cols=4; tile_w=330; tile_h=260
        rows=max(1, math.ceil(len(imgs)/cols))
        sheet=Image.new("RGB", (cols*tile_w, rows*tile_h), (12,14,18))
        draw=ImageDraw.Draw(sheet)
        for i,a in enumerate(imgs):
            x=(i%cols)*tile_w; y=(i//cols)*tile_h
            tile=Image.new("RGB", (tile_w, tile_h), (24,27,34))
            try:
                im=Image.open(a["path"]).convert("RGB")
                im.thumbnail((tile_w-24, tile_h-72))
                tile.paste(im, (12,10))
            except Exception:
                pass
            label=(a.get("name","")[:38] + f"  score={a.get('score',0)}")
            try:
                d=ImageDraw.Draw(tile)
                d.rectangle((0,tile_h-58,tile_w,tile_h), fill=(8,10,14))
                d.text((10,tile_h-52), label, fill=(235,235,235))
                note=str(a.get("note", ""))[:44]
                if note: d.text((10,tile_h-34), note, fill=(180,190,205))
            except Exception:
                pass
            sheet.paste(tile,(x,y))
        art=sl92_save_image(root, report, outdir, name, sheet, 360, "OPEN FIRST: labeled visual contact sheet of the highest-value reconstructions")
        if art:
            art["kind"]="sloper_v92_open_first_contact_sheet"
            art["score"]=420
        return art
    except Exception as e:
        try: sl_trace(report,"V92ContactSheetError",str(e),0)
        except Exception: pass
        return None
def sl92_visual_first_image_agent(report, root, data):
    path=Path(report.get("path", ""))
    if path.suffix.lower() not in SL92_VISUAL_EXTS and report.get("kind") != "image":
        return []
    if report.get("_sl92_visual_done"):
        return []
    report["_sl92_visual_done"] = True
    arts=[]
    try:
        if _sl92_importlib:
            try:
                _sl92_importlib.import_module("PIL.ImageFile").LOAD_TRUNCATED_IMAGES = True
            except Exception:
                pass
        im0 = Image.open(path)
        try: im0.load()
        except Exception: pass
        mode0 = getattr(im0, "mode", "")
        rgba = im0.convert("RGBA")
        rgb = rgba.convert("RGB")
        outdir=root/"generated"/"sloper_v92"/"visual_first"/safe(report.get("name", path.stem))
        meta = {
            "file": report.get("rel", path.name), "mode": mode0, "size": list(rgba.size),
            "pil_info": {str(k): str(v)[:300] for k,v in getattr(im0, "info", {}).items()},
            "purpose": "Open 00_OPEN_FIRST_visual_contact_sheet.png first. Then inspect alpha/bitplanes/thresholds and lsb_text_candidates.txt.",
        }
        arts.append(sl92_art(root, report, "00_VISUAL_FIRST_README.md", "# V92 Visual-first review\n\nOpen `00_OPEN_FIRST_visual_contact_sheet.png` first. Then inspect alpha, bitplanes, thresholds, and LSB text candidates.\n\n```json\n"+json.dumps(meta,indent=2,ensure_ascii=False)+"\n```\n", "sloper_v92_visual_readme", 430, "Visual review instructions", subdir="visual_first"))
        preview=rgb.copy()
        if max(preview.size)>1600: preview.thumbnail((1600,1600))
        arts.append(sl92_save_image(root, report, outdir, "01_original_preview", preview, 100, "original preview"))
        gray=ImageOps.grayscale(preview)
        base_visuals=[
            ("02_gray_autocontrast", ImageOps.autocontrast(gray), 130, "grayscale autocontrast"),
            ("03_invert", ImageOps.invert(gray), 110, "inverted grayscale"),
            ("04_edges_autocontrast", ImageOps.autocontrast(gray.filter(ImageFilter.FIND_EDGES)), 145, "edges/autocontrast"),
        ]
        for t in [40,64,96,128,160,192,220]:
            base_visuals.append((f"threshold_{t}", gray.point(lambda x, thr=t: 255 if x>thr else 0), 125, f"threshold {t}; QR/text recovery"))
        for scale in [2,4]:
            try:
                up=ImageOps.autocontrast(gray).resize((gray.size[0]*scale, gray.size[1]*scale))
                base_visuals.append((f"qr_upscale_{scale}x_autocontrast", up, 150+scale, "upscaled for QR/barcode/manual reading"))
            except Exception: pass
        for nm,img,sc,note in base_visuals:
            arts.append(sl92_save_image(root, report, outdir, nm, img, sc, note))
        arts += sl92_channel_bitplane_images(root, report, rgba, outdir)
        # LSB text artifacts: make them visible in Artifacts tab.
        lsb_variants=sl92_extract_lsb_texts(rgba)
        if lsb_variants:
            textblob=[]
            for v in lsb_variants:
                textblob.append(f"===== {v['name']} score={v.get('score',0)} flags={v.get('flags',[])} =====\n{v.get('text','')[:12000]}\n")
                try:
                    sl_promote_text(report, v.get("text", ""), "V92 LSB VisualFirst", v["name"], None, int(v.get("score",0))+160)
                except Exception:
                    pass
            art=sl92_art(root, report, "lsb_text_candidates.txt", "\n".join(textblob), "sloper_v92_lsb_text_candidates", 300, "Open this if bitplanes look noisy; contains decoded LSB text variants.", subdir="visual_first")
            arts.append(art)
        # Raw trailing/appended signatures: common in corrupted/visual stego files.
        try:
            sigs=[(b"PK\x03\x04","zip"),(b"\x1f\x8b\x08","gzip"),(b"BZh","bzip2"),(b"\xfd7zXZ\x00","xz"),(b"\x89PNG\r\n\x1a\n","png"),(b"\xff\xd8\xff","jpg")]
            manifest=[]
            for sig,label in sigs:
                start=0
                while True:
                    off=data.find(sig,start)
                    if off<0: break
                    if off>0:
                        carved=data[off:]
                        ext=".bin" if label not in ["zip","gzip","png","jpg"] else {"zip":".zip","gzip":".gz","png":".png","jpg":".jpg"}[label]
                        cpath=safe(f"carved_{label}_offset_{off}{ext}")
                        art=sl92_art(root, report, cpath, carved, "sloper_v92_carved_appended_signature", 240, f"Carved {label} signature at offset {off}", binary=True, subdir="visual_first/carved")
                        arts.append(art); manifest.append({"offset":off,"label":label,"artifact":art.get("path") if art else ""})
                    start=off+1
                    if len(manifest)>20: break
            if manifest:
                arts.append(sl92_art(root, report, "carved_signature_manifest.json", json.dumps(manifest,indent=2), "sloper_v92_carved_manifest", 250, "Embedded/appended file signatures found", subdir="visual_first"))
        except Exception:
            pass
        contact=sl92_contact_sheet(root, report, outdir, [a for a in arts if a], "00_OPEN_FIRST_visual_contact_sheet.png")
        if contact:
            arts.insert(0, contact)
        try: report["answer_candidates"] = vf_collect_answer_candidates(report)
        except Exception: pass
        try: sl_trace(report, "V92VisualFirst", f"generated {len([a for a in arts if a])} visual/reconstruction artifacts", 420, contact.get("path") if contact else "")
        except Exception: pass
    except Exception as e:
        arts.append(sl92_art(root, report, "visual_first_error.txt", str(e), "sloper_v92_visual_error", 10, "V92 visual agent error", subdir="visual_first"))
    return [a for a in arts if a]
def sl92_artifact_log_reconstruct(report, root, data):
    text=data.decode("utf-8", "ignore")
    if '"x"' not in text or '"rows"' not in text:
        return []
    entries=[]
    for line in text.splitlines():
        try:
            obj=json.loads(line)
            if all(k in obj for k in ["x","y","rows"]) and isinstance(obj.get("rows"), list):
                obj["x"]=int(obj.get("x",0)); obj["y"]=int(obj.get("y",0)); obj["rows"]=[str(r) for r in obj.get("rows", [])]
                entries.append(obj)
        except Exception:
            pass
    if len(entries)<3:
        return []
    useful=set(" $/_\\|()[]{}<>.:;,_-+ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
    artchars=set(" $/_\\|")
    scored=[]
    for i,e in enumerate(entries):
        raw="".join(e["rows"])
        if not raw: continue
        art_ratio=sum(ch in artchars for ch in raw)/max(1,len(raw))
        useful_ratio=sum(ch in useful for ch in raw)/max(1,len(raw))
        noise_ratio=sum(ch in "@#%?!*&" for ch in raw)/max(1,len(raw))
        nonspace=sum(ch!=" " for ch in raw)
        score=art_ratio*100 + useful_ratio*30 + min(nonspace,40) - noise_ratio*130
        e2=dict(e); e2["_score"]=round(score,2); e2["_line_index"]=i; scored.append(e2)
    # Pick the best tile for each x/y/dimensions; this handles duplicated corrupted chunks.
    byslot={}
    for e in scored:
        h=len(e["rows"]); w=max((len(r) for r in e["rows"]), default=0)
        key=(e["x"],e["y"],w,h)
        if key not in byslot or e["_score"]>byslot[key]["_score"]:
            byslot[key]=e
    chosen=[e for e in byslot.values() if e["_score"]>=45]
    if not chosen:
        chosen=sorted(scored,key=lambda x:x["_score"],reverse=True)[:max(3,len(scored)//3)]
    maxx=max(e["x"]+max(len(r) for r in e["rows"]) for e in chosen)
    maxy=max(e["y"]+len(e["rows"]) for e in chosen)
    canvas=[[" "]*maxx for _ in range(maxy)]
    for e in sorted(chosen,key=lambda x:(x["y"],x["x"],-x["_score"])):
        for dy,row in enumerate(e["rows"]):
            for dx,ch in enumerate(row):
                if ch!=" ":
                    yy=e["y"]+dy; xx=e["x"]+dx
                    if 0<=yy<maxy and 0<=xx<maxx:
                        canvas[yy][xx]=ch
    art_text="\n".join("".join(row).rstrip() for row in canvas)
    arts=[]
    arts.append(sl92_art(root, report, "00_OPEN_FIRST_artifact_log_reconstructed_ascii.txt", art_text, "sloper_v92_artifact_log_ascii", 390, "OPEN FIRST: coordinate JSON chunks reconstructed into ASCII canvas", subdir="artifact_reconstruction"))
    meta={"entries_total":len(entries),"slots":len(byslot),"chosen":len(chosen),"width":maxx,"height":maxy,"top_rejected":sorted([{k:e[k] for k in ["x","y","_score","_line_index"] if k in e} for e in scored if e not in chosen], key=lambda x:x.get("_score",0), reverse=True)[:50]}
    arts.append(sl92_art(root, report, "artifact_log_reconstruction_scoring.json", json.dumps(meta,indent=2,ensure_ascii=False), "sloper_v92_artifact_log_meta", 250, "Scored duplicate/noisy chunks; useful for manual audit", subdir="artifact_reconstruction"))
    # Render as a PNG so the visual answer is instantly readable in the UI gallery.
    try:
        scale_x, scale_y = 8, 13
        margin=16
        img=Image.new("RGB", (max(1,maxx*scale_x+margin*2), max(1,maxy*scale_y+margin*2)), (10,12,16))
        draw=ImageDraw.Draw(img)
        y=margin
        for line in art_text.splitlines():
            draw.text((margin,y), line, fill=(235,240,235))
            y += scale_y
        outdir=root/"generated"/"sloper_v92"/"artifact_reconstruction"/safe(report.get("name","artifact"))
        png=sl92_save_image(root, report, outdir, "00_OPEN_FIRST_artifact_log_reconstructed_ascii_png", img, 430, "OPEN FIRST: rendered ASCII reconstruction as image")
        if png:
            png["kind"]="sloper_v92_artifact_log_visual_render"
            arts.insert(0,png)
    except Exception as e:
        try: sl_trace(report,"V92ArtifactLogPngError",str(e),0)
        except Exception: pass
    try:
        sl_promote_text(report, art_text, "V92 ArtifactLog Reconstruction", "ASCII canvas", arts[0].get("path") if arts and arts[0] else "", 360)
    except Exception:
        pass
    try: sl_trace(report, "V92ArtifactLogReconstruction", f"chosen {len(chosen)}/{len(entries)} chunks; canvas {maxx}x{maxy}", 430, arts[0].get("path") if arts and arts[0] else "")
    except Exception: pass
    return [a for a in arts if a]
def sl92_kind_from_name(name):
    suf=Path(name).suffix.lower()
    if suf in SL92_VISUAL_EXTS: return "image"
    if suf in [".pcap", ".pcapng"]: return "pcap"
    if suf in [".txt", ".log", ".csv", ".json", ".md", ".xml", ".html", ".js", ".css"]: return "text"
    if suf in [".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".xz", ".bz2"]: return "archive"
    if suf in [".wav", ".mp3", ".flac", ".ogg"]: return "media"
    if suf == ".pyc": return "python_bytecode"
    return "generic"
_prev_rb_enhance_report_v92 = rb_enhance_report
def rb_enhance_report(root, report, data):
    try:
        _prev_rb_enhance_report_v92(root, report, data)
    except Exception as e:
        try: sl_trace(report, "V92PreviousEnhanceError", str(e), 0)
        except Exception: pass
    arts=[]
    try:
        arts += sl92_visual_first_image_agent(report, root, data)
    except Exception as e:
        try: sl_trace(report, "V92VisualFirstError", str(e), 0)
        except Exception: pass
    try:
        if Path(report.get("path","")).name.lower()=="artifact.log" or ('"x"' in data[:200000].decode("utf-8","ignore") and '"rows"' in data[:200000].decode("utf-8","ignore")):
            arts += sl92_artifact_log_reconstruct(report, root, data)
    except Exception as e:
        try: sl_trace(report, "V92ArtifactLogError", str(e), 0)
        except Exception: pass
    # Deduplicate artifact list while preserving top scores.
    try:
        best={}
        for a in report.get("artifacts",[]):
            k=a.get("path") or (a.get("kind"),a.get("name"))
            if k not in best or int(a.get("score",0) or 0)>int(best[k].get("score",0) or 0):
                best[k]=a
        report["artifacts"]=sorted(best.values(), key=lambda a:(int(a.get("score",0) or 0), bool(a.get("exists",False)), int(a.get("size",0) or 0)), reverse=True)[:3000]
    except Exception:
        pass
    return report
_prev_cs_static_benchmark_zip_v92 = cs_static_benchmark_zip
def cs_static_benchmark_zip(zip_path="/mnt/data/Cyber Sprint 2026 1 etapas.zip"):
    """V92 bounded static benchmark. It avoids full binary decode loops and surfaces visual artifacts."""
    zip_path=Path(zip_path)
    if not zip_path.exists():
        return {"ok":False,"error":"zip not found","path":str(zip_path)}
    tmp=BASE/"generated"/"cybersprint_zip_bench_v92"
    if tmp.exists():
        shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True, exist_ok=True)
    results=[]
    with zipfile.ZipFile(zip_path) as z:
        names=[n for n in z.namelist() if not n.endswith("/") and "__MACOSX" not in n]
        # group by category/challenge, assuming zip/category/challenge/file
        groups={}
        for n in names:
            parts=Path(n).parts
            if len(parts)>=4:
                key=(parts[-3],parts[-2])
            elif len(parts)>=3:
                key=(parts[-2],parts[-1])
            else:
                key=("root",Path(n).parent.name or "files")
            groups.setdefault(key,[]).append(n)
        for (cat,ch),files in sorted(groups.items()):
            report={"title":cat+"/"+ch,"category":cat,"challenge":ch,"files":len(files),"flags":[],"answers":[],"artifacts":[],"notes":[],"visual_first":[]}
            fake_root=tmp/safe(cat+"_"+ch); fake_root.mkdir(parents=True,exist_ok=True)
            for n in files:
                try: data=z.read(n)
                except Exception: continue
                rel=Path(n).name
                fp=fake_root/safe(rel); fp.write_bytes(data)
                kind=sl92_kind_from_name(rel)
                text=data[:1_200_000].decode("utf-8","ignore") if kind in ["text","generic","python_bytecode"] else "\n".join(py_strings(data,limit=1200))
                r={"name":rel,"rel":rel,"path":str(fp),"kind":kind,"file":"","artifacts":[],"transformations":[],"strings":py_strings(data,limit=1200),"outputs":[],"flags":vf_primary_flags(text,limit=30,scan_limit=120000),"chain_results":[],"previews":[],"verified_flags":[],"answer_candidates":[],"solve_trace":[]}
                rb_enhance_report(fake_root,r,data)
                # Only run text decoders on bounded text-like data, never megabytes of binary noise.
                if kind in ["text","generic","python_bytecode"] and text:
                    try:
                        for c in (mb_fast_chain(text,max_depth=5,state_limit=220)[:18] if "mb_fast_chain" in globals() else []):
                            r.setdefault("chain_results",[]).append(c)
                            for fl in c.get("flags",[]):
                                if fl not in r["flags"]: r["flags"].append(fl)
                    except Exception: pass
                    try:
                        for c in (ff_extra_decoders(text)[:12] if "ff_extra_decoders" in globals() else []):
                            r.setdefault("chain_results",[]).append(c)
                            for fl in c.get("flags",[]):
                                if fl not in r["flags"]: r["flags"].append(fl)
                    except Exception: pass
                    try: sl_promote_text(r,text,"V92StaticText","bounded text scan",None,120)
                    except Exception: pass
                try: r["answer_candidates"]=vf_collect_answer_candidates(r)
                except Exception: pass
                report["flags"] += [x for x in r.get("flags",[]) if smartsolve_strict_target_flag_ok(x)]
                report["answers"] += [a.get("value") for a in r.get("answer_candidates",[])[:8] if a.get("value")]
                arts=sorted(r.get("artifacts",[]), key=lambda a:int(a.get("score",0) or 0), reverse=True)[:16]
                report["artifacts"] += [{"name":a.get("name"),"kind":a.get("kind"),"path":a.get("path"),"score":a.get("score"),"note":a.get("note"),"source":a.get("source")} for a in arts]
                report["visual_first"] += [a.get("path") for a in arts if "OPEN_FIRST" in str(a.get("name","")) or "open_first" in str(a.get("kind","")).lower()]
                if r.get("chain_results"):
                    report["notes"].append("chain:"+str(r["chain_results"][0].get("type")))
                if kind=="image":
                    report["notes"].append("visual-first artifacts generated")
            report["flags"]=list(dict.fromkeys(report["flags"]))[:50]
            report["answers"]=list(dict.fromkeys([x for x in report["answers"] if x]))[:30]
            report["status"]="flag" if report["flags"] else ("answer/artifact" if report["answers"] or report["artifacts"] else "unresolved")
            results.append(report)
    solved=sum(1 for r in results if r["flags"])
    has_signal=sum(1 for r in results if r["status"]!="unresolved")
    visual=sum(1 for r in results if r.get("visual_first"))
    return {"ok":True,"engine":"v92_visual_first_static","zip":str(zip_path),"total":len(results),"with_flags":solved,"with_signal":has_signal,"with_visual_first":visual,"unresolved":len(results)-has_signal,"results":results}
def sl92_extract_lsb_texts(img_rgba):
    """Fast bounded LSB text variants using numpy packbits; avoids UI/benchmark hangs on megapixel PNGs."""
    variants=[]
    try:
        arr=np.array(img_rgba)
        if arr.ndim!=3 or arr.shape[2]<4:
            return []
        flat=arr.reshape(-1, arr.shape[2])[:, :4]
        max_px=260000
        if flat.shape[0] > max_px:
            step=max(1, flat.shape[0]//max_px)
            flat=flat[::step][:max_px]
        orders=[("RGB",[0,1,2]),("BGR",[2,1,0]),("RGBA",[0,1,2,3]),("A",[3]),("R",[0]),("G",[1]),("B",[2])]
        def text_from_bits(vals):
            vals=np.asarray(vals,dtype=np.uint8).reshape(-1)
            usable=(len(vals)//8)*8
            if usable<16: return ""
            packed=np.packbits(vals[:min(usable, 350000*8)])
            return bytes(packed).decode("utf-8","replace")
        for bit in [0,1]:
            for name,idxs in orders:
                vals=((flat[:,idxs] >> bit) & 1).astype(np.uint8).reshape(-1)
                txt=text_from_bits(vals)
                q=sl92_text_quality(txt)
                flags=fast_flag_matches(txt,limit=10,scan_limit=50000) if "fast_flag_matches" in globals() else []
                if q>=35 or flags:
                    variants.append({"name":f"lsb_bit{bit}_{name}","text":txt[:50000],"score":q+(180 if flags else 0),"flags":flags})
                if bit==0 and name in ["RGB","BGR","A"]:
                    rtxt=text_from_bits(vals[::-1])
                    rq=sl92_text_quality(rtxt)
                    rflags=fast_flag_matches(rtxt,limit=10,scan_limit=50000) if "fast_flag_matches" in globals() else []
                    if rq>=45 or rflags:
                        variants.append({"name":f"lsb_bit{bit}_{name}_reversed","text":rtxt[:50000],"score":rq+(180 if rflags else 0),"flags":rflags})
        a=flat[:,3]
        if int(a.min()) != int(a.max()):
            vals=((a >> 7) & 1).astype(np.uint8)
            txt=text_from_bits(vals)
            q=sl92_text_quality(txt); flags=fast_flag_matches(txt,limit=10,scan_limit=50000) if "fast_flag_matches" in globals() else []
            if q>=30 or flags:
                variants.append({"name":"alpha_msb_text","text":txt[:50000],"score":q+(180 if flags else 0),"flags":flags})
    except Exception as e:
        variants.append({"name":"lsb_error","text":str(e),"score":0,"flags":[]})
    return sorted(variants,key=lambda x:x.get("score",0),reverse=True)[:24]
APP_TITLE = "CTF SLOPER v98 UX Reasoning"
if __name__=="__main__":
    import uvicorn
    uvicorn.run(app,host="127.0.0.1",port=7860)
APP_TITLE = "CTF SLOPER v98 UX Reasoning"
V98_PATTERN_CATALOG_VERSION = "v98_ux_reasoning"
def v98_text_art(root, report, name, text, kind="v98_text_artifact", score=120, note=""):
    try:
        outdir = Path(root)/"generated"/"v98"/safe(report.get("name","artifact"))
        outdir.mkdir(parents=True, exist_ok=True)
        path = outdir/safe(name)
        path.write_text(str(text)[:500000], encoding="utf-8", errors="ignore")
        art={"kind":kind,"name":name,"path":str(path),"url":"/api/raw?path="+str(path),"source":"SLOPER v98","score":score,"note":note,"exists":True,"size":path.stat().st_size,"file":report.get("rel","")}
        report.setdefault("artifacts",[]).append(art)
        report.setdefault("transformations",[]).append(art)
        try:
            for fl in vf_primary_flags(str(text), limit=20, scan_limit=120000):
                if fl not in report.setdefault("flags",[]): report["flags"].append(fl)
        except Exception: pass
        try:
            sl_promote_text(report, str(text), "v98", note or kind, str(path), score)
        except Exception: pass
        return art
    except Exception:
        return None
def v98_route_transposition_agent(root, report, data):
    """Bounded route-transposition workbench for short noisy crypto strings."""
    try:
        txt=data.decode("utf-8","ignore").strip()
    except Exception:
        return []
    if not txt or len(txt)>6000 or len(txt)<20: return []
    if not re.fullmatch(r"[\x20-\x7e\r\n\t]+", txt): return []
    s="".join(x for x in txt.split() if x)
    if len(s)<20 or len(s)>2000: return []
    outs=[]
    def q(t):
        low=t.lower(); score=0
        for k,w in [("ctf_cs{",200),("ctf",80),("flag",70),("cyber",65),("sprint",65),("secret",55),("hidden",45),("_",8),("{",25),("}",25)]: score += low.count(k)*w
        score += sum(c.isalnum() or c in "{}_-.+:" for c in t)/max(1,len(t))*25
        return score
    n=len(s)
    dims=[]
    for r in range(2,80):
        if n%r==0: dims.append((r,n//r))
    for rows,cols in dims[:80]:
        grid=[s[i*cols:(i+1)*cols] for i in range(rows)]
        variants=[]
        variants.append(("rowfill_colread", ''.join(grid[r][c] for c in range(cols) for r in range(rows))))
        variants.append(("rowfill_colread_revrows", ''.join(grid[r][c] for c in range(cols) for r in reversed(range(rows)))))
        variants.append(("rowfill_colread_revcols", ''.join(grid[r][c] for c in reversed(range(cols)) for r in range(rows))))
        variants.append(("rowfill_rowreverse_colread", ''.join((grid[r][::-1] if r%2 else grid[r])[c] for c in range(cols) for r in range(rows))))
        # column fill -> row read
        cg=[['']*cols for _ in range(rows)]; it=iter(s)
        for c in range(cols):
            for r in range(rows): cg[r][c]=next(it)
        variants.append(("colfill_rowread", ''.join(''.join(row) for row in cg)))
        for name,out in variants:
            sc=q(out)
            if sc>=70:
                outs.append({"name":name,"rows":rows,"cols":cols,"score":round(sc,2),"text":out[:3000]})
    if not outs: return []
    outs=sorted(outs,key=lambda x:x["score"],reverse=True)[:40]
    art=v98_text_art(root, report, "v98_route_transposition_candidates.json", json.dumps(outs,ensure_ascii=False,indent=2), "v98_route_transposition", 210, "Bounded route transposition candidates; inspect highest scores first.")
    return [art] if art else []
def v98_parse_classic_pcap(data):
    if len(data)<24: return []
    magic=data[:4]
    if magic==b"\xd4\xc3\xb2\xa1": endian="<"
    elif magic==b"\xa1\xb2\xc3\xd4": endian=">"
    else: return []
    packets=[]; off=24
    try:
        while off+16<=len(data) and len(packets)<20000:
            ts,us,cap,orig=struct.unpack(endian+"IIII", data[off:off+16]); off+=16
            pkt=data[off:off+cap]; off+=cap
            if pkt: packets.append((ts,us,pkt))
    except Exception: pass
    return packets
def v98_pcap_scalar_agent(root, report, data):
    packets=v98_parse_classic_pcap(data)
    if not packets: return []
    fields={k:[] for k in ["ipid","ttl","tos","proto","src_last","dst_last","sport","dport","length","time_delta_ms"]}
    payload=b""; prev=None
    for ts,us,pkt in packets:
        if prev is not None: fields["time_delta_ms"].append(int(((ts-prev[0])*1000)+((us-prev[1])/1000)) & 255)
        prev=(ts,us)
        # raw IP or Ethernet
        ip=pkt[14:] if len(pkt)>=34 and pkt[12:14]==b"\x08\x00" else pkt
        if len(ip)<20 or (ip[0]>>4)!=4: continue
        ihl=(ip[0]&15)*4
        if len(ip)<ihl: continue
        total=struct.unpack("!H", ip[2:4])[0]
        fields["length"].append(total&255); fields["tos"].append(ip[1]); fields["ipid"].append(struct.unpack("!H",ip[4:6])[0]); fields["ttl"].append(ip[8]); fields["proto"].append(ip[9]); fields["src_last"].append(ip[15]); fields["dst_last"].append(ip[19])
        pl=ip[ihl:min(len(ip),total)]
        if ip[9]==17 and len(pl)>=8:
            sp,dp,ln,cs=struct.unpack("!HHHH",pl[:8]); fields["sport"].append(sp); fields["dport"].append(dp); payload+=pl[8:]
        elif ip[9]==6 and len(pl)>=20:
            off=(pl[12]>>4)*4; payload+=pl[off:]
        elif ip[9]==1 and len(pl)>=8:
            payload+=pl[8:]
    hits=[]
    def add(label, vals):
        if not vals: return
        modes={"low8":[x&255 for x in vals],"diff":[(vals[i]-vals[i-1])&255 for i in range(1,len(vals))],"mod95":[(x%95)+32 for x in vals]}
        for mode,arr in modes.items():
            if len(arr)<4: continue
            txt=bytes(arr[:60000]).decode("latin1","ignore")
            low=txt.lower(); score=0
            for k,w in [("ctf_cs{",400),("ctf",120),("flag",90),("cyber",70),("sprint",70),("secret",60),("{",30),("_",8)]: score+=low.count(k)*w
            if score>=80 or any(32<=b<127 for b in arr[:80]):
                if score>=80 or label in ["ttl","ipid","length","time_delta_ms"]:
                    hits.append({"channel":label,"mode":mode,"score":score,"preview":txt[:1000]})
    for k,v in fields.items(): add(k,v)
    if payload:
        try:
            s=payload[:120000].decode("latin1","ignore")
            if any(x in s.lower() for x in ["ctf","flag","secret","cyber","sprint","internal"]): hits.append({"channel":"payload_strings","mode":"latin1","score":150,"preview":s[:3000]})
        except Exception: pass
    if not hits: return []
    art=v98_text_art(root, report, "v98_pcap_scalar_channels.json", json.dumps(hits,ensure_ascii=False,indent=2), "v98_pcap_scalar_channels", 250, "Classic PCAP scalar-channel workbench: IP/TCP/UDP fields, lengths, timing, payload strings.")
    return [art] if art else []
def v98_marker_case_agent(root, report, data):
    # Handles large ASCII blobs where case variants of marker words encode bits.
    if len(data)<1000 or len(data)>8_000_000: return []
    try: txt=data.decode("ascii","ignore")
    except Exception: return []
    marks=re.findall(r"(?i)(ctf|lob)", txt)
    if len(marks)<16: return []
    outs=[]
    for mode in ["word_lob_bit", "uppercase_any", "casebits"]:
        bits=[]
        for w in marks[:5000]:
            if mode=="word_lob_bit": bits.append('1' if w.lower()=="lob" else '0')
            elif mode=="uppercase_any": bits.append('1' if any(c.isupper() for c in w) else '0')
            else: bits.extend('1' if c.isupper() else '0' for c in w)
        for rev in [False, True]:
            b=bits[::-1] if rev else bits
            raw=[]
            for i in range(0,(len(b)//8)*8,8): raw.append(int(''.join(b[i:i+8]),2))
            text=bytes(raw).decode("latin1","ignore")
            sc=sum(text.lower().count(k)*100 for k in ["ctf","flag","cyber","sprint","secret"])
            outs.append({"mode":mode,"reversed":rev,"score":sc,"preview":text[:1200]})
    art=v98_text_art(root, report, "v98_marker_case_decode.json", json.dumps(sorted(outs,key=lambda x:x['score'],reverse=True),indent=2,ensure_ascii=False), "v98_marker_case_decode", 190, "Case variants of marker words such as CTF/LOB decoded as bit streams.")
    return [art] if art else []
_prev_rb_enhance_report_v98 = rb_enhance_report
def rb_enhance_report(root, report, data):
    try: _prev_rb_enhance_report_v98(root, report, data)
    except Exception: pass
    try:
        if report.get("kind") in ["text","generic"] or Path(report.get("path","")).suffix.lower() in [".txt",".log"]:
            v98_route_transposition_agent(root, report, data)
            v98_marker_case_agent(root, report, data)
    except Exception as e:
        try: sl_trace(report,"V98TextPatternError",str(e),0)
        except Exception: pass
    try:
        if Path(report.get("path","")).suffix.lower() in [".pcap",".pcapng"] or data[:4] in [b"\xd4\xc3\xb2\xa1",b"\xa1\xb2\xc3\xd4"]:
            v98_pcap_scalar_agent(root, report, data)
    except Exception as e:
        try: sl_trace(report,"V98PcapPatternError",str(e),0)
        except Exception: pass
    return report
_prev_project_summary_v98 = project_summary
def project_summary(reports, meta):
    summary=_prev_project_summary_v98(reports, meta)
    fam=summary.setdefault("v98_pattern_coverage",{})
    for r in reports:
        for a in r.get("artifacts",[]):
            k=str(a.get("kind") or a.get("source") or "artifact")
            if "v98" in k.lower(): fam[k]=fam.get(k,0)+1
    summary["v98_ux"]={"status_colors":"yellow=running, green=done", "auto_title":"first uploaded filename when title is blank", "pattern_catalog":"V98_PATTERN_CATALOG.md"}
    return summary
import os as _v99_os, re as _v99_re, json as _v99_json, struct as _v99_struct, subprocess as _v99_subprocess, tempfile as _v99_tempfile, zipfile as _v99_zipfile, base64 as _v99_base64, math as _v99_math, shutil as _v99_shutil
from pathlib import Path as _V99Path
V99_VERSION = "v99_workflow_sprint"
def v99_url(path):
    return "/api/raw?path=" + str(path)
def v99_safe_name(x):
    try:
        return safe(str(x))
    except Exception:
        return _v99_re.sub(r"[^A-Za-z0-9_.-]+", "_", str(x or "file"))[:120]
def v99_art(root, report, name, content, kind="v99_artifact", score=220, note="", binary=False, subdir="v99"):
    try:
        outdir = _V99Path(root) / "generated" / "sloper_v99" / subdir / v99_safe_name(report.get("name", "file"))
        outdir.mkdir(parents=True, exist_ok=True)
        path = outdir / v99_safe_name(name)
        if binary:
            path.write_bytes(bytes(content))
        else:
            path.write_text(str(content), encoding="utf-8", errors="ignore")
        art={"kind":kind,"name":path.name,"path":str(path),"url":v99_url(path),"source":"CTF SLOPER v99 Workflow Sprint","score":int(score or 0),"note":note or kind,"exists":True,"size":path.stat().st_size,"file":report.get("rel","")}
        report.setdefault("artifacts",[]).append(art)
        report.setdefault("transformations",[]).append(art)
        try: sl_trace(report,"V99Artifact",f"{kind}: {path.name}",score,str(path))
        except Exception: pass
        return art
    except Exception as e:
        try: sl_trace(report,"V99ArtifactError",f"{name}: {e}",0)
        except Exception: pass
        return None
def v99_flag(body, fmt="ctf_cs"):
    s=str(body or "").strip()
    if not s: return ""
    m=_v99_re.search(r"(?:ctf_cs|gigem|flag)\{[^}\r\n]{2,200}\}", s, _v99_re.I)
    if m: return m.group(0)
    s=s.strip("`'\" \t\r\n")
    if s.startswith("{") and s.endswith("}"): s=s[1:-1]
    if not _v99_re.fullmatch(r"[A-Za-z0-9_+\-=/.:]{3,180}", s):
        return ""
    return f"{fmt}"+"{"+s+"}"
def v99_add_flag(report, flag, source, score=520, why=""):
    flag=v99_flag(flag) if not str(flag).startswith("ctf_cs{") else str(flag)
    if not flag: return None
    rec={"flag":flag,"status":"likely","score":int(score),"source":source,"reasons":[why or source],"negative_reasons":[]}
    vf=report.setdefault("verified_flags",[])
    if not any(v.get("flag")==flag for v in vf): vf.append(rec)
    fs=report.setdefault("flags",[])
    if flag not in fs: fs.append(flag)
    report.setdefault("findings",[]).append({"score":score,"type":"v99_likely_flag","value":flag,"why":why or source})
    try: sl_trace(report,"V99Flag",f"{source}: {flag}",score,flag=flag)
    except Exception: pass
    return rec
def v99_ascii_score(s):
    s=str(s or "")
    if not s: return 0
    printable=sum(32 <= ord(c) < 127 or c in "\r\n\t" for c in s)/max(1,len(s))
    score=int(printable*90)
    score += len(_v99_re.findall(r"[a-zA-Z0-9]{3,}",s))*2
    score += 60 if "_" in s else 0
    score += 120 if _v99_re.search(r"[a-z][0-9][a-z]|[0-9][a-z][0-9]",s) else 0
    score += 200 if _v99_re.search(r"flag|ctf|cyber|sprint|secret",s,_v99_re.I) else 0
    if _v99_re.fullmatch(r"[A-Za-z0-9_+\-]{8,80}",s): score+=80
    return score
def v99_double_table_ascii_agent(root, report, data):
    if not data or len(data) < 96 or len(data) > 80_000_000: return []
    # Mainly for reverse binaries, but harmless over any file.
    hits=[]
    max_windows = min(len(data)-96, 5_000_000)
    step=8
    for off in range(0, max_windows, step):
        try:
            vals=_v99_struct.unpack_from('<12d', data, off)
        except Exception:
            continue
        if any((not _v99_math.isfinite(v)) or abs(v)>1e7 for v in vals):
            continue
        out=[]; ok=0
        for idx,v in enumerate(vals,1):
            n=int(v*idx) & 0xffff
            a=n & 255; b=(n>>8)&255
            if 32 <= a < 127 and 32 <= b < 127:
                out.append(chr(a)+chr(b)); ok+=1
            else:
                out.append('??')
        text=''.join(out)
        if ok>=10:
            sc=v99_ascii_score(text)
            if sc>=260 and _v99_re.search(r"[_0-9]",text):
                hits.append({"offset":off,"text":text,"score":sc,"values":[float(x) for x in vals]})
    hits=sorted(hits,key=lambda x:x["score"],reverse=True)[:10]
    if hits:
        v99_art(root,report,"v99_double_table_ascii.json",_v99_json.dumps(hits,indent=2,ensure_ascii=False),"v99_double_table_ascii",420,"Scans binary double tables; int(coeff[i]*i) read as little-endian ASCII pairs.")
        top=hits[0]
        if top["score"]>=340:
            v99_add_flag(report, top["text"], "v99_double_table_ascii", 610, "Static coefficient table decodes to a leetspeak ASCII phrase.")
    return hits
def v99_xor_dword_array_agent(root, report, data):
    if not data or len(data)<64 or len(data)>60_000_000: return []
    hits=[]
    n=len(data)
    # scan dword arrays whose low byte is populated and upper bytes zero
    for off in range(0, n-32):
        arr=[]
        for j in range(0, min(96, n-off), 4):
            if off+j+4>n: break
            w=data[off+j:off+j+4]
            if w[1:] == b"\x00\x00\x00" and w[0] < 128:
                arr.append(w[0])
            else:
                break
        if len(arr) < 6: continue
        raw=bytes(arr[:80])
        for key in range(1,256):
            dec=bytes([b^key for b in raw])
            try: txt=dec.decode('ascii')
            except Exception: continue
            if not all((32<=ord(c)<127) for c in txt): continue
            sc=v99_ascii_score(txt)
            if '{' in txt and '}' in txt: sc += 260
            if sc>=300:
                hits.append({"offset":off,"key":key,"text":txt,"score":sc,"array_len":len(raw)})
        if len(hits)>60: break
    # also scan plain byte arrays for brace-like XOR payloads
    for off in range(0, max(0,n-10), 1):
        chunk=data[off:off+80]
        if len(chunk)<8: continue
        for key in [0x52,0x23,0x42,0x55,0x13,0x37,0x20,0x7f]:
            dec=bytes([b^key for b in chunk])
            try: txt=dec.decode('ascii','ignore')
            except Exception: continue
            m=_v99_re.search(r"\{[A-Za-z0-9_+\-]{4,80}\}",txt)
            if m:
                hits.append({"offset":off,"key":key,"text":m.group(0),"score":520,"mode":"byte_array"})
    clean=[]; seen=set()
    for h in sorted(hits,key=lambda x:x.get('score',0),reverse=True):
        k=(h.get('text','')[:120],h.get('key'))
        if k in seen: continue
        seen.add(k); clean.append(h)
        if len(clean)>=20: break
    if clean:
        v99_art(root,report,"v99_xor_static_arrays.json",_v99_json.dumps(clean,indent=2,ensure_ascii=False),"v99_xor_static_arrays",390,"Static dword/byte arrays decoded with single-byte XOR keys.")
        top=clean[0]; txt=top.get('text','')
        m=_v99_re.search(r"\{([^}\r\n]{3,120})\}",txt)
        if m:
            v99_add_flag(report, m.group(1), "v99_xor_static_array", 600, "XOR-decoded static array contains a brace token.")
    return clean
