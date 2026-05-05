import base64
import io
import sqlite3
import wave
import zipfile
import zlib
from pathlib import Path

from sloper_v72.competition_v114 import (
    _office_texts_from_zip,
    _sqlite_texts,
    _png_chunks,
    _wav_lsb_channels,
    _payload_frontier,
    _xor_candidates,
)
from sloper_v72.evidence_v114 import enrich_summary


def test_v114_office_docx_text_normalization():
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("word/document.xml", "<w:document><w:t>ctf_cs{docx_xml_text_21}</w:t></w:document>")
    texts = _office_texts_from_zip(bio.getvalue())
    assert any("ctf_cs{docx_xml_text_21}" in text for _, text in texts)


def test_v114_sqlite_text_extraction(tmp_path: Path):
    db = tmp_path / "chal.db"
    con = sqlite3.connect(db)
    con.execute("create table notes(id integer, body text)")
    con.execute("insert into notes values(1, 'final ctf_cs{sqlite_table_22}')")
    con.commit(); con.close()
    texts = _sqlite_texts(db)
    assert any("ctf_cs{sqlite_table_22}" in text for _, text in texts)


def test_v114_png_ztxt_chunk_extraction():
    def chunk(t: bytes, data: bytes) -> bytes:
        import struct, zlib
        body = t + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xffffffff)
    raw = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00")
    raw += chunk(b"zTXt", b"Comment\x00\x00" + zlib.compress(b"ctf_cs{png_ztxt_23}")) + chunk(b"IEND", b"")
    chunks = _png_chunks(raw)
    assert any(b"ctf_cs{png_ztxt_23}" in data for _, data, _ in chunks)


def test_v114_wav_lsb_channel(tmp_path: Path):
    payload = b"ctf_cs{wav_lsb_24}\x00"
    bits = [int(bit) for byte in payload for bit in f"{byte:08b}"]
    frames = bytearray()
    for bit in bits:
        frames.append((100 & 0xFE) | bit)
    wavp = tmp_path / "hidden.wav"
    with wave.open(str(wavp), "wb") as wf:
        wf.setnchannels(1); wf.setsampwidth(1); wf.setframerate(8000); wf.writeframes(bytes(frames))
    chans = _wav_lsb_channels(wavp)
    assert any(b"ctf_cs{wav_lsb_24}" in data for _, data in chans)


def test_v114_payload_frontier_xor_and_nested_gzip_base64():
    inner = base64.b64encode(zlib.compress(b"ctf_cs{frontier_nested_25}"))
    rows, manifest, payloads = _payload_frontier(inner, {"flag_format": "ctf_cs", "max_depth": 5, "max_artifacts": 800}, "case.bin")
    assert any(r.get("flag") == "ctf_cs{frontier_nested_25}" for r in rows)
    assert manifest


def test_v114_xor_candidate_keeps_flagish_output():
    raw = bytes(b ^ 0x42 for b in b"ctf_cs{xor_rescue_26}")
    outs = _xor_candidates(raw)
    assert any(b"ctf_cs{xor_rescue_26}" in data for _, data in outs)


def test_v114_summary_triage_best_flag():
    summary = enrich_summary({"flags": [
        {"flag": "ctf_cs{fake_example_ignore_me}", "source": "input"},
        {"flag": "ctf_cs{real_v114_best_27}", "source": "input->zip->base64->gzip"},
    ], "artifacts": [{"kind": "png_chunk"}, {"kind": "png_chunk"}]}, {"flag_format": "ctf_cs"})
    assert summary["v114_triage"]["best_flag"] == "ctf_cs{real_v114_best_27}"
    assert summary["v114_triage"]["artifact_kinds"]["png_chunk"] == 2
