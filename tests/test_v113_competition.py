from pathlib import Path
import base64
import io
import zipfile

from sloper_v72.evidence_v113 import annotate_flag_row, annotate_summary
from sloper_v72.competition_v113 import _case_and_space_channels, _zip_members


def test_v113_decoy_gets_demoted():
    good = annotate_flag_row({"flag": "ctf_cs{real_final_123}", "source": "input->base64->gzip"}, {"flag_format": "ctf_cs"})
    bad = annotate_flag_row({"flag": "ctf_cs{fake_example_ignore_me}", "source": "input"}, {"flag_format": "ctf_cs"})
    assert good["confidence"] > bad["confidence"]
    assert bad["risk"] >= 50
    assert good["verdict"] in {"high", "medium"}


def test_v113_summary_promotes_real_over_fake():
    summary = annotate_summary({"flags": [
        {"flag": "ctf_cs{fake_example_ignore_me}", "source": "input"},
        {"flag": "ctf_cs{real_nested_flag_42}", "source": "input->base64->gzip"},
    ]}, {"flag_format": "ctf_cs"})
    assert summary["flags"][0]["flag"] == "ctf_cs{real_nested_flag_42}"
    assert summary["v113_evidence"]["enabled"] is True


def test_v113_zip_member_extraction():
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("flag.txt", base64.b64encode(b"ctf_cs{zip_unit_01}"))
    members = _zip_members(bio.getvalue())
    assert members and members[0][0] == "flag.txt"
    assert b"ctf_cs" in base64.b64decode(members[0][1])


def test_v113_space_tab_channel_offsets():
    payload = b"ctf_cs{space_unit_02}"
    bits = "".join(f"{b:08b}" for b in payload)
    text = "prefix letters " + "".join("\t" if bit == "1" else " " for bit in bits)
    chans = dict(_case_and_space_channels(text))
    assert any(b"ctf_cs{space_unit_02}" in data for data in chans.values())
