import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sloper_v72.control_plane_v111 import normalize_settings, compile_flag_patterns, preferred_flag


def test_ctf_cm_format_compiles_and_wraps():
    prefs = normalize_settings({"flag_format": "ctf_cm", "flag_prefix": "ctf_cm"})
    pats = compile_flag_patterns(prefs)
    assert any(p.search("ctf_cm{abc_123}") for p in pats)
    assert preferred_flag("ctf_cs{abc_123}", prefs) == "ctf_cm{abc_123}"


def test_custom_regex_plain_token_allowed_by_profile():
    prefs = normalize_settings({"flag_format": "custom_regex", "custom_flag_regex": r"KEY-[A-Z0-9-]+"})
    pats = compile_flag_patterns(prefs)
    assert any(p.search("KEY-BENCH-09") for p in pats)
