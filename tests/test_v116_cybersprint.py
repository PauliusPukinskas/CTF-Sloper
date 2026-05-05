from pathlib import Path
import tempfile

from sloper_v72.competition_v116 import _morse_decode, _rect_transpositions, _carve_zips
from sloper_v72.evidence_v116 import _risk


def test_v116_morse_lithuania_password():
    assert "LIETUVA" in _morse_decode(".-.. .. . - ..- ...- .-")


def test_v116_rectangular_transposition_wraps_realistic_braces():
    s = "teE}GC7BsS{5yd74a=w[7uo79-RE7!o,q({1___hbt[Hp{=@8;4JUOc%PhCM7vl13}bUFeSa,1lN6LyK(-9S$_30n_PO+j,g-[k-q+saze5Tap1ru_l2F;Xwtih)x"
    outs = dict(_rect_transpositions(s))
    joined = "\n".join(outs.values())
    assert "{17_15_v3ry_l0ud_1n_7h3_l4b}" in joined


def test_v116_noise_risk_demotes_short_xor():
    risks = _risk("ctf_cs{aejgda}", "input->xor_08")
    assert "short_lowercase_noise" in risks or "xor_weak" in risks
