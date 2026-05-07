from pathlib import Path


def test_boot_chain_uses_manifest_not_hand_stitched_imports():
    root = Path(__file__).resolve().parents[1]
    bootstrap = (root / "sloper_v72" / "bootstrap.py").read_text(encoding="utf-8")
    tail = bootstrap[bootstrap.index("def boot():"):]
    assert "apply_runtime_layers" in tail
    assert "hardening_v108" not in tail
    assert "upload_flow_v123" not in tail


def test_compat_layers_use_manifest_not_bootstrap_stitches():
    root = Path(__file__).resolve().parents[1]
    bootstrap = (root / "sloper_v72" / "bootstrap.py").read_text(encoding="utf-8")
    assert "apply_compat_layers" in bootstrap
    assert "install_v100_ctf_player" not in bootstrap
    assert "install_v89_universal" not in bootstrap
    compat = (root / "sloper_v72" / "compat_steps.py").read_text(encoding="utf-8")
    assert "COMPAT_STEPS" in compat


def test_boot_status_hides_internal_version_modules():
    from sloper.runtime import boot

    runtime = boot()
    steps = getattr(runtime, "SLOPER_BOOT_STEPS", [])
    assert steps
    assert all("module" not in step for step in steps)
    assert getattr(runtime, "SLOPER_RUNTIME", "") == "clean"
