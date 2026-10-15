#!/usr/bin/env python3
"""Run v3.1 unit regressions with stock Luau; no Roblox engine is emulated.

Only Roblox-dependent stage bodies are substituted in a TEMPORARY test copy.
The real state runner, resource helpers, buffers/language checks, public API,
WorldModel/EditableMesh/Path2D helpers, and native stack probes are exercised.
There are no bypass flags or test injection points in the production module.
"""
import argparse
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def function_span(source, name):
    pattern = rf"^local function {re.escape(name)}\(ctx\)\n.*?^end$"
    match = re.search(pattern, source, re.DOTALL | re.MULTILINE)
    if match is None:
        raise RuntimeError(f"Cannot find top-level function: {name}")
    return match


def instrument(source):
    # Keep the actual C-stack/yield probes; only remove Roblox-specific targets.
    native = function_span(source, "checkStage8_AntiHookAndStackOracles").group()
    native = native[:native.index("    -- Legacy scheduler globals check")]
    native = re.sub(
        r"^        \{ (?:task0\.|Instance0\.|UDim20\.|Random0\.|game0\.).*\n",
        "", native, flags=re.MULTILINE,
    )
    native = native.replace("checkStage8_AntiHookAndStackOracles", "checkNativeStackProbes", 1)
    native += "end\n"
    replacements = {
        "checkStage1_RuntimeAndSandbox": ("runtime", [0x4C756175]),
        "checkStage3_RandomAndManifold": ("random", [763, 397, 847]),
        "checkStage5_GeometryAndPhysicsSync": ("geometry", [39, 1]),
        "checkStage6_ReflectionAndSignals": ("signals", [17]),
        "checkStage7_HttpServiceInvariants": ("http", [4]),
        "checkStage8_AntiHookAndStackOracles": ("closures", [5]),
        "checkStage9_Path2DAndDynamicScaling": ("path2d", [86]),
    }
    path_probe = function_span(source, "checkStage9_Path2DAndDynamicScaling").group()
    path_probe = path_probe.replace("checkStage9_Path2DAndDynamicScaling", "checkRealPathProbe", 1)
    for name, (stage, tokens) in replacements.items():
        match = function_span(source, name)
        body = f'local function {name}(ctx)\n    if testHooks.{stage} then testHooks.{stage}(ctx) end\n'
        body += "".join(f"    feedState(ctx, {token})\n" for token in tokens)
        body += "end"
        source = source[:match.start()] + body + source[match.end():]
    # The Path2D helper itself feeds its token. Tests invoke it separately from
    # the orchestration stub, or compensate explicitly when routing through it.
    source = source.replace(
        "-- Function identity, metadata, and environment/binding guards.",
        native + "\n" + path_probe + "\n\n-- Function identity, metadata, and environment/binding guards.",
        1,
    )
    source = "local testHooks = {}\n" + source
    tests = (ROOT / "tests" / "runtime.spec.luau").read_text()
    assert source.count("return tFreeze(AntiTamper)") == 1
    return source.replace("return tFreeze(AntiTamper)", "tFreeze(AntiTamper)\n" + tests)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--luau", default=shutil.which("luau"))
    parser.add_argument("--compile", dest="compiler", default=shutil.which("luau-compile"))
    parser.add_argument("--optimization", type=int, choices=(0, 1, 2), default=1)
    args = parser.parse_args()
    optimization = f"-O{args.optimization}"
    if not args.luau or not args.compiler:
        parser.error("Provide --luau and --compile, or put both Luau executables on PATH")
    subprocess.run(
        [args.compiler, optimization, "--null", *[str(ROOT / "BestAntiTamper" / f"{n}.lua") for n in (1, 2, 3)]],
        check=True, timeout=30,
    )
    # Unmodified production code must reject stock CLI cleanly, not hang or
    # fail during module construction before a useful stage diagnostic exists.
    unsupported = subprocess.run(
        [args.luau, optimization, str(ROOT / "BestAntiTamper" / "3.lua")],
        capture_output=True, text=True, timeout=10,
    )
    diagnostic = unsupported.stdout + unsupported.stderr
    if unsupported.returncode == 0 or "Runtime check failed [runtime]" not in diagnostic:
        raise RuntimeError("Unexpected standalone-runtime outcome:\n" + diagnostic)
    print("PASS unmodified module rejects unsupported standalone runtime", flush=True)
    source = (ROOT / "BestAntiTamper" / "3.lua").read_text()
    with tempfile.TemporaryDirectory(prefix="anti-tamper-tests-") as temp:
        path = Path(temp) / "runtime-tests.luau"
        path.write_text(instrument(source))
        subprocess.run([args.luau, optimization, str(path)], check=True, timeout=30)


if __name__ == "__main__":
    main()
