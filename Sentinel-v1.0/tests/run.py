#!/usr/bin/env python3
"""
Run Sentinel v1 regressions against stock Luau. No Roblox engine is emulated.

Sentinel degrades gracefully outside Roblox: `core` and `self` probes execute
for real against the host Luau, and `engine` probes are expected to report
themselves `unavailable`. The same file is the production module that ships
into Roblox. There are no test-only switches, no substitution copies, and no
bypass flags.
"""
import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LUAU_VERSION = "0.742"


def find_luau(args):
	if args.luau:
		return args.luau
	found = shutil.which("luau")
	if found:
		return found
	sys.exit("Provide --luau or put the `luau` executable on PATH")


def find_compiler(args):
	if args.compiler:
		return args.compiler
	found = shutil.which("luau-compile")
	if found:
		return found
	sys.exit("Provide --compile or put `luau-compile` on PATH")


def build_luau(target_dir):
	"""Download and build a pinned stock Luau if none was provided."""
	import tarfile
	import tempfile
	import urllib.request

	tarball = target_dir / f"luau-{LUAU_VERSION}.tar.gz"
	if not tarball.exists():
		url = f"https://codeload.github.com/luau-lang/luau/tar.gz/refs/tags/{LUAU_VERSION}"
		print(f"Fetching {url}")
		with urllib.request.urlopen(url, timeout=30) as r, open(tarball, "wb") as out:
			out.write(r.read())
	with tarfile.open(tarball) as tar:
		tar.extractall(target_dir)
	src = target_dir / f"luau-{LUAU_VERSION}"
	if not (src / "luau").exists():
		print(f"Building Luau {LUAU_VERSION} (this takes a couple of minutes the first time)")
		subprocess.run(
			["make", f"-j{__import__('os').cpu_count() or 2}",
				"config=release", "luau", "luau-compile"],
			cwd=src, check=True,
		)
	return src / "luau", src / "luau-compile"


def main():
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("--luau", help="path to a `luau` executable")
	parser.add_argument("--compile", dest="compiler", help="path to a `luau-compile` executable")
	parser.add_argument("--optimization", type=int, choices=(0, 1, 2), default=None,
		help="compile optimization level; runs all three if omitted")
	parser.add_argument("--build-luau", action="store_true",
		help="download and build a pinned stock Luau in the current directory if needed")
	args = parser.parse_args()

	luau = args.luau or find_luau(args)
	compiler = args.compiler or find_compiler(args)

	if args.build_luau and (not luau or not compiler):
		with_built_luau, with_built_compile = build_luau(Path.cwd())
		luau = luau or str(with_built_luau)
		compiler = compiler or str(with_built_compile)

	optimizations = [args.optimization] if args.optimization is not None else [0, 1, 2]
	failures = []
	for o in optimizations:
		optim = f"-O{o}"
		print(f"\n=== Luau @ {o} ===")
		# Compile the module at the requested optimization level to catch
		# syntax/bytecode errors that only appear at certain flags.
		print(f"compiling Sentinel.lua {optim} ...", end=" ", flush=True)
		res = subprocess.run(
			[compiler, optim, "--null", str(ROOT / "Sentinel.lua")],
			capture_output=True, text=True, timeout=30,
		)
		if res.returncode != 0:
			sys.exit(f"FAILED\n{res.stdout}{res.stderr}")
		print("ok")

		# Run the spec.
		print(f"running tests/sentinel.spec.luau {optim} ...", end=" ", flush=True)
		res = subprocess.run(
			[luau, optim, str(ROOT / "tests" / "sentinel.spec.luau")],
			capture_output=True, text=True, timeout=60,
		)
		output = res.stdout + res.stderr
		if res.returncode != 0:
			print(f"FAILED\n{output}")
			failures.append((o, output))
		else:
			# The spec prints a one-line summary; surface it.
			print(output.strip().splitlines()[-1] if output.strip() else "ok")

	if failures:
		print("\nFAILURES:")
		for o, out in failures:
			print(f"--- O{o} ---")
			print(out)
		sys.exit(1)
	print("\nAll optimization levels passed.")


if __name__ == "__main__":
	main()
