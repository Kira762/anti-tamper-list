# v3.1 regression tests

Requires Python 3 and stock **Luau 0.742** (`luau` and `luau-compile`). With the
executables on PATH, run from the repository root:

```sh
python3 tests/run.py
```

Or specify their locations:

```sh
python3 tests/run.py --luau /path/to/luau --compile /path/to/luau-compile
```

Add `--optimization 0`, `--optimization 1` (default), or `--optimization 2` to
select Luau's compiler optimization level. The GitHub Actions workflow builds
that pinned version from source and tests all three levels. No third-party Python packages are needed. Generated test files live
in an automatically removed temporary directory, not in the repository.

## What the CLI tests verify

- Syntax of all three `BestAntiTamper` scripts and clean rejection of the
  unsupported standalone runtime by the unmodified production module.
- Real Luau buffer/language checks and the native C-stack/yield-boundary probes.
- The actual v3.1 runner and public APIs, including interleaved `Run`/`DeriveKey`,
  per-run failures, immutable options/reports, and compatible deterministic bytes.
- Cleanup after normal execution, unexpected exceptions, strict unavailability,
  and swallowed assertion failures; bounded waiting and invalid caller arguments.
- Function environment replacement, optional watched bindings (including NaN),
  raw binding-list validation, reseal restrictions,
  and preservation of yields/multiple return values/nil holes.
- EditableMesh, WorldModel, and Path2D helper control flow against small fixtures:
  nil allocation, mutation errors, missing positive ray hits, absent PlayerGui,
  layout readiness, geometric inconsistencies, and resource disposal.

`run.py` substitutes only Roblox-dependent stage bodies in a **temporary copy**
while retaining the production runner/helpers/API. The original Path2D and native
stack probe bodies are also tested separately. Mesh fixture methods cannot have
native C metadata; only those focused fixture tests replace the metadata checker.
The real metadata checker is tested against stock Luau functions. There are no
production switches to bypass checks or inject test implementations.

These are **not** Roblox end-to-end tests and do not establish that an engine
version, graphics implementation, or executor is compatible.

## Required Roblox integration checks before deployment

1. Put `BestAntiTamper/3.lua` in a ModuleScript named `AntiTamper`, accessible to a
   LocalScript. Require it after the local player's PlayerGui exists. Startup runs
   the suite; report any thrown error with its stage. Inspect `InitialReport`.
2. Call `Check()` in Studio Play and a published test experience. Inspect **every**
   `skipped` entry. Confirm a known-good client does not report `failed`.
3. Repeat with both Immediate and Deferred signal behavior. Run two concurrent
   calls to `Run()` and two to `DeriveKey(seed)`; compare digests/keys to sequential
   runs. Confirm no probe GUIs, parts, meshes, or connections remain afterward.
4. Verify the real WorldModel fixture returns the required positive hit and miss.
   Test Path2D length, midpoint, and scale ratio on the current client, including
   different resolutions/UI scales. Fixtures in CLI cannot establish these facts.
5. Test with EditableMesh permissions enabled/disabled, available/exhausted editable
   memory, and restricted service access. Default mode should return `partial`
   where unavailable; strict mode should return `unavailable`, not accuse tampering.
   Test resource pressure only in an isolated development experience.
6. Confirm `Check({allowStudio = false})` explicitly rejects Studio. On server-side
   execution, expect UI-dependent probes to be unavailable rather than complete.
7. Test each supported engine/platform/execution context and repeat after Roblox
   updates. Include error/timeout cleanup and a respawn during checks. Do not cancel
   suspended check coroutines externally; cancellation cannot guarantee cleanup.

No live Roblox integration run is performed by the CLI workflow.
