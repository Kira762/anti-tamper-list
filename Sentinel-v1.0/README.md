# Sentinel

A Lua/Luau client-integrity suite for Roblox, designed to be honest about
what it can and cannot do.

```
Sentinel v1 — 27 probes — 299 tests passing at -O0/-O1/-O2
```

## What it is

A suite of independent probes that look for *internal inconsistency* in
the client runtime: emulators that stub the engine, executors that
replace library functions, mocks that return plausible values for the
wrong reasons. Each probe states an invariant the real engine holds and
fails only when that invariant is violated.

The suite is split into three stages, with different trust guarantees:

- **core** — pure-Luau invariants (string metatable lock, buffer
  IEEE-754 aliasing, `string.pack` round-trips, utf8 codepoint
  encoding, `table.move` overlapping semantics, the non-yieldable
  C-call boundary, and so on). These run identically on every Luau
  build, including stock CLI, so they can be regression-tested in CI
  without a Roblox engine.
- **engine** — Roblox-specific surface (CFrame algebra, WorldModel
  raycast, TweenService completion, Heartbeat frame cadence, GetPropertyChangedSignal
  identity, EditableMesh, …). Outside Roblox, these report
  `unavailable` rather than failing, so the same file runs end-to-end
  in CI.
- **self** — the module's own environment, captured at load. The
  module's first line of defence is that it captured its library
  references before anything else ran; this stage checks the other
  half of that contract.

## What it is not

- **Not a trust boundary.** Everything here runs on an
  attacker-controlled client. A determined attacker can patch the
  probe, stub the probe's own dependencies, or replace this module
  wholesale. The goal is *evidence*, not enforcement.
- **Not cryptography.** The `digest` and `DeriveKey` outputs contain
  no secret entropy, are not a KDF or a MAC, and must never protect a
  secret or authorise an action. They are change detectors for *this
  build of this module*: a divergence tells you a probe ran a
  different code path; it does not commit anyone to anything.
- **Not a ban signal.** A failed probe is *evidence to collect*, not
  proof of cheating. Legitimate clients fail probes constantly: low
  memory, restricted permissions, server-side execution, Studio,
  outdated engine versions, accessibility tooling. The matching
  `Policy.lua` exists to make that explicit and to keep the
  irreversible action (ban) out of the module.

## Install

Copy `Sentinel.lua` (and optionally `Policy.lua` and `examples/`) into
your Roblox game. The cleanest layout:

```
src/
  Sentinel.lua          -- the module (ModuleScript)
  Policy.lua            -- the server-side decision policy (ModuleScript)
  Server/
    Intake.server.lua   -- listens for client reports
server/
  Storage/
    AntiTamperStorage.lua   -- the module under ReplicatedStorage
  Storage/
    AntiTamperPolicy.lua    -- the policy under ServerStorage
client/
  LocalScript.client.lua
```

`Sentinel.lua` runs its `self.integrity` probe on load and exposes a
frozen `Sentinel` table from the ModuleScript's return value. Require
it from a LocalScript and call `Sentinel.Run()` at sensible checkpoints:

```lua
-- client/LocalScript.client.lua
local Sentinel = require(ReplicatedStorage.Sentinel)
local function checkpoint(label)
    local ok, err = pcall(function()
        local digest, report = Sentinel.Run()
        -- Send to the server. Do NOT trust the digest server-side.
        IntakeRemote:FireServer({
            label = label,
            report = report,
        })
    end)
    if not ok then
        -- The run itself raised: the client is in a state we don't trust.
        -- Forwarding the error is more useful than silently retrying.
        warn("Sentinel checkpoint failed:", err)
    end
end

-- initial check
checkpoint("startup")

-- periodic re-check on Heartbeat, but at most once per few seconds
local last = 0
RunService.Heartbeat:Connect(function()
    if os.clock() - last < 5 then return end
    last = os.clock()
    checkpoint("periodic")
end)
```

The `Sentinel` table is the entire API. The notable members:

| Member | Purpose |
|---|---|
| `Sentinel.Run(options)` | Run the suite. Throws on `failed` or `unavailable`; returns `(digest, report)`. |
| `Sentinel.Check(options)` | Same as `Run`, but never throws on a probe outcome — only on programmer errors. |
| `Sentinel.Describe(report?)` | One-paragraph human summary, for `warn` calls. |
| `Sentinel.GetProbes()` | The registered probe registry, frozen. Use it to build `only`/`skip` filters. |
| `Sentinel.Seal(fn, bindingNames?)` | Record a function's metadata + environment. |
| `Sentinel.VerifyFunction(fn)` | Throw if a sealed function changed. |
| `Sentinel.Protect(fn, bindingNames?)` | Wrap a function with a per-call verify-before-and-after. |
| `Sentinel.DeriveKey(seed, options)` | **Not cryptographic.** Deterministic bytes for a public seed. |

Options are validated per call and frozen at call time, so a caller
mutating their table mid-run cannot influence an in-flight run.

## Server side

`Policy.lua` is the half the upstream codebases don't ship. It exists
because the worst outcome of anti-tamper code is an overconfident
server, and the easiest way to make a server overconfident is to
auto-ban on a single failed probe. The policy:

1. **Aggregates samples over a window.** A single failure is recorded
   and surfaced as `observe`; the policy does not act on a single
   sample of anything.
2. **Distinguishes contradictions from failures.** A failing probe in
   `core.identity` or `self.integrity` is a different class of evidence
   from a failing probe in `engine.worldModel`: the first means the
   client contradicts itself about its own state; the second means the
   client does not have a raycast target.
3. **Makes ban the path you reach for, not the default.** The default
   recommendation for a player with no evidence is `ignore`. The
   default for one failed sample is `observe`. Kick needs
   corroboration. Ban needs either a sustained contradiction or
   several independent probes failing the same way.

```lua
-- server/Intake.server.lua
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Policy = require(ServerStorage.AntiTamperPolicy)
local Intake = ReplicatedStorage.IntakeRemote

local policy = Policy.new({
    -- tune to your game. defaults are sensible but conservative.
    evidenceLifetime = 60,
    minSamplesForAction = 3,
})

Intake.OnServerEvent:Connect(function(player, payload)
    -- validate before trusting any field
    if type(payload) ~= "table" then return end
    policy:update(player, payload.report, os.clock())
end)

-- periodically age out and check
while true do
    local now = os.clock()
    for _, player in ipairs(Players:GetPlayers()) do
        local rec = policy:recommend(player, now)
        if rec.action == "ban" then
            -- irreversible: log and notify
            warn(("sentinel ban: %s reason=%s"):format(player.Name, rec.reason))
            player:Kick("Forensic evidence has been retained. See support.")
            -- your game has its own ban system; this is the trigger.
        elseif rec.action == "kick" then
            warn(("sentinel kick: %s reason=%s"):format(player.Name, rec.reason))
            player:Kick()
        elseif rec.action == "observe" then
            -- rate-limit, reduce spawn priority, flag for staff review
        end
    end
    policy:tick(now)
    task.wait(5)
end
```

The policy's outputs are *recommendations*, not actions. You can
ignore them; you can tighten the thresholds; you can rewrite the
recommend function entirely. The non-negotiable point is that the
client should never be the entity deciding its own trust level.

## Running the test suite

```
$ python3 tests/run.py --build-luau
```

This downloads and builds a pinned stock Luau 0.742, compiles the
module, and runs `tests/sentinel.spec.luau` at O0, O1 and O2. The
core and self probes execute for real against the host; the engine
probes report themselves unavailable. A 299-assertion suite covers:

- Every probe runs and reports correctly under both Roblox and
  stock Luau.
- A failed probe does not poison a later invocation.
- The resource ledger is empty after every run, including repeated
  runs and runs that throw.
- The report is deeply frozen, including every nested record.
- The digest is deterministic across runs and changes when probes
  are excluded.
- `Seal` and `Protect` detect replacement; `Protect` preserves
  yields, multiple return values and nil holes.
- The integrity probe detects a binding appearing in the module's
  environment after load, and verifies the failure does not persist
  once the binding is removed.
- Option validation is exhaustive: bad filters, bad timeouts, bad
  seeds, bad binding names all fail loudly.
- Two overlapping invocations in different coroutines stay
  independent.

The test harness does not substitute any probe bodies and there is no
test-injection switch in the module. The same file you ship is the
file the test suite runs.

## Coverage

```
27 probes, 11 core / 13 engine / 1 executors / 1 self / 1 capabilities gate
```

The full probe list is `Sentinel.GetProbes()`. Each entry has an `id`
(used in filters), a `stage` (for the report's stage label), and a
`class` (`required`, `engine`, or `capability`).

Notable probes the upstream anti-tamper patterns do not cover, that
Sentinel does:

- `string.pack`/`unpack`/`packsize` binary round-trip with
  little-endian, big-endian, signed and unsigned widths.
- `utf8` library — codepoint encoding, astral planes, invalid
  sequence rejection, `utf8.charpattern` interop with `gmatch`.
- `table.move` overlapping-copy semantics (memmove, not memcpy).
- `string.split` round-trip and empty-separator behaviour.
- `math.clamp`/`lerp`/`isnan`/`isinf`/`isfinite` (where present).
- `coroutine.finally` and `coroutine.isyieldable` (where present).
- `GetPropertyChangedSignal` identity and the "same value does not
  fire" rule.
- `NumberSequence:Evaluate` at and between keypoints.
- `ColorSequence` linear interpolation.
- `TweenService` tween-completion with the actual target value.
- `Heartbeat` frame cadence against a deadline.
- `CFrame:Lerp`, `CFrame.fromEulerAnglesXYZ` round-trip, `Ray:IntersectSegment`.
- `EditSetAttribute` mutation that doesn't disturb other instances.

The integrity probe (`self.integrity`) is a new category of check: the
module's own environment table, captured at load, watched for
identity changes.

## Limitations

- Server-side execution. Several engine probes are gated on `isClient`;
  the suite degrades gracefully on the server but reports partial
  coverage.
- Custom executor environments. A legitimate environment that happens
  to expose a function called `iscclosure` is not a verdict on its
  own. The policy requires corroboration.
- Studio. Studio is a developer environment, not a cheater's; the
  suite is configurable to allow Studio via `allowStudio = true`
  (default).
- Engine version drift. A Luau build that lacks `math.type` is still
  supported; the probe degrades to a few universally-valid
  invariants. A Luau build that *changes* the semantics of `string.pack`
  would require a Sentinel update.
- The scriptable attacker. As stated: a hostile client can always
  replace this module. The design is to gather *evidence the server
  can act on*, not to make a hostile client trust itself.

## License

The upstream repositories this was inspired by are license-ambiguous.
Sentinel is offered under MIT. If you find a probe that originated in
a leaked obfuscator's internal code and you are the author, please
open an issue and the probe will be removed or replaced with an
equivalent one derived from public Luau documentation.

```
MIT License

Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the above copyright notice and this
permission notice appearing in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
```
