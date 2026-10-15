# Runtime checks

- `1.lua`: executor-specific Drawing object lifecycle check (unchanged).
- `2.lua`: older environment/service/EditableMesh checks (unchanged; includes infinite-loop failure paths).
- `3.lua`: v3.1 nine-stage runtime consistency suite with isolated per-call state,
  cleanup, bounded scheduler waits, explicit coverage reports, and function guards.

These checks can expose incomplete runtime emulations or some replaced functions.
**They cannot establish trust in an attacker-controlled client, prevent every hook,
or protect secrets delivered to that client.** Keep authoritative game decisions
and secrets on the server. A failed probe is diagnostic evidence, not sufficient
reason to ban a player.

## Using `3.lua`

Keep it as a standalone chunk in your obfuscator, or install it as a ModuleScript
named `AntiTamper`. It still validates on load and returns a frozen API table.
Startup failures raise an error naming the stage; partial coverage is returned in
`InitialReport` and produces a warning. The other scripts have not been hardened.

```lua
local AntiTamper = require(pathToAntiTamperModule)

local report = AntiTamper.Check() -- may yield; probe failures are returned
print(report.status, report.complete)
for _, skipped in ipairs(report.skipped) do
    warn(skipped.stage, skipped.check, skipped.reason)
end

-- Like v3: throws on failure and returns the successful digest first.
-- The second return now explains coverage; the digest alone does NOT prove it.
local digest, details = AntiTamper.Run()

-- Reject unavailable probes as well as inconsistent ones:
local strictReport = AntiTamper.Check({ requireAllChecks = true })
if not strictReport.ok then
    warn(strictReport.status, strictReport.stage, strictReport.message)
end
```

### Options

| Option | Default | Meaning |
| --- | --- | --- |
| `requireAllChecks` | `false` | Stop with `unavailable` rather than accept partial coverage when a probe lacks resources/capabilities. |
| `allowStudio` | `true` | Studio is not itself tampering. Set `false` to explicitly reject it. |
| `timeoutSeconds` | `1` | Scheduler/layout wait budget per wait, from 0 to 10 seconds; also capped at 120 resumptions. |

Options are copied before execution. Changing the caller's options while a run
is suspended cannot change its policy. `Check`, `Run`, and `DeriveKey` can overlap;
each invocation owns its accumulator, failure state, diagnostics, and cleanup stack.
A failed invocation does not permanently poison subsequent invocations.

### Reports and availability

Reports and their diagnostic arrays/records are frozen.

| `status` | `ok` | `complete` | Meaning |
| --- | --- | --- | --- |
| `passed` | `true` | `true` | All applicable probes completed. |
| `partial` | `true` | `false` | Required invariants passed; one or more capability/resource-dependent probes were skipped. |
| `failed` | `false` | `false` | An invariant, API call, or cleanup failed. Inspect `stage`, `message`, and `cleanupErrors`. |
| `unavailable` | `false` | `false` | Strict mode could not complete a capability/resource-dependent probe. This is **not** a tampering verdict. |

A report also contains `stages`, `skipped`, and (only for a successful run) `digest`.
`Run` and key derivation throw for `failed`/`unavailable`; `Check` returns the report.
Invalid options/seeds/binding lists are programmer errors and still throw.

By default these conditions produce partial coverage instead of false detections:

- EditableMesh creation returns `nil` (its documented editable-memory budget limit),
  is unavailable, or raises a permission/resource error.
- Restricted service methods or `CorePackages` cannot be accessed.
- A local `PlayerGui`, GUI layout, or Path2D support is unavailable.
- Signal callbacks cannot be observed within the bounded wait.

Use `requireAllChecks = true` where complete coverage is required. A restricted or
server context may consequently be unable to pass strict mode. Missing executor
extensions such as Drawing are not treated as a failure: those extension probes
are only applicable when the relevant API is present. `complete` refers to the
suite's **applicable probes**, not to proof of an unmodified environment.

An available WorldModel fixture must actually hit its known test part; two `nil`
raycast results no longer pass. WorldModels live under a ViewportFrame in PlayerGui,
and Path2D uses laid-out frames there rather than StarterGui templates. Path2D
checks linear geometry and scaling rather than release-729 floating-point fixtures.
JSON tests use semantic round-trips instead of exact implementation-specific text.
Temporary instances, meshes, connections, and probe coroutines are cleaned up at
each stage boundary, including failure paths. Do not externally cancel a check's
coroutine while it is suspended: Luau cancellation does not run a `finally` block.

## Function guards

```lua
local protected = AntiTamper.Protect(myFunction)

-- Optionally watch named global/environment bindings by identity/value:
local protectedWithBindings = AntiTamper.Protect(otherFunction, { "dependency" })

local fingerprint = AntiTamper.Seal(thirdFunction)
AntiTamper.VerifyFunction(thirdFunction) -- true, or an error
```

A seal records function identity/metadata **and environment-table identity**.
Optional binding names must be a dense array of distinct strings. Replacement of
a watched binding is detected, including a previously absent binding becoming
present. NaN-valued bindings are compared as NaN rather than falsely reporting a
change because NaN is unequal to itself. Resealing verifies the old seal; it cannot silently accept changes or
weaken an existing binding policy. `Protect` verifies before and after a call and
preserves yields, multiple returns, and nil holes.

This does **not** hash executable code or snapshot mutable upvalues/nested tables.
An in-place hook retaining the observed metadata, a changed captured value, or a
mutation inside a watched table can still be invisible. Unwatched environment
bindings are not checked. Baselines assume initialization in a trusted environment.

## Obfuscation keys, not cryptography

`DeriveKey(seed?, options?)` is retained for compatibility;
`DeriveObfuscationKey` is a clearer alias. Both return a 32-byte array followed by
the coverage report. Seeds must be unsigned 32-bit integers; the default remains
`0xA5A5A5A5`. Successful runs preserve the legacy digest `0xEAECA79E` and key bytes
for the same valid seed, including partial runs. Each derivation reruns the suite.

The state tokens and default seed are public constants. The 32-byte output has no
secret entropy supplied by the probes, and the mixing is not a cryptographic KDF
or MAC. Do not use it for authentication, client attestation, or confidential data.
Run the suite at controlled checkpoints, not on every render frame or string lookup.

## Testing and compatibility

See [`../tests/README.md`](../tests/README.md) for stock-Luau regression commands and
a Roblox integration checklist. CLI fixtures verify control flow, not Roblox engine
semantics. The suite still inspects engine-specific behavior (including seeded
Random results and C-function metadata); validate your target engine version and
execution context before deployment. No zero-false-positive guarantee is made.

-- Join KVms Best Free Env Logger & Deobf : https://discord.gg/X4MdbwjBFw
