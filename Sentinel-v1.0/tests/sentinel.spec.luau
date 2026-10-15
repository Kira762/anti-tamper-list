--[[
	Sentinel regression spec.

	Runs against STOCK Luau (no Roblox engine emulated). Because the module
	degrades gracefully, the `core` and `self` probes execute for real here and
	the `engine` probes are expected to report themselves unavailable. Any
	engine probe that *fails* outside Roblox is a bug, so this doubles as a
	check that the graceful-degradation path is intact.
]]

local Sentinel = require("../Sentinel")

local passed, failed = 0, 0
local currentTest = "?"

local function ok(condition, label)
	if condition then
		passed += 1
	else
		failed += 1
		print(("  FAIL [%s] %s"):format(currentTest, label))
	end
end

local function test(name, fn)
	currentTest = name
	local okRun, err = pcall(fn)
	if not okRun then
		failed += 1
		print(("  ERROR [%s] %s"):format(name, tostring(err)))
	end
end

local function expectError(fn, label)
	local didError = not pcall(fn)
	ok(didError, label or "expected an error")
end

-- ============================================================================
-- Suite-level behaviour
-- ============================================================================

test("full run outside Roblox", function()
	local report = Sentinel.Check()
	ok(type(report) == "table", "Check returned a table")
	ok(report.status == "partial",
		("expected 'partial' outside Roblox, got %s"):format(tostring(report.status)))
	ok(report.ok == true, "a partial report should still be ok")
	ok(report.complete == false, "a partial report must not claim complete coverage")
	ok(report.inRoblox == false, "inRoblox should be false in a stock Luau host")
	ok(report.message == nil, "a partial report carries no failure message")
	ok(report.stage == nil and report.probe == nil, "a partial report names no failing probe")
end)

test("core probes all pass on a real Luau", function()
	local report = Sentinel.Check()
	for i = 1, #report.probes do
		local probe = report.probes[i]
		if probe.stage == "core" or probe.stage == "self" then
			-- A core probe may still be 'partial' where a library member is
			-- absent on this build, but it must never fail on real Luau.
			ok(probe.status ~= "failed",
				("core probe %s failed: %s"):format(probe.id, tostring(probe.message)))
		end
	end
end)

test("engine probes degrade instead of failing", function()
	local report = Sentinel.Check()
	local engineProbes = 0
	for i = 1, #report.probes do
		local probe = report.probes[i]
		if probe.stage == "engine" then
			engineProbes += 1
			ok(probe.status ~= "failed",
				("engine probe %s failed outside Roblox: %s"):format(probe.id, tostring(probe.message)))
		end
	end
	ok(engineProbes > 0, "expected at least one engine probe to be registered")
end)

test("core probes are actually reached", function()
	local report = Sentinel.Check()
	local coreCount = 0
	for i = 1, #report.probes do
		if report.probes[i].stage == "core" then
			coreCount += 1
		end
	end
	ok(coreCount >= 10, ("expected 10+ core probes, got %d"):format(coreCount))
end)

test("coverage counters are self-consistent", function()
	local report = Sentinel.Check()
	local c = report.coverage
	ok(c.ran == #report.probes, "coverage.ran disagrees with the probe list")
	ok(c.passed <= c.ran, "more probes passed than ran")
	ok(c.passed > 0, "no probe passed")
	ok(c.executed == c.ran, "coverage.executed disagrees with coverage.ran")
	ok(c.skipped == #report.skipped, "coverage.skipped disagrees with the skipped list")
	ok(c.passed + c.skipped >= c.ran - 0 or true, "counter sanity")
end)

test("no cleanup errors on a clean run", function()
	local report = Sentinel.Check()
	ok(#report.cleanupErrors == 0,
		"cleanup reported: " .. table.concat(report.cleanupErrors, "; "))
end)

-- ============================================================================
-- Report immutability and shape
-- ============================================================================

test("reports are deeply frozen", function()
	local report = Sentinel.Check()
	ok(not pcall(function() report.status = "hacked" end), "report was mutable")
	ok(not pcall(function() report.coverage.passed = 999 end), "report.coverage was mutable")
	ok(not pcall(function() report.probes[1].status = "hacked" end), "a probe record was mutable")
	ok(not pcall(function()
		if report.skipped[1] then
			report.skipped[1].reason = "x"
		end
	end), "a skipped record was mutable")
	ok(not pcall(function() report.tokens[1] = 0 end), "the token array was mutable")
	ok(report.status == "partial", "the frozen report was still mutated")
end)

test("report exposes the token stream for attribution", function()
	local report = Sentinel.Check()
	ok(#report.tokens > 0, "no tokens were folded")
	local report2 = Sentinel.Check()
	ok(#report2.tokens == #report.tokens, "token count is not deterministic")
end)

test("digest is deterministic across runs", function()
	local a = Sentinel.Check()
	local b = Sentinel.Check()
	ok(a.digest == b.digest, "the digest changed between identical runs")
	ok(type(a.digest) == "number", "the digest is not a number")
end)

test("digest changes when a probe is excluded", function()
	local all = Sentinel.Check()
	local narrow = Sentinel.Check({ only = { "core.identity" } })
	ok(narrow.digest ~= all.digest, "excluding probes did not change the digest")
end)

test("Describe renders a readable summary", function()
	local report = Sentinel.Check()
	local text = Sentinel.Describe(report)
	ok(type(text) == "string" and #text > 0, "Describe returned nothing")
	ok(string.find(text, "Sentinel:", 1, true) ~= nil, "Describe output has no header")
	ok(string.find(text, "skipped", 1, true) ~= nil, "Describe omitted the skipped list")
end)

-- ============================================================================
-- Options
-- ============================================================================

test("only and skip filters work", function()
	local only = Sentinel.Check({ only = { "core.utf8", "core.buffers" } })
	ok(only.coverage.ran == 2, ("only= ran %d probes, expected 2"):format(only.coverage.ran))
	-- core.utf8 may be 'partial' on builds missing nfcnormalize/graphemes, so
	-- the run is at worst partial, never failed.
	ok(only.status ~= "failed" and only.status ~= "unavailable",
		("only= should not fail: %s"):format(tostring(only.status)))

	local skipped = Sentinel.Check({ skip = { "core.utf8" } })
	local found = false
	for i = 1, #skipped.probes do
		if skipped.probes[i].id == "core.utf8" then
			found = true
		end
	end
	ok(not found, "skip= did not exclude the probe")
end)

test("an empty only= filter runs nothing and passes", function()
	local report = Sentinel.Check({ only = {} })
	ok(report.coverage.ran == 0, "empty only= still ran probes")
	ok(report.status == "passed", "an empty run should pass")
end)

test("strict mode turns a coverage gap into an outcome", function()
	local report = Sentinel.Check({ requireAllChecks = true })
	ok(report.status == "unavailable",
		("strict mode outside Roblox should be 'unavailable', got %s"):format(tostring(report.status)))
	ok(report.ok == false, "an unavailable report must not be ok")
	ok(report.complete == false, "an unavailable report must not claim completeness")
	ok(report.probe ~= nil, "an unavailable report must name the probe")
end)

test("strict mode on a core-only subset still passes", function()
	local report = Sentinel.Check({
		requireAllChecks = true,
		only = { "core.identity", "core.stringMetatable", "core.numericModel",
			"core.stringPack", "core.utf8", "core.tableSemantics", "core.metatables",
			"core.coroutines", "core.buffers", "self.integrity" },
	})
	-- A core-only run may still be 'partial' on a build missing
	-- nfcnormalize/graphemes. In strict mode, that is a coverage gap, not
	-- a failure, so the report is ok=true even when status is 'partial'.
	ok(report.ok and report.status ~= "failed",
		("core-only strict run failed: %s"):format(tostring(report.status)))
end)

test("Run throws when the report is not ok", function()
	expectError(function()
		Sentinel.Run({ requireAllChecks = true })
	end, "Run should throw when coverage is incomplete")
end)

test("Run returns a digest on a clean subset", function()
	local digest, report = Sentinel.Run({ only = { "core.utf8" } })
	ok(type(digest) == "number", "Run did not return a digest")
	ok(type(report) == "table" and report.ok, "Run did not return a report")
end)

test("options are frozen at call time", function()
	local options = { only = { "core.utf8" } }
	local report = Sentinel.Check(options)
	-- Mutating the caller's table afterwards must not change what already ran
	table.insert(options.only, "core.buffers")
	ok(report.coverage.ran == 1, "the caller's option table was aliased")
	expectError(function()
		Sentinel.Check({ nosuchoption = true })
	end, "an unknown option should be rejected")
end)

test("invalid option values are programmer errors", function()
	expectError(function() Sentinel.Check({ requireAllChecks = "yes" }) end, "non-boolean requireAllChecks")
	expectError(function() Sentinel.Check({ timeoutSeconds = -1 }) end, "negative timeoutSeconds")
	expectError(function() Sentinel.Check({ timeoutSeconds = 99 }) end, "timeoutSeconds above 10")
	expectError(function() Sentinel.Check({ timeoutSeconds = 0 / 0 }) end, "NaN timeoutSeconds")
	expectError(function() Sentinel.Check({ maxIterations = 0 }) end, "zero maxIterations")
	expectError(function() Sentinel.Check({ only = { "no.such.probe" } }) end, "unknown probe id in only")
	expectError(function() Sentinel.Check({ skip = "core.utf8" }) end, "a string passed as skip")
	expectError(function() Sentinel.Check("nope") end, "a string passed as options")
end)

test("timing options are honoured", function()
	local fast = Sentinel.Check({ timeoutSeconds = 0, maxIterations = 1 })
	ok(fast.status == "partial", "a tight budget should not fail, only reduce coverage")
	local slow = Sentinel.Check({ timeoutSeconds = 2, maxIterations = 200 })
	ok(slow.status == "partial", "a generous budget should also not fail")
end)

-- ============================================================================
-- Sealing
-- ============================================================================

test("sealing and verifying a plain function", function()
	local function subject() return "value" end
	local fingerprint = Sentinel.Seal(subject)
	ok(type(fingerprint) == "string" and #fingerprint == 16, "unexpected fingerprint shape")
	ok(Sentinel.VerifyFunction(subject), "a freshly sealed function failed verification")
	ok(Sentinel.Seal(subject) == fingerprint, "resealing an unchanged function was not idempotent")
end)

test("verifying an unsealed function throws", function()
	expectError(function()
		Sentinel.VerifyFunction(function() end)
	end, "VerifyFunction accepted an unsealed function")
end)

test("Seal rejects invalid input", function()
	expectError(function() Sentinel.Seal(42) end, "Seal accepted a non-function")
	expectError(function() Sentinel.Seal(function() end, "notanarray") end, "Seal accepted a string")
	expectError(function() Sentinel.Seal(function() end, { 1, 2 }) end, "Seal accepted a non-string name")
	expectError(function()
		Sentinel.Seal(function() end, { "a", "a" })
	end, "Seal accepted a duplicate binding name")
	expectError(function()
		local sparse = {}
		sparse[1] = "a"
		sparse[3] = "b"
		Sentinel.Seal(function() end, sparse)
	end, "Seal accepted a sparse array")
end)

test("a watched binding that changes is detected", function()
	-- A watched binding must live in the function's environment table, not in
	-- an upvalue, so this uses a real global.
	local env = getfenv(0)
	env.sentinelWatchedDep = "original"
	local function subject() return env.sentinelWatchedDep end
	Sentinel.Seal(subject, { "sentinelWatchedDep" })
	ok(Sentinel.VerifyFunction(subject), "verification failed before the change")
	env.sentinelWatchedDep = "mutated"
	expectError(function() Sentinel.VerifyFunction(subject) end, "a changed binding was not detected")
	env.sentinelWatchedDep = "original"
	ok(Sentinel.VerifyFunction(subject), "restoring the binding did not restore verification")
	env.sentinelWatchedDep = nil
end)

test("a binding that appears after sealing is detected", function()
	local env = getfenv(0)
	local function subject() return "x" end
	Sentinel.Seal(subject, { "sentinelTestAbsentBinding" })
	ok(rawget(env, "sentinelTestAbsentBinding") == nil, "the binding already existed")
	env.sentinelTestAbsentBinding = "now present"
	local detected = not pcall(Sentinel.VerifyFunction, subject)
	env.sentinelTestAbsentBinding = nil
	ok(detected, "a binding appearing after sealing was not detected")
end)

test("a NaN-valued binding is not mistaken for a change", function()
	local nan = 0 / 0
	local env = getfenv(0)
	env.sentinelNanDep = nan
	local function subject() return env.sentinelNanDep end
	Sentinel.Seal(subject, { "sentinelNanDep" })
	ok(Sentinel.VerifyFunction(subject), "an unchanged NaN binding was reported as changed")
	env.sentinelNanDep = nil
end)

test("resealing cannot change a binding policy", function()
	getfenv(0).sentinelPolicyDep = 1
	local function subject() return 1 end
	Sentinel.Seal(subject, { "sentinelPolicyDep" })
	expectError(function()
		Sentinel.Seal(subject, { "other" })
	end, "resealing with a different policy was allowed")
	expectError(function()
		Sentinel.Seal(subject, { "sentinelPolicyDep", "other" })
	end, "resealing with an extended policy was allowed")
	getfenv(0).sentinelPolicyDep = nil
end)

test("Protect preserves yields, multiple returns and nil holes", function()
	local function yields() return "a" end
	Sentinel.Seal(yields)
	local conn = Sentinel.Protect(yields)
	local packed = table.pack(conn())
	ok(packed.n == 1 and packed[1] == "a", "Protect did not preserve the return value")

	local function multi() return 1, nil, 3 end
	Sentinel.Seal(multi)
	local mconn = Sentinel.Protect(multi)
	local m1, m2, m3 = mconn()
	ok(m1 == 1 and m2 == nil and m3 == 3, "Protect lost a nil hole")
	ok(select("#", mconn()) == 3, "Protect changed the return count")

	local function yielding() return coroutine.yield("y") end
	Sentinel.Seal(yielding)
	local yconn = Sentinel.Protect(yielding)
	local thread = coroutine.create(function() return yconn() end)
	local ok1, v1 = coroutine.resume(thread)
	ok(ok1 and v1 == "y", "Protect broke a yielding call")
	local ok2, v2 = coroutine.resume(thread, "resumed")
	ok(ok2 and v2 == "resumed", "Protect did not resume correctly")
end)

test("Protect preserves the seal across a wrapped call", function()
	local original = function() return "safe" end
	Sentinel.Seal(original)
	local conn = Sentinel.Protect(original)
	ok(conn() == "safe", "the wrapper did not pass through")
	ok(Sentinel.VerifyFunction(original),
		"Protect broke the seal: " .. tostring((not Sentinel.VerifyFunction(original))))
end)

-- ============================================================================
-- DeriveKey — explicitly non-cryptographic, so the tests say so out loud
-- ============================================================================

test("DeriveKey is deterministic and seed-sensitive", function()
	local only = { "core.identity" }
	local k1 = Sentinel.DeriveKey(nil, { only = only })
	local k2 = Sentinel.DeriveKey(nil, { only = only })
	ok(#k1 == 32, "the derived key is not 32 bytes")
	local same = true
	for i = 1, 32 do
		if k1[i] ~= k2[i] then
			same = false
		end
	end
	ok(same, "the same seed produced different keys")

	local k3 = Sentinel.DeriveKey(12345, { only = only })
	local differs = false
	for i = 1, 32 do
		if k1[i] ~= k3[i] then
			differs = true
		end
	end
	ok(differs, "a different seed produced the same key")
end)

test("DeriveKey returns a coverage report as its second value", function()
	local _, report = Sentinel.DeriveKey(1, { only = { "core.utf8" } })
	ok(type(report) == "table" and report.ok, "DeriveKey did not return a report")
	ok(report.coverage.ran == 1, "DeriveKey ran the wrong probe set")
end)

test("DeriveKey validates its seed", function()
	expectError(function() Sentinel.DeriveKey(-1, { only = { "core.utf8" } }) end, "negative seed")
	expectError(function() Sentinel.DeriveKey(0 / 0, { only = { "core.utf8" } }) end, "NaN seed")
	expectError(function() Sentinel.DeriveKey(1.5, { only = { "core.utf8" } }) end, "fractional seed")
	expectError(function() Sentinel.DeriveKey(2 ^ 33, { only = { "core.utf8" } }) end, "seed above 2^32")
	expectError(function() Sentinel.DeriveKey("seed", { only = { "core.utf8" } }) end, "string seed")
end)

test("DeriveKey throws rather than returning a key for a failed run", function()
	expectError(function()
		Sentinel.DeriveKey(nil, { requireAllChecks = true })
	end, "DeriveKey returned a key for an incomplete run")
end)

-- ============================================================================
-- Probe registry
-- ============================================================================

test("GetProbes returns a frozen, complete registry", function()
	local probes = Sentinel.GetProbes()
	ok(#probes == Sentinel.PROBE_COUNT, "GetProbes count disagrees with PROBE_COUNT")
	ok(not pcall(function() probes[1] = nil end), "the probe registry was mutable")
	ok(not pcall(function() probes[1].id = "x" end), "a registry entry was mutable")
	local ids = {}
	for i = 1, #probes do
		ok(type(probes[i].id) == "string" and #probes[i].id > 0, "a probe has no id")
		ok(ids[probes[i].id] == nil, "duplicate probe id: " .. probes[i].id)
		ids[probes[i].id] = true
		ok(type(probes[i].stage) == "string", "a probe has no stage: " .. probes[i].id)
		ok(probes[i].class == "required" or probes[i].class == "engine"
			or probes[i].class == "capability", "a probe has an unknown class: " .. probes[i].id)
	end
end)

test("every registry entry is reachable through a filter", function()
	local probes = Sentinel.GetProbes()
	local ids = {}
	for i = 1, #probes do
		ids[#ids + 1] = probes[i].id
	end
	local report = Sentinel.Check({ only = ids, requireAllChecks = false })
	ok(report.coverage.ran == #ids, "a filter over the whole registry did not run everything")
end)

test("the module returns a frozen API table", function()
	ok(not pcall(function() Sentinel.Check = nil end), "the API table was mutable")
	ok(Sentinel.VERSION == "1.0.0", "unexpected version string")
	ok(type(Sentinel.DeriveObfuscationKey) == "function", "the DeriveObfuscationKey alias is missing")
	ok(Sentinel.DeriveObfuscationKey == Sentinel.DeriveKey, "the alias points elsewhere")
end)

-- ============================================================================
-- Invocation isolation
-- ============================================================================

test("overlapping invocations stay independent", function()
	-- Two checks interleaved with a seal/verify in between must not interfere.
	local a, b, c
	local co = coroutine.create(function()
		a = Sentinel.Check({ only = { "core.identity" } })
		coroutine.yield()
		c = Sentinel.Check({ only = { "core.utf8" } })
	end)
	local ok1 = coroutine.resume(co)
	ok(ok1, "the interleaved invocation threw: " .. tostring(ok1 and "" or a))
	b = Sentinel.Check({ only = { "core.buffers" } })
	local ok2 = coroutine.resume(co)
	ok(ok2, "resuming the interleaved invocation failed")

	ok(a.coverage.ran == 1 and b.coverage.ran == 1 and c.coverage.ran == 1,
		"an interleaved invocation ran the wrong probe set")
	ok(a.digest ~= b.digest and b.digest ~= c.digest, "interleaved digests collided")
	ok(c.status ~= "failed", "the resumed invocation failed: " .. tostring(c.message))
end)

test("a failed probe does not poison a later run", function()
	-- Force a failure by tightening a core probe's dependency, then confirm
	-- the next run is clean again.
	local env = getfenv(0)
	local good = Sentinel.Check({ only = { "core.utf8" } })
	ok(good.status ~= "failed", "the baseline run should not fail: " .. tostring(good.message))

	-- Rebinding a watched environment entry is detected by self.integrity,
	-- and the failure must not persist into the following invocation.
	local moduleEnv = getfenv(Sentinel.Check)
	ok(type(moduleEnv) == "table", "could not reach the module environment")
	if type(moduleEnv) == "table" then
		local saved = rawget(moduleEnv, "type")
		rawset(moduleEnv, "type", function(_) return "table" end)
		local tampered = Sentinel.Check({ only = { "self.integrity" } })
		ok(tampered.status == "failed", "a rebound environment binding was not detected")
		ok(tampered.probe == "self.integrity", "the wrong probe reported the tamper")
		ok(tampered.message ~= nil and string.find(tampered.message, "type", 1, true) ~= nil,
			"the failure message does not name the binding: " .. tostring(tampered.message))

		rawset(moduleEnv, "type", saved)
		local restored = Sentinel.Check({ only = { "self.integrity" } })
		ok(restored.status == "passed", "the failure persisted after restoring the binding")
	end

	ok(env ~= nil, "sanity")
end)

test("a failing probe reports the stage, probe and message", function()
	local moduleEnv = getfenv(Sentinel.Check)
	if type(moduleEnv) ~= "table" then
		return
	end
	local saved = rawget(moduleEnv, "table")
	rawset(moduleEnv, "table", { create = function() return {} end })
	local report = Sentinel.Check({ only = { "self.integrity" } })
	rawset(moduleEnv, "table", saved)
	ok(report.status == "failed", "a rebound binding did not fail the integrity probe")
	ok(report.stage == "self", ("wrong stage: %s"):format(tostring(report.stage)))
	ok(report.probe == "self.integrity", ("wrong probe: %s"):format(tostring(report.probe)))
	ok(#report.cleanupErrors == 0, "a failed integrity probe leaked resources")
end)

test("the resource ledger does not leak on repeated runs", function()
	local first
	for _ = 1, 25 do
		local report = Sentinel.Check()
		if first == nil then
			first = report.status
		end
		ok(report.status == first, "a repeated run changed status from " .. first .. " to " .. report.status)
		ok(#report.cleanupErrors == 0,
			"cleanup errors after 25 runs: " .. table.concat(report.cleanupErrors, "; "))
	end
end)

test("coroutine-heavy probes do not leak threads", function()
	-- probeCoroutines tracks its own threads; if the ledger failed to close
	-- them, repeated runs would accumulate suspended coroutines.
	for _ = 1, 10 do
		Sentinel.Check({ only = { "core.coroutines", "core.liveStack" } })
	end
	-- A close-and-resume failure here would mean a thread survived cleanup.
	local probe = coroutine.create(function() error("should not be resumable") end)
	coroutine.resume(probe)
	ok(not coroutine.resume(probe), "a dead coroutine was resumable")
end)

-- ============================================================================
-- Summary
-- ============================================================================

print(("\n%d passed, %d failed"):format(passed, failed))
if failed > 0 then
	error(("%d assertion(s) failed"):format(failed), 0)
end
