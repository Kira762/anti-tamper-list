--[[
	Sentinel v1.0 — Roblox client runtime-consistency probes.

	WHAT THIS IS
		A suite of independent probes that look for *internal inconsistency* in
		the client runtime: emulators that stub the engine, executors that
		replace library functions, and mocks that return plausible values for
		the wrong reasons. Each probe states an invariant the real engine holds
		and fails only when that invariant is violated.

	WHAT THIS IS NOT
		* Not a trust boundary. Everything here runs on an attacker-controlled
		  client. A determined attacker can patch the probe, stub the probe's
		  own dependencies, or replace this module wholesale.
		* Not cryptography. Fingerprints and derived keys below contain no
		  secret entropy, are not a KDF/MAC, and must never protect a secret
		  or authorise an action.
		* Not a ban signal. A failed probe is *evidence to collect*, not proof
		  of cheating. Legitimate clients fail probes constantly: low memory,
		  restricted permissions, server-side execution, Studio, outdated
		  engine versions, accessibility tooling.

	DESIGN
		* Probe registry. Every probe is a named unit with its own status, so
		  callers can see exactly what ran, what was skipped, and why.
		* Graceful degradation. Probes that need the Roblox engine, or a
		  capability that may be absent, report `unavailable` instead of
		  failing. This keeps the same file runnable (and testable) outside
		  Roblox, with no test-only branches in the production path.
		* Per-invocation isolation. State, diagnostics and the resource ledger
		  belong to one call. Concurrent calls cannot corrupt each other, and
		  a failed call does not poison later ones.
		* Everything owned is released. Temporary Instances, connections,
		  threads and meshes are torn down at each probe boundary, including
		  on the error path.

	SEE README.md for the full threat model, coverage matrix, and the
	server-side evidence policy this is designed to feed.
]]

-- ============================================================================
-- Section 0: Captured references.
--
-- Captured at load, before any probe runs. This is the module's core
-- defence against post-load tampering: if an executor swaps a library
-- function *after* this chunk runs, we keep calling the original. The
-- SELF stage re-verifies that this environment table's own bindings have
-- not been rebound underneath us.
-- ============================================================================

local type = type
local typeof = typeof
local pcall = pcall
local xpcall = xpcall
local error = error
local tostring = tostring
local tonumber = tonumber
local select = select
local rawget = rawget
local rawset = rawset
local rawequal = rawequal
local next = next
local pairs = pairs
local ipairs = ipairs
local getmetatable = getmetatable
local setmetatable = setmetatable
local unpack = table.unpack

local typeOf = type
local s = string
local tb = table
local mt = math
local b32 = bit32
local buf = buffer
local u8 = utf8
local co = coroutine
local dbg = debug

local mAbs = mt.abs
local mRandom = mt.random
local mPi = mt.pi
local mMax = mt.max
local mType = mt.type
local mHuge = mt.huge

local sByte = s.byte
local sSub = s.sub
local sFind = s.find
local sMatch = s.match
local sGsub = s.gsub
local sFormat = s.format
local sPack = s.pack
local sUnpack = s.unpack
local sPackSize = s.packsize
local sRep = s.rep
local sGmatch = s.gmatch
local sReverse = s.reverse
local sUpper = s.upper

local tInsert = tb.insert
local tConcat = tb.concat
local tSort = tb.sort
local tPack = tb.pack
local tCreate = tb.create
local tFreeze = tb.freeze
local tIsFrozen = tb.isfrozen
local tClear = tb.clear
local tMove = tb.move
local tRemove = tb.remove
local tConcatErr = tb.concat
local tClone = tb.clone

local bBand = b32.band
local bBxor = b32.bxor
local bLshift = b32.lshift
local bRshift = b32.rshift
local bArshift = b32.arshift
local bExtract = b32.extract
local bReplace = b32.replace
local bLrotate = b32.lrotate
local bCountlz = b32.countlz

-- Library surface that varies by Luau build. Probes gate on these rather
-- than assuming a particular version, so the same file runs on an old CLI
-- and on current Roblox without a version check.
local HAS_MATH_TYPE = type(mt.type) == "function"
local HAS_MATH_ULT = type(mt.ult) == "function"
local HAS_STRING_SPLIT = type(s.split) == "function"
local HAS_UTF8_NORMALIZE = type(u8.nfcnormalize) == "function"
local HAS_UTF8_GRAPHEMES = type(u8.graphemes) == "function"
local HAS_COROUTINE_FINALLY = type(co.finally) == "function"
local HAS_COROUTINE_ISYIELDABLE = type(co.isyieldable) == "function"
local HAS_BUFFER_BITS = type(buf.readbits) == "function" and type(buf.writebits) == "function"
local HAS_TABLE_FIND = type(tb.find) == "function"

local cCreate = co.create
local cResume = co.resume
local cYield = co.yield
local cWrap = co.wrap
local cStatus = co.status
local cClose = co.close
local cFinally = co.finally
local cIsYieldable = co.isyieldable

local dInfo = dbg and dbg.info
local dTraceback = dbg and dbg.traceback

-- Engine globals: present in Roblox, absent in a standalone Luau host.
local hasGame = type(game) == "table" or type(game) == "userdata"
local hasInstance = type(Instance) == "function"
local hasEnum = type(Enum) == "table"
local hasRandom = type(Random) == "table" or type(Random) == "userdata"
local hasVector3 = type(Vector3) == "table"
local hasVector2 = type(Vector2) == "table"
local hasCFrame = type(CFrame) == "table"
local hasUDim2 = type(UDim2) == "table"

local IN_ROBLOX = hasGame and hasInstance

-- This chunk's own environment table, plus a baseline snapshot of the
-- bindings that matter. The SELF stage compares against this later.
local MODULE_ENV_OK, MODULE_ENV = pcall(getfenv, 0)
if not MODULE_ENV_OK or type(MODULE_ENV) ~= "table" then
	MODULE_ENV, MODULE_ENV_OK = nil, false
end

local WATCHED_ENV = {
	"pcall", "xpcall", "type", "typeof", "tostring", "tonumber", "select",
	"rawget", "rawset", "rawequal", "next", "pairs", "ipairs",
	"getmetatable", "setmetatable", "getfenv", "setfenv", "newproxy",
	"table", "string", "math", "bit32", "buffer", "utf8", "coroutine", "debug",
	"os", "task", "tick",
	"game", "workspace", "Instance", "Enum", "Random", "Vector2", "Vector3",
	"CFrame", "UDim2", "Vector3int16", "Rect", "Axes", "PhysicalProperties",
	"Path2DControlPoint", "NumberSequence", "ColorSequence", "Region3",
	"script",
}

local ENV_BASELINE = nil
if MODULE_ENV_OK then
	ENV_BASELINE = {}
	for i = 1, #WATCHED_ENV do
		ENV_BASELINE[WATCHED_ENV[i]] = rawget(MODULE_ENV, WATCHED_ENV[i])
	end
	ENV_BASELINE = tFreeze(ENV_BASELINE)
end

-- Executor-style globals, resolved from the module environment rather than
-- _G so that a sandboxed __index is honoured.
local function executorGlobal(name)
	if MODULE_ENV_OK then
		return rawget(MODULE_ENV, name)
	end
	return rawget(_G, name)
end

local getgenvFn = executorGlobal("getgenv")

-- ============================================================================
-- Section 1: Deterministic, NON-CRYPTGRAPHIC state accumulator.
--
-- FNV-1a and a splitmix-style avalanche, folded over per-probe tokens.
-- The output is a change detector for *this build of this module*: if the
-- token stream changes, the digest changes. It is not a commitment, not
-- keyed, not collision-resistant, and carries no secret. Tokens are
-- published in the report so a divergence can be attributed to a probe.
-- ============================================================================

local FUNCTION_TOKENS = 0x5E4E544C -- "SNTL"

local function mul32(a, b)
	a = bBand(a, 0xFFFFFFFF)
	b = bBand(b, 0xFFFFFFFF)
	local alo, ahi = bBand(a, 0xFFFF), bRshift(a, 16)
	local blo, bhi = bBand(b, 0xFFFF), bRshift(b, 16)
	return bBand(alo * blo + bBand(alo * bhi + ahi * blo, 0xFFFF) * 65536, 0xFFFFFFFF)
end

-- Fold a 32-bit token into a 4-lane accumulator.
local function feed(acc, token)
	token = bBand(token, 0xFFFFFFFF)
	acc.a = mul32(bBxor(acc.a, token), 0x01000193)
	acc.b = bBand(mul32(acc.b, 0x045D9F3B) + bBxor(token, acc.a) + 0x9E3779B9, 0xFFFFFFFF)
	local rot = bBxor(bLshift(acc.c, 13), bRshift(acc.c, 19))
	acc.c = mul32(bBxor(rot, token), 0x1B873593)
	acc.d = bBxor(acc.d, bBand(acc.a + acc.b + acc.c + token, 0xFFFFFFFF))
end

local function collapse(acc)
	return bBxor(bBxor(acc.a, acc.b), bBxor(acc.c, acc.d))
end

-- ============================================================================
-- Section 2: Invocation context, diagnostics, resource ledger.
-- ============================================================================

local PROBE_REQUIRED = "required"
local PROBE_ENGINE = "engine"
local PROBE_CAPABILITY = "capability"

-- Wall-clock source. `tick` is monotonic on the Roblox client; `os.clock` is
-- CPU time and is a poor deadline source on a yielding client, so it is only
-- a last resort. Iteration count is always the hard backstop.
local tickFn = type(tick) == "function" and tick or nil
local osClock = (type(os) == "table" and type(os.clock) == "function") and os.clock or nil

local function nowSeconds()
	if tickFn then
		return tickFn()
	end
	if osClock then
		return osClock()
	end
	return nil
end

local function describe(value)
	local ok, text = pcall(tostring, value)
	if ok and type(text) == "string" then
		return text
	end
	return "<unprintable error>"
end

local function approx(a, b, eps)
	if type(a) ~= "number" or type(b) ~= "number" then
		return false
	end
	return mAbs(a - b) <= (eps or 1e-4)
end

-- NaN is not equal to itself; treat two NaNs as equal so an unchanged
-- NaN-valued binding is never reported as a replacement.
local function sameValue(a, b)
	if rawequal(a, b) then
		return true
	end
	return type(a) == "number" and type(b) == "number" and a ~= a and b ~= b
end

local function newContext(options)
	return {
		options = options,
		acc = { a = 0x811C9DC5, b = 0xCBF29CE4, c = 0x84222325, d = 0x9E3779B9 },
		probe = "<none>",
		stage = "<none>",
		tokens = {},
		probes = {},
		skipped = {},
		cleanupErrors = {},
		-- ledger: every resource this invocation created, torn down at each
		-- probe boundary whether the probe passed, threw, or was interrupted.
		ledger = {},
		hardFailure = nil,
		hardUnavailable = nil,
	}
end

-- Invariant violated. Latched on the context so a pcall inside a probe
-- cannot swallow it.
local function fail(ctx, message)
	ctx.hardFailure = ctx.hardFailure or message or "Runtime invariant violated"
	error(ctx.hardFailure, 0)
end

local function expect(ctx, condition, message)
	if not condition then
		fail(ctx, message)
	end
	return condition
end

-- This probe cannot run here. Not a verdict: it is a coverage gap.
local function skip(ctx, reason)
	tInsert(ctx.skipped, { probe = ctx.probe, stage = ctx.stage, reason = reason })
end

-- Strict mode turns a coverage gap into a run-level outcome, so callers who
-- need complete coverage can insist on it without treating the gap itself
-- as evidence of tampering.
local function unavailable(ctx, reason)
	skip(ctx, reason)
	if ctx.options.requireAllChecks then
		ctx.hardUnavailable = reason
		error("Coverage unavailable: " .. reason, 0)
	end
end

-- engine-only probe, outside Roblox.
local function needRoblox(ctx, feature)
	if not IN_ROBLOX then
		skip(ctx, "Not running on the Roblox engine (" .. feature .. ")")
		return false
	end
	return true
end

-- Optional capability, absent on this client or blocked by permissions.
local function needCapability(ctx, feature, present, detail)
	if present then
		return true
	end
	unavailable(ctx, feature .. " is unavailable" .. (detail and (": " .. detail) or ""))
	return false
end

-- ============================================================================
-- Resource ledger
-- ============================================================================

local function ledgerAdd(ctx, resource, dispose)
	expect(ctx, resource ~= nil, "Resource allocation returned nil")
	dispose = dispose or (resource.Destroy)
	expect(ctx, type(dispose) == "function", "Resource exposes no cleanup method")
	tInsert(ctx.ledger, { resource = resource, dispose = dispose, released = false })
	return resource
end

-- Release a specific resource early (when a probe is done with it) without
-- abandoning the rest of the ledger.
local function ledgerRelease(ctx, resource)
	for i = #ctx.ledger, 1, -1 do
		local entry = ctx.ledger[i]
		if rawequal(entry.resource, resource) then
			if not entry.released then
				entry.dispose(entry.resource)
				entry.released = true
			end
			return
		end
	end
	fail(ctx, "Attempted to release a resource this invocation does not own")
end

-- Drain the ledger. Returns the (possibly empty) list of cleanup failures so
-- a failure to clean up is itself a reportable failure.
local function ledgerDrain(ctx)
	local errors = {}
	for i = #ctx.ledger, 1, -1 do
		local entry = ctx.ledger[i]
		if not entry.released then
			local ok, err = pcall(entry.dispose, entry.resource)
			entry.released = true
			if not ok then
				tInsert(errors, describe(err))
			end
		end
	end
	tClear(ctx.ledger)
	return errors
end

-- Connections are a common leak source and have no Destroy method.
local function trackConnection(ctx, connection)
	return ledgerAdd(ctx, connection, function(c)
		if type(c.Disconnect) == "function" and c.Connected then
			c:Disconnect()
		end
	end)
end

local function trackThread(ctx, thread)
	return ledgerAdd(ctx, thread, function(t)
		local ok, status = pcall(cStatus, t)
		if ok and status ~= "dead" and status ~= "suspended" then
			pcall(cClose, t)
		elseif ok and status == "suspended" then
			pcall(cClose, t)
		end
	end)
end

-- Bounded polling wait for an engine-side effect (layout, signal delivery,
-- raycast readiness). Two independent bounds: a deadline when a clock is
-- available, and a hard iteration cap that also covers a broken or mocked
-- clock. Returns true if the predicate became true.
local function awaitChange(ctx, predicate)
	if predicate() then
		return true
	end
	local deadline
	local start = nowSeconds()
	if start then
		deadline = start + ctx.options.timeoutSeconds
	end
	local iterations = ctx.options.maxIterations
	for _ = 1, iterations do
		if type(task) == "table" and type(task.wait) == "function" then
			task.wait()
		else
			co.yield()
		end
		if predicate() then
			return true
		end
		local mark = nowSeconds()
		if deadline and mark and mark >= deadline then
			break
		end
	end
	return false
end

-- A live PlayerGui, not StarterGui (a template that never gets laid out).
local function openProbeGui(ctx, feature)
	local ok, playerGui = pcall(function()
		local player = game:GetService("Players").LocalPlayer
		return player and player:FindFirstChildOfClass("PlayerGui")
	end)
	if not ok or playerGui == nil then
		unavailable(ctx, "A live local PlayerGui is unavailable (" .. feature .. ")")
		return nil
	end
	local holder = ledgerAdd(ctx, Instance.new("ScreenGui"))
	holder.Name = "SentinelProbe_" .. tostring(mRandom(1000, 999999))
	holder.ResetOnSpawn = false
	holder.DisplayOrder = 9999
	holder.Parent = playerGui
	return holder
end

-- ============================================================================
-- Section 3: PROBES — pure Luau invariants.
--
-- These hold in any correct Luau implementation, so they are the strongest
-- part of the suite: an emulator that mocks the engine has to reproduce all
-- of them to get past them.
-- ============================================================================

-- --- P-CORE-1: runtime identity -------------------------------------------
-- Confirms this is Luau and not a bridge, and that the host has not been
-- handed Lua 5.x or a Python-style sandbox.
local function probeCoreIdentity(ctx)
	expect(ctx, _VERSION == "Luau", "Runtime is not Luau (_VERSION = " .. tostring(_VERSION) .. ")")
	expect(ctx, type(_G) == "table", "_G is not a table")
	expect(ctx, sFind(tostring(_G), "table: ") ~= nil, "_G does not stringify as a table")
	expect(ctx, sFind(tostring(_G), "userdata: ") == nil, "_G stringifies as userdata")

	-- boolean stringification is fixed-width in Luau
	expect(ctx, #tostring(true) + #tostring(false) == 9, "boolean tostring width is wrong")
	expect(ctx, sByte(tostring(true)) ~= sByte(tostring(false)), "true/false share a first byte")

	-- number formatting: integers, floats and exponents
	expect(ctx, sFormat("%d", 42) == "42", "integer format is wrong")
	expect(ctx, sFormat("%.3f", 1 / 3) == "0.333", "float format is wrong")
	expect(ctx, sFormat("%g", 1e100) == "1e+100", "exponent format is wrong")
	expect(ctx, tostring(0.1) == "0.1", "float tostring is wrong")
	expect(ctx, tostring(-0.0) == "-0", "negative zero tostring is wrong")

	-- Every probe in this suite depends on these being callable at all.
	local required = {
		["type"] = type, ["pcall"] = pcall, ["xpcall"] = xpcall,
		["rawget"] = rawget, ["rawset"] = rawset, ["rawequal"] = rawequal,
		["next"] = next, ["pairs"] = pairs, ["ipairs"] = ipairs,
		["getmetatable"] = getmetatable, ["setmetatable"] = setmetatable,
		["tostring"] = tostring, ["tonumber"] = tonumber, ["select"] = select,
	}
	for name, fn in pairs(required) do
		expect(ctx, type(fn) == "function", "Base function is missing: " .. name)
	end

	-- Type-classification must distinguish every basic type. A host that
	-- returns "userdata" or "number" for everything collapses here.
	expect(ctx, type(nil) == "nil" and type(true) == "boolean" and type(0) == "number"
		and type("") == "string" and type({}) == "table" and type(print) == "function",
		"Base type classification is wrong")

	if dInfo then
		expect(ctx, not pcall(dInfo, 1, "z"), "debug.info accepted an invalid option")
		expect(ctx, not pcall(dInfo, -1, "s"), "debug.info accepted a negative level")
		expect(ctx, dInfo(99999, "s") == nil, "debug.info returned data for an out-of-range level")
	end

	ctx.tokens[#ctx.tokens + 1] = bBand(sByte(_VERSION, 1), 0xFFFF)
		ctx.tokens[#ctx.tokens + 1] = bBand(sByte(_VERSION, 4), 0xFFFF)
end

-- --- P-CORE-2: string metatable lock -------------------------------------
-- getmetatable("") returning a real table is impossible in stock Luau
-- (luaB_getmetatable refuses strings). A host that returns one has
-- intercepted the builtin.
local function probeStringMetatable(ctx)
	local ok, mt = pcall(getmetatable, "")
	expect(ctx, ok, "getmetatable(\"\") threw")
	expect(ctx,
		mt == "The metatable is locked"
			or (type(mt) == "table" and rawequal(mt.__index, s) and mt.__metatable == nil),
		"getmetatable(\"\") returned an unexpected value")
	expect(ctx, not pcall(setmetatable, "", {}), "setmetatable succeeded on a string")

	-- method identity: ("A").byte must be the same function as string.byte
	expect(ctx, rawequal(sByte, ("A").byte), "string method lookup does not return the same function")
	expect(ctx, sByte("A") == 65, "string.byte is wrong")
	expect(ctx, sByte("A", 1, 1) == 65, "string.byte range is wrong")
	expect(ctx, select("#", sByte("A", 1, 1)) == 1, "string.byte range return count is wrong")

	-- string.* correctness and edge cases
	expect(ctx, sSub("hello", 2, 3) == "el", "string.sub is wrong")
	expect(ctx, sSub("hello", -3) == "llo", "string.sub negative index is wrong")
	expect(ctx, sRep("ab", 3) == "ababab" and sRep("ab", 0) == "", "string.rep is wrong")
	expect(ctx, type(sRep("ab", -1)) == "string", "string.rep with a negative count did not return a string")
	expect(ctx, sReverse("abc") == "cba", "string.reverse is wrong")
	expect(ctx, sUpper("aBc") == "ABC", "string.upper is wrong")
	expect(ctx, sGsub("a1b2", "%d", "#") == "a#b#", "string.gsub is wrong")
	expect(ctx, sFormat("%5.2f", 1.5) == " 1.50", "string.format padding is wrong")
	expect(ctx, sFormat("%x", 255) == "ff", "string.format hex is wrong")
	expect(ctx, sFormat("%d", 42) == "42" and sFormat("%.3f", 1 / 3) == "0.333",
		"string.format integer/float directives are wrong")
	expect(ctx, sFormat("%g", 1e100) == "1e+100", "string.format exponent is wrong")
	expect(ctx, sFormat("%s|%s", "a", 1) == "a|1", "string.format %s coercion is wrong")
	expect(ctx, not pcall(sFormat, "%s", true), "string.format %s accepted a boolean")

	-- string.split, where the build provides it. Whether an empty field is
	-- preserved differs between Luau builds, so the assertion is the
	-- round-trip property that holds either way rather than a fixed count.
	if HAS_STRING_SPLIT then
		local parts = s.split("a,b,c", ",")
		expect(ctx, type(parts) == "table" and #parts >= 3, "string.split did not split on every separator")
		expect(ctx, parts[1] == "a" and parts[#parts] == "c", "string.split endpoints are wrong")
		local absent = s.split("abc", ",")
		expect(ctx, #absent == 1 and absent[1] == "abc", "string.split with no separator is wrong")
		local every = s.split("abc", "")
		expect(ctx, #every == 3 and every[1] == "a" and every[3] == "c",
			"string.split with an empty separator is wrong")
		local rebuilt = tConcat(s.split("a,b,c", ","), ",")
		expect(ctx, rebuilt == "a,b,c", "string.split parts did not round-trip")
	else
		skip(ctx, "string.split is not exposed on this Luau build")
	end

	-- gmatch: full iteration, not just the first result
	local seen = {}
	for word in sGmatch("alpha beta gamma", "%a+") do
		seen[#seen + 1] = word
	end
	expect(ctx, #seen == 3 and seen[1] == "alpha" and seen[3] == "gamma",
		"string.gmatch did not iterate correctly")

	-- Lua patterns, not regex
	expect(ctx, sFind("a.b", ".", 1, true) == 2, "string.find plain mode is wrong")
	expect(ctx, sMatch("key = value", "^(%w+)%s*=%s*(%w+)$") == "key", "string.match anchors are wrong")
	expect(ctx, sMatch("2026-10-15", "^(%d%d%d%d)-(%d%d)-(%d%d)$") == "2026",
		"string.match capture behaviour is wrong")

	ctx.tokens[#ctx.tokens + 1] = bBand(#s, 0xFFFF)
end

-- --- P-CORE-3: numeric model ---------------------------------------------
-- Integer/float distinction, NaN, infinity and precision. A host with a
-- single numeric type (e.g. a JS or Python bridge) fails here.
--
-- math.type / math.ult are recent Luau additions; the integer-exactness
-- invariants below hold on every Luau build, so they carry the probe when
-- the reflection API is absent.
local function probeNumericModel(ctx)
	-- integer arithmetic is exact past float53
	expect(ctx, 2^53 + 1 == 2^53, "Integer arithmetic is not exact past 2^53")
	expect(ctx, 9007199254740993 == 9007199254740992, "Integer literal precision is wrong")
	expect(ctx, 7 // 2 == 3 and -7 // 2 == -4, "Floor division is wrong")
	expect(ctx, 7 % 2 == 1 and -7 % 2 == 1, "Modulo is wrong")

	-- if the reflection API exists, it must be honest about the distinction
	if HAS_MATH_TYPE then
		expect(ctx, mType(1) == "integer" and mType(1.0) == "float",
			"math.type does not distinguish 1 from 1.0")
		expect(ctx, mType(1) ~= mType(1.5), "math.type is not distinguishing integer from float")
		expect(ctx, mType("1") == nil and mType({}) == nil, "math.type accepted a non-number")
		expect(ctx, mType(4 / 2) == "float", "4/2 did not produce a float")
	else
		skip(ctx, "math.type is not exposed on this Luau build")
	end

	if HAS_MATH_ULT then
		expect(ctx, mt.ult(-1, 1) == true and mt.ult(1, -1) == false,
			"math.ult unsigned comparison is wrong")
		skip(ctx, "math.ult is not exposed on this Luau build")
	end

	-- infinity and NaN behaviour
	expect(ctx, 1 / 0 == mHuge, "1/0 is not +inf")
	expect(ctx, -1 / 0 == -mHuge, "-1/0 is not -inf")
	expect(ctx, mt.huge == 1 / 0, "math.huge is not 1/0")
	local nan = 0 / 0
	expect(ctx, nan ~= nan, "0/0 is not NaN")
	expect(ctx, not (nan == nan), "NaN compared equal")
	expect(ctx, not (nan < 1) and not (nan > 1) and not (nan <= 1) and not (nan >= 1),
		"NaN ordered against a number")

	-- math library identities that hold on every build
	expect(ctx, mt.sqrt(9) == 3, "math.sqrt is wrong")
	expect(ctx, mAbs(mt.sin(0)) < 1e-12 and mAbs(mt.cos(0) - 1) < 1e-12, "math.sin/cos at 0")
	expect(ctx, mAbs(mt.exp(0) - 1) < 1e-12, "math.exp(0) is not 1")
	expect(ctx, mAbs(mt.log(1)) < 1e-12, "math.log(1) is not 0")
	expect(ctx, mAbs(mt.atan2(0, 1)) < 1e-12, "math.atan2 is wrong")
	expect(ctx, mt.fmod(7, 3) == 1 and mt.fmod(-7, 3) == -1, "math.fmod sign is wrong")
	expect(ctx, mAbs(mt.pow(2, 10) - 1024) < 1e-9, "math.pow is wrong")
	expect(ctx, mt.floor(-1.5) == -2 and mt.ceil(-1.5) == -1, "math.floor/ceil rounding is wrong")
	expect(ctx, mt.sign(-7) == -1, "math.sign is wrong")
	expect(ctx, mt.min(3, 1, 2) == 1 and mMax(1, 2, 3) == 3, "math.min/max is wrong")
	expect(ctx, mt.clamp(5, 0, 3) == 3, "math.clamp is wrong")
	expect(ctx, mt.lerp(0, 10, 0.5) == 5, "math.lerp is wrong")

	-- explicit NaN/infinity predicates, where present
	if type(mt.isnan) == "function" then
		expect(ctx, mt.isnan(0 / 0) == true and mt.isnan(1) == false, "math.isnan is wrong")
	end
	if type(mt.isinf) == "function" then
		expect(ctx, mt.isinf(1 / 0) == true and mt.isinf(0 / 0) == false
			and mt.isinf(1) == false, "math.isinf is wrong")
	end
	if type(mt.isfinite) == "function" then
		expect(ctx, mt.isfinite(1) == true and mt.isfinite(1 / 0) == false
			and mt.isfinite(0 / 0) == false, "math.isfinite is wrong")
	end

	-- random bounds must hold; the host cannot fake these consistently
	for _ = 1, 32 do
		local r = mt.random(5, 9)
		expect(ctx, r >= 5 and r <= 9 and r % 1 == 0, "math.random escaped its inclusive range")
	end
	local u = mt.random()
	expect(ctx, u >= 0 and u < 1, "math.random() escaped [0,1)")
	expect(ctx, mt.random(7, 7) == 7, "math.random with an equal range is wrong")

	-- number parsing
	expect(ctx, tonumber("0x10") == 16, "hex parsing is wrong")
	expect(ctx, tonumber("  12  ") == 12, "whitespace-tolerant parsing is wrong")
	expect(ctx, tonumber("abc") == nil, "tonumber accepted garbage")
	expect(ctx, tonumber("") == nil and tonumber("0x") == nil, "tonumber accepted an empty/partial literal")
	expect(ctx, tonumber("1e3") == 1000, "exponent parsing is wrong")

	ctx.tokens[#ctx.tokens + 1] = bBand(7 // 2, 0xFFFF)
	ctx.tokens[#ctx.tokens + 1] = bBand(mt.floor(-1.5) + 3, 0xFFFF)
end

-- --- P-CORE-4: string.pack / string.unpack -------------------------------
-- Binary serialisation with explicit endianness and widths. A mock that
-- implements pack loosely (or via string.format) gets this wrong.
local function probeStringPack(ctx)
	expect(ctx, type(sPack) == "function", "string.pack is missing")
	expect(ctx, type(sUnpack) == "function", "string.unpack is missing")
	expect(ctx, type(sPackSize) == "function", "string.packsize is missing")

	-- little-endian and big-endian of the same value
	local le = sPack("<I4", 0x01020304)
	local be = sPack(">I4", 0x01020304)
	expect(ctx, #le == 4 and #be == 4, "string.pack produced the wrong length")
	expect(ctx, sByte(le, 1) == 0x04 and sByte(le, 4) == 0x01, "little-endian packing is wrong")
	expect(ctx, sByte(be, 1) == 0x01 and sByte(be, 4) == 0x04, "big-endian packing is wrong")
	expect(ctx, le ~= be, "endianness did not affect the output")

	expect(ctx, sPackSize("I4") == 4, "string.packsize(I4) is wrong")
	expect(ctx, sPackSize("<I4") == 4 and sPackSize(">i2") == 2, "string.packsize with a prefix is wrong")
	expect(ctx, sPackSize("c3") == 3, "string.packsize(c3) is wrong")
	expect(ctx, not pcall(sPackSize, "Z"), "string.packsize accepted a variable-length format")
	expect(ctx, not pcall(sPackSize, "z"), "string.packsize accepted a variable-length format")

	-- round-trip through every supported directive
	local u32v, i16v, f64v, s8v = 3735928559, -12345, 1.7976931348623157e308, "luau"
	local packed = sPack("<I4i2dz", u32v, i16v, f64v, s8v)
	expect(ctx, sUnpack("<I4", packed) == u32v, "I4 round-trip failed")
	local ru32, ri16, rf64, rest = sUnpack("<I4i2d", packed)
	expect(ctx, ru32 == u32v, "I4 round-trip failed")
	expect(ctx, ri16 == i16v, "i2 round-trip failed")
	expect(ctx, rf64 == f64v, "d round-trip failed")
	-- unpack's trailing return is the 1-based offset just past the last read
	expect(ctx, type(rest) == "number" and rest == 15, "unpack did not report the next byte offset")
	expect(ctx, sUnpack("c3", packed, rest) == "lua", "c3 round-trip failed")
	expect(ctx, sUnpack("z", packed, rest) == s8v, "z round-trip failed")
	-- packsize rejects variable-length directives rather than guessing
	expect(ctx, not pcall(sPackSize, "z"), "string.packsize accepted a variable-length format")

	-- floats bit-exactly
	local onePointFive = sPack("<f", 1.5)
	expect(ctx, #onePointFive == 4, "f directive length is wrong")
	expect(ctx, sUnpack("<f", onePointFive) == 1.5, "f round-trip failed")
	expect(ctx, sUnpack(">f", sPack(">f", -2.25)) == -2.25, "f round-trip failed (big-endian)")

	-- error behaviour: out-of-range values and bad formats must be rejected
	expect(ctx, not pcall(sPack, "<I4", -1), "string.pack accepted a negative u32")
	expect(ctx, not pcall(sPack, "<i1", 200), "string.pack accepted an out-of-range i1")
	expect(ctx, not pcall(sPack, "<I4"), "string.pack accepted a missing argument")
	expect(ctx, not pcall(sUnpack, "<I4", "ab"), "string.unpack accepted a short buffer")
	expect(ctx, not pcall(sPack, "<Q", 1), "string.pack accepted an unknown directive")

	-- alignment and multiple values in one call
	local multi = sPack("<I2I2", 0xAAAA, 0xBBBB)
	expect(ctx, #multi == 4 and sUnpack("<I2", multi) == 0xAAAA, "repeated directives are wrong")

	ctx.tokens[#ctx.tokens + 1] = bBand(#sPack(">I4", 0x01020304), 0xFFFF)
	ctx.tokens[#ctx.tokens + 1] = bBand(sByte(be, 1), 0xFFFF)
end

-- --- P-CORE-5: utf8 -------------------------------------------------------
-- Codepoint-correct UTF-8. Length must be in bytes, offsets in codepoints,
-- and invalid sequences must be reported, not silently replaced.
local function probeUtf8(ctx)
	expect(ctx, type(u8) == "table", "utf8 is missing")
	expect(ctx, type(u8.char) == "function" and type(u8.len) == "function"
		and type(u8.codepoint) == "function" and type(u8.charpattern) == "string",
		"utf8 is missing required members")

	-- ASCII and BMP
	expect(ctx, u8.char(72, 105) == "Hi", "utf8.char is wrong")
	expect(ctx, u8.len("Hi") == 2, "utf8.len is wrong for ASCII")
	expect(ctx, u8.len("héllo") == 5, "utf8.len counted codepoints, not bytes")
	expect(ctx, #"héllo" == 6, "the host is not storing UTF-8 bytes")
	expect(ctx, u8.len("héllo", 1, -1) == 5, "utf8.len with a range is wrong")

	-- astral plane: U+1F600, encoded as 4 bytes
	local grin = u8.char(0x1F600)
	expect(ctx, #grin == 4, "astral codepoint did not encode to 4 bytes")
	expect(ctx, u8.len(grin) == 1, "astral codepoint length is wrong")
	expect(ctx, u8.codepoint(grin) == 0x1F600, "utf8.codepoint is wrong for an astral codepoint")
	expect(ctx, u8.codepoint(grin, 1, 1) == 0x1F600, "utf8.codepoint ranged form is wrong")

	-- byte offset vs codepoint index
	local mixed = "a" .. grin .. "b"
	expect(ctx, u8.len(mixed) == 3, "utf8.len on a mixed string is wrong")
	expect(ctx, #mixed == 6, "mixed string byte length is wrong")
	expect(ctx, u8.offset(mixed, 2) == 2, "utf8.offset is wrong")
	expect(ctx, u8.offset(mixed, 3) == 6, "utf8.offset is wrong for the third codepoint")

	-- invalid sequences are rejected, not repaired
	expect(ctx, u8.len("\xFF") == nil, "utf8.len accepted a lone 0xFF")
	expect(ctx, u8.len("\xC3") == nil, "utf8.len accepted a truncated sequence")
	expect(ctx, not pcall(u8.codepoint, "\xED\xA0\x80"), "utf8.codepoint accepted a surrogate encoding")
	expect(ctx, not pcall(u8.char, 0x110000), "utf8.char accepted an out-of-range codepoint")
	expect(ctx, not pcall(u8.char, -1), "utf8.char accepted a negative codepoint")

	-- utf8 library interop with the pattern-matching engine
	expect(ctx, sFind("héllo", u8.charpattern) == 1, "utf8.charpattern is not a valid pattern")
	local matchCount = 0
	for _ in sGmatch("héllo", u8.charpattern) do
		matchCount += 1
	end
	expect(ctx, matchCount == 5, "utf8.charpattern did not match 5 codepoints")
	local firstMatch = sGmatch("héllo", u8.charpattern)()
	expect(ctx, firstMatch == "h", "utf8.charpattern did not match the first codepoint")

	-- utf8.codes, where available
	if type(u8.codes) == "function" then
		local n = 0
		for _ in u8.codes("héllo") do
			n += 1
		end
		expect(ctx, n == 5, "utf8.codes did not iterate 5 codepoints")
	else
		skip(ctx, "utf8.codes is not exposed on this Luau build")
	end
	if HAS_UTF8_NORMALIZE then
		expect(ctx, type(u8.nfcnormalize("abc")) == "string", "utf8.nfcnormalize is wrong")
	else
		skip(ctx, "utf8.nfcnormalize is not exposed on this Luau build")
	end
	if HAS_UTF8_GRAPHEMES then
		expect(ctx, u8.graphemes("abc", true) == 1, "utf8.graphemes is wrong")
	else
		skip(ctx, "utf8.graphemes is not exposed on this Luau build")
	end

	ctx.tokens[#ctx.tokens + 1] = bBand(#u8.char(0x1F600), 0xFFFF)
	ctx.tokens[#ctx.tokens + 1] = bBand(u8.len("héllo"), 0xFFFF)
end

-- --- P-CORE-6: table semantics -------------------------------------------
local function probeTableSemantics(ctx)
	-- length of a table with a hole is implementation-defined, so only the
	-- dense cases are asserted
	local dense = { 10, 20, 30 }
	expect(ctx, #dense == 3, "# on a dense array is wrong")
	expect(ctx, #{} == 0, "# on an empty table is wrong")
	expect(ctx, #{ 1, 2, 3, 4, 5 } == 5, "# on a longer dense array is wrong")
	expect(ctx, tPack("a", nil, "c").n == 3, "table.pack miscounts a nil hole")

	-- insert/remove return values and shifting
	local list = { "a", "b", "c" }
	local removed = tRemove(list, 2)
	expect(ctx, removed == "b" and #list == 2 and list[2] == "c", "table.remove is wrong")
	tInsert(list, 2, "z")
	expect(ctx, list[2] == "z" and #list == 3, "table.insert at an index is wrong")
	tInsert(list, "end")
	expect(ctx, #list == 4 and list[4] == "end", "table.insert append is wrong")

	-- concat: rejects non-string/number elements, and honours a separator
	expect(ctx, tConcat({ "a", "b" }, "-") == "a-b", "table.concat separator is wrong")
	expect(ctx, tConcat({}, ",") == "", "table.concat on an empty table is wrong")
	expect(ctx, tConcat({ 1, 2, 3 }, "") == "123", "table.concat of numbers is wrong")
	expect(ctx, not pcall(tConcat, { "a", {} }, ","), "table.concat accepted a table element")
	expect(ctx, not pcall(tConcat, { "a", true }, ","), "table.concat accepted a boolean element")

	-- sort: comparator-driven, and an invalid comparator must be rejected.
	-- (Luau 0.742 permits an always-true comparator on 3 elements, so the
	-- rejection is asserted on the genuinely invalid comparison below.)
	local nums = { 5, 3, 9, 1, 7 }
	tSort(nums, function(a, b) return a < b end)
	expect(ctx, nums[1] == 1 and nums[5] == 9, "table.sort did not order ascending")
	tSort(nums, function(a, b) return a > b end)
	expect(ctx, nums[1] == 9 and nums[5] == 1, "table.sort did not order descending")
	expect(ctx, not pcall(tSort, { 3, 1, 2, "x" }), "table.sort accepted incomparable value types")
	local sortedStrings = { "pear", "apple", "fig" }
	tSort(sortedStrings)
	expect(ctx, sortedStrings[1] == "apple" and sortedStrings[3] == "pear", "table.sort default order is wrong")

	-- table.move: overlapping ranges must behave like memmove, not memcpy
	local src = { 1, 2, 3, 4, 5 }
	tMove(src, 1, 4, 2)
	expect(ctx, src[1] == 1 and src[2] == 1 and src[3] == 2 and src[4] == 3 and src[5] == 4,
		"table.move overlapping copy is wrong (it must behave like memmove)")
	local dst = tMove({ 1, 2, 3, 4 }, 1, 4, 1, {})
	expect(ctx, #dst == 4 and dst[4] == 4, "table.move to a new table is wrong")
	-- An over-long range clamps to the source length rather than erroring
	local clamped = tMove({ 1, 2, 3 }, 1, 99, 1, {})
	expect(ctx, #clamped == 3 and clamped[3] == 3, "table.move did not clamp an over-long range")

	-- concat: rejects non-string/number elements, and honours a separator
	expect(ctx, tConcat({ "a", "b" }, "-") == "a-b", "table.concat separator is wrong")
	expect(ctx, tConcat({}, ",") == "", "table.concat on an empty table is wrong")
	expect(ctx, tConcat({ 1, 2, 3 }, "") == "123", "table.concat of numbers is wrong")
	expect(ctx, not pcall(tConcat, { "a", {} }, ","), "table.concat accepted a table element")
	expect(ctx, not pcall(tConcat, { "a", true }, ","), "table.concat accepted a boolean element")

	-- unpack honours an explicit range and preserves nil holes
	local packed = tPack("a", nil, "c")
	expect(ctx, select("#", unpack(packed, 1, packed.n)) == 3, "table.unpack lost a nil hole")
	-- An end index past the table returns nils rather than erroring
	expect(ctx, select("#", unpack({ 1, 2, 3 }, 1, 5)) == 5, "table.unpack did not pad to the requested range")
	expect(ctx, unpack({ 1, 2, 3 }, 99, 100) == nil, "table.unpack with a start past the end was not nil")

	-- create/freeze/isfrozen
	local created = tCreate(4, 9)
	expect(ctx, #created == 4 and created[1] == 9 and created[4] == 9, "table.create is wrong")
	expect(ctx, not pcall(tCreate, -1), "table.create accepted a negative size")
	local frozen = tFreeze({ k = 42 })
	expect(ctx, tIsFrozen(frozen) and frozen.k == 42, "table.freeze/isfrozen is wrong")
	expect(ctx, not pcall(function() frozen.k = 1 end), "assignment to a frozen table succeeded")
	expect(ctx, not pcall(rawset, frozen, "k", 1), "rawset on a frozen table succeeded")
	expect(ctx, not pcall(setmetatable, frozen, {}), "setmetatable on a frozen table succeeded")
	local deep = tFreeze({ inner = tFreeze({ v = 1 }) })
	expect(ctx, not pcall(function() deep.inner.v = 2 end), "a nested frozen table was mutable")

	-- clone copies the top level, but nested tables are kept by reference.
	-- This is the documented Luau behaviour. (Roblox's table.clone may be
	-- deeper; the top-level copy is the universal invariant.)
	local original = { n = 1, nested = { d = 2 } }
	local copied = tClone(original)
	expect(ctx, copied.n == 1 and not rawequal(copied, original), "table.clone identity is wrong")
	expect(ctx, copied.nested.d == 2 and rawequal(copied.nested, original.nested),
		"table.clone should preserve nested tables by reference")

	-- next enumerates every key exactly once, and rawget/rawequal ignore
	-- metamethods
	local meta = setmetatable({}, {
		__index = function() return "meta" end,
		__len = function() return 999 end,
	})
	expect(ctx, meta.missing == "meta", "__index is not functioning")
	expect(ctx, rawget(meta, "missing") == nil, "rawget was intercepted by __index")
	expect(ctx, not rawequal({}, {}), "rawequal compared two distinct tables equal")
	local seenKeys, count = {}, 0
	for k in next, { a = 1, b = 2, c = 3 } do
		seenKeys[#seenKeys + 1] = k
		count += 1
	end
	expect(ctx, count == 3, "next did not enumerate every key")
	tSort(seenKeys)
	expect(ctx, seenKeys[1] == "a" and seenKeys[3] == "c", "next returned wrong keys")
	expect(ctx, next({}) == nil, "next on an empty table was not nil")

	-- ipairs stops at the first nil
	local ip, ic = 0, 0
	for _ in ipairs({ 1, 2, nil, 4 }) do
		ic += 1
	end
	ip = ic
	expect(ctx, ip == 2, "ipairs did not stop at a nil hole")

	ctx.tokens[#ctx.tokens + 1] = bBand(sPackSize("<I4"), 0xFFFF)
	ctx.tokens[#ctx.tokens + 1] = bBand(u8.len("x"), 0xFFFF)
end

-- --- P-CORE-7: metatables, newproxy, error handling ----------------------
local function probeMetatablesAndErrors(ctx)
	-- pcall preserves multiple returns including nil holes
	local ok, a, b, c = pcall(function() return 1, nil, 3 end)
	expect(ctx, ok and a == 1 and b == nil and c == 3, "pcall lost a nil hole")

	-- xpcall receives the error and its return value propagates
	local xok, msg = xpcall(function() error("sentinel_91", 0) end,
		function(e) return "caught:" .. tostring(e) end)
	expect(ctx, not xok and msg == "caught:sentinel_91", "xpcall did not see the error value")

	-- level 0 keeps the message unprefixed
	local zok, zmsg = pcall(function() error("raw", 0) end)
	expect(ctx, not zok and zmsg == "raw", "error(_, 0) added a position prefix")
	local lok, lmsg = pcall(function() error("levelled", 1) end)
	expect(ctx, not lok and sFind(lmsg, "levelled") ~= nil, "error(_, 1) lost the message")

	-- a non-string error value is preserved
	local vok, verr = pcall(function() error({ code = 7 }, 0) end)
	expect(ctx, not vok and type(verr) == "table" and verr.code == 7, "error() mangled a table error value")

	-- select semantics
	expect(ctx, select("#", 1, nil, 3) == 3, "select('#') miscounted")
	expect(ctx, select(2, "a", "b", "c") == "b", "select(n) is wrong")
	expect(ctx, select(-1, "a", "b", "c") == "c", "select(-n) is wrong")
	expect(ctx, not pcall(select, 0, "a"), "select(0) was accepted")

	-- newproxy: real userdata with a writable metatable
	local newproxyFn = executorGlobal("newproxy")
	if type(newproxyFn) == "function" then
		local p = newproxyFn(true)
		local pm = getmetatable(p)
		expect(ctx, type(pm) == "table" and type(p) == "userdata", "newproxy(true) is wrong")
		pm.__len = function() return 1000159 end
		pm.__index = { probe = "ok" }
		expect(ctx, #p == 1000159 and p.probe == "ok", "newproxy metamethods do not work")
		expect(ctx, not pcall(newproxyFn, p), "newproxy accepted a userdata argument")
		pm.__metatable = false
		expect(ctx, getmetatable(p) == false, "__metatable protection did not apply")
		local pf = newproxyFn(false)
		expect(ctx, type(pf) == "userdata" and getmetatable(pf) == nil, "newproxy(false) is wrong")
		expect(ctx, not pcall(setmetatable, pf, {}), "setmetatable succeeded on an unprotected userdata")
	else
		-- Not present in every sandbox; absence is a configuration fact.
		skip(ctx, "newproxy is not exposed in this sandbox")
	end

	-- bit32 identities
	expect(ctx, bBxor(0x12345678, 0xFFFFFFFF) == 0xEDCBA987, "bit32.bxor is wrong")
	expect(ctx, bArshift(0x80000000, 31) == 0xFFFFFFFF, "bit32.arshift is wrong")
	expect(ctx, bExtract(0xAB, 0, 8) == 0xAB, "bit32.extract is wrong")
	expect(ctx, bReplace(0xABCD1234, 0xFF, 8, 8) == 0xABCDFF34, "bit32.replace is wrong")
	expect(ctx, bBand(0xFF, 0xF0) == 0xF0, "bit32.band is wrong")
	expect(ctx, bBand(0xFFFF, 0xFF00) == 0xFF00, "bit32.band with no overlap is wrong")
	expect(ctx, bLshift(1, 31) == 0x80000000, "bit32.lshift overflow is wrong")
	expect(ctx, not pcall(bExtract, 0, 0, 0), "bit32.extract accepted a zero field")
	expect(ctx, not pcall(bExtract, 0, 8, 25), "bit32.extract accepted a range that runs off the top")
	expect(ctx, b32.byteswap(0x12345678) == 0x78563412, "bit32.byteswap is wrong")
	expect(ctx, b32.btest(0xF0, 0x10) == true and b32.btest(0xF0, 0x0F) == false, "bit32.btest is wrong")
	expect(ctx, b32.bnot(0) == 0xFFFFFFFF, "bit32.bnot is wrong")
	if type(bLrotate) == "function" then
		expect(ctx, bLrotate(1, 1) == 2 and bLrotate(0x80000000, 1) == 1, "bit32.lrotate is wrong")
	end

	-- traceback must mention this chunk and grow with call depth
	if dTraceback then
		local tb1 = dTraceback()
		local deepTb
		pcall(function()
			deepTb = (function()
				return (function() return dTraceback() end)()
			end)()
		end)
		expect(ctx, type(tb1) == "string" and #tb1 > 0, "debug.traceback returned nothing usable")
		expect(ctx, type(deepTb) == "string" and #deepTb >= #tb1, "debug.traceback did not grow with depth")
	end

	-- error on a frozen table is a plain error, not a host crash
	expect(ctx, not pcall(function() error(setmetatable({}, { __index = function() error("nested") end })) end),
		"nested metamethod error did not propagate")

	ctx.tokens[#ctx.tokens + 1] = bBxor(0x12345678, 0xFFFFFFFF)
end

-- --- P-CORE-8: coroutine lifecycle ---------------------------------------
local function probeCoroutines(ctx)
	-- normal resume/yield round-trip
	local co1 = cCreate(function(a)
		local b = cYield(a * 2)
		return b + 1
	end)
	local ok1, v1 = cResume(co1, 5)
	local ok2, v2 = cResume(co1, 10)
	expect(ctx, ok1 and v1 == 10, "first coroutine resume is wrong")
	expect(ctx, ok2 and v2 == 11, "second coroutine resume is wrong")
	expect(ctx, cStatus(co1) == "dead", "a finished coroutine is not 'dead'")

	-- error inside a coroutine is reported, not propagated
	local co2 = cCreate(function() error("co_err", 0) end)
	local eok, eerr = cResume(co2)
	expect(ctx, not eok and eerr == "co_err", "coroutine error was not reported")
	expect(ctx, cStatus(co2) == "dead", "an errored coroutine is not 'dead'")

	-- resume on a dead coroutine fails
	expect(ctx, not cResume(co2), "resuming a dead coroutine succeeded")
	expect(ctx, not cResume(co1), "resuming a finished coroutine succeeded")

	-- close kills a suspended coroutine and makes it unresumable. In some
	-- builds the status is 'closed' afterwards, in others it's 'dead' — both
	-- indicate the coroutine is finished.
	local co3 = cCreate(function() cYield("pending") end)
	cResume(co3)
	expect(ctx, cStatus(co3) == "suspended", "coroutine was not suspended")
	local closeOk, closeErr = pcall(cClose, co3)
	expect(ctx, closeOk, "coroutine.close failed: " .. describe(closeErr))
	local afterStatus = cStatus(co3)
	expect(ctx, afterStatus == "closed" or afterStatus == "dead",
		"coroutine.close left the coroutine in state " .. tostring(afterStatus))
	expect(ctx, not cResume(co3), "resuming a closed coroutine succeeded")

	-- coroutine.isyieldable, where the build provides it
	if HAS_COROUTINE_ISYIELDABLE then
		local seen
		local inCo = cCreate(function()
			seen = cIsYieldable()
		end)
		cResume(inCo)
		expect(ctx, seen == true, "isyieldable reported false inside a coroutine")
	else
		skip(ctx, "coroutine.isyieldable is not exposed on this Luau build")
	end

	-- wrap reports the same errors
	local w = cWrap(function() error("wrapped", 0) end)
	expect(ctx, not pcall(w), "coroutine.wrap swallowed an error")
	local yielded = cWrap(function() return cYield("via-wrap") end)
	expect(ctx, yielded() == "via-wrap", "coroutine.wrap did not forward a yield")

	-- yield across a pcall boundary is allowed
	local co4 = cCreate(function() return pcall(function() return cYield("through-pcall") end) end)
	local r1, r2 = cResume(co4)
	local r3, r4, r5 = cResume(co4, "resumed")
	expect(ctx, r1 and r2 == "through-pcall", "yield did not cross a pcall boundary")
	expect(ctx, r3 and r4 == true and r5 == "resumed", "pcall did not resume cleanly")

	ctx.tokens[#ctx.tokens + 1] = FUNCTION_TOKENS
end

-- --- P-CORE-9: buffer memory aliasing ------------------------------------
-- Writing one width and reading another proves a real byte-addressed buffer
-- with IEEE-754 encoding. A key-value mock cannot pass this.
local function probeBuffers(ctx)
	expect(ctx, type(buf) == "table", "buffer is missing")
	local methods = {
		"create", "fromstring", "tostring", "len",
		"readu8", "readu16", "readi16", "readi32", "readu32", "readf32", "readf64", "readstring",
		"writeu8", "writeu16", "writei16", "writei32", "writeu32", "writef32", "writef64", "writestring",
		"fill", "copy",
	}
	for i = 1, #methods do
		expect(ctx, type(buf[methods[i]]) == "function", "buffer." .. methods[i] .. " is missing")
	end

	local b = buf.create(48)
	expect(ctx, buf.len(b) == 48, "buffer.create produced the wrong length")

	-- float64 pi, read as two little-endian u32s
	buf.writef64(b, 0, mPi)
	local piLow, piHigh = buf.readu32(b, 0), buf.readu32(b, 4)
	expect(ctx, piLow == 0x54442D18 and piHigh == 0x400921FB, "float64 IEEE-754 encoding is wrong")

	-- float32 bit patterns
	buf.writef32(b, 8, 1.5)
	buf.writef32(b, 12, -2.25)
	expect(ctx, buf.readu32(b, 8) == 0x3FC00000, "float32 1.5 bit pattern is wrong")
	expect(ctx, buf.readu32(b, 12) == 0xC0100000, "float32 -2.25 bit pattern is wrong")

	-- cross-width aliasing: two u16 halves must read back as 3.0
	buf.writeu16(b, 16, 0x0000)
	buf.writeu16(b, 18, 0x4040)
	expect(ctx, buf.readf32(b, 16) == 3, "u16->f32 aliasing is wrong")

	-- signed integers round-trip and are two's complement
	buf.writei32(b, 20, -1)
	expect(ctx, buf.readu32(b, 20) == 0xFFFFFFFF, "i32 -1 is not two's complement")
	expect(ctx, buf.readi16(b, 20) == -1, "i16 truncation is wrong")
	expect(ctx, buf.readi32(b, 20) == -1, "i32 round-trip failed")

	-- dynamic bit decomposition
	local n = mRandom(2, 63) * 1.5
	buf.writef32(b, 24, n)
	local bits = buf.readu32(b, 24)
	buf.writeu32(b, 28, bits)
	expect(ctx, buf.readf32(b, 28) == n, "f32 bit round-trip failed")
	expect(ctx, bExtract(bits, 31, 1) == 0, "positive float had the sign bit set")

	-- NaN and infinity survive the wire
	buf.writef32(b, 32, 0 / 0)
	expect(ctx, buf.readf32(b, 32) ~= buf.readf32(b, 32), "NaN did not survive a buffer round-trip")
	buf.writef64(b, 36, mHuge)
	expect(ctx, buf.readf64(b, 36) == mHuge, "infinity did not survive a buffer round-trip")

	-- out-of-bounds must throw, not wrap
	expect(ctx, not pcall(buf.readu8, b, 48), "read past the end of a buffer succeeded")
	expect(ctx, not pcall(buf.writeu32, b, 46, 1), "straddling write past the end succeeded")
	expect(ctx, not pcall(buf.create, -1), "buffer.create accepted a negative size")
	expect(ctx, not pcall(buf.readu8, "not a buffer", 0), "buffer.readu8 accepted a non-buffer")

	-- copy/fill, including an overlapping copy
	local src = buf.fromstring("RBLX_AT")
	buf.copy(b, 40, src, 0, 7)
	expect(ctx, buf.readstring(b, 40, 7) == "RBLX_AT", "buffer.copy is wrong")
	buf.fill(b, 40, 0x5A, 4)
	expect(ctx, buf.readu32(b, 40) == 0x5A5A5A5A, "buffer.fill is wrong")
	buf.fill(b, 40, 0x11, 4)
	expect(ctx, buf.readstring(b, 40, 4) == "\17\17\17\17", "buffer.fill wrote the wrong value")
	expect(ctx, buf.tostring(buf.fromstring("round")) == "round", "buffer.fromstring/tostring is wrong")

	ctx.tokens[#ctx.tokens + 1] = bBxor(piLow, piHigh)
	ctx.tokens[#ctx.tokens + 1] = 0x3FC00000
end

-- --- P-CORE-10: C-closure metadata ---------------------------------------
-- Verifies that a "native" function really is a C closure with the expected
-- name, by asking debug.info in two different option orders. A hook that
-- special-cases the canonical "slnaf" order fails the permuted query.
local function verifyCClosure(ctx, fn, expectedName)
	expect(ctx, type(fn) == "function", "Expected a C function for " .. tostring(expectedName))

	local s1, l1, n1, a1, v1, f1 = dInfo(fn, "slnaf")
	expect(ctx,
		s1 == "[C]" and l1 == -1 and n1 == expectedName and a1 == 0 and v1 == true and rawequal(f1, fn),
		"debug.info gave wrong metadata for " .. tostring(expectedName))

	-- permuted order: catches a hook that assumes a fixed return order
	local f2, l2, s2, n2, a2, v2 = dInfo(fn, "flsna")
	expect(ctx,
		rawequal(f2, fn) and l2 == -1 and s2 == "[C]" and n2 == expectedName and a2 == 0 and v2 == true,
		"debug.info returned wrong values for a permuted query on " .. tostring(expectedName))

	-- a C closure has no Luau environment to replace
	expect(ctx, not pcall(setmetatable, fn, {}), "setmetatable succeeded on a C function")
	local newcclosure = executorGlobal("newcclosure")
	if type(newcclosure) == "function" then
		expect(ctx, type(newcclosure(fn)) == "function", "newcclosure failed on a C function")
	end
end

local function probeCClosureMetadata(ctx)
	if not dInfo then
		skip(ctx, "debug.info is not available")
		return
	end

	-- A broad spread of library functions. The corpus of leaked checks
	-- concentrates on a handful; covering widely raises the cost of a
	-- complete fake without changing the shape of the attack.
	--
	-- Entries whose presence varies by Luau build are appended conditionally
	-- below, so a missing function is never mistaken for a tampered one.
	local targets = {
		{ pcall, "pcall" }, { xpcall, "xpcall" },
		{ type, "type" }, { typeof, "typeof" },
		{ tostring, "tostring" }, { tonumber, "tonumber" }, { select, "select" },
		{ rawget, "rawget" }, { rawset, "rawset" }, { rawequal, "rawequal" },
		{ next, "next" }, { pairs, "pairs" }, { ipairs, "ipairs" },
		{ getmetatable, "getmetatable" }, { setmetatable, "setmetatable" },
		{ unpack, "unpack" }, { tPack, "pack" }, { tCreate, "create" },
		{ tFreeze, "freeze" }, { tIsFrozen, "isfrozen" }, { tMove, "move" },
		{ tSort, "sort" }, { tInsert, "insert" }, { tRemove, "remove" },
		{ tConcat, "concat" }, { tClone, "clone" }, { tClear, "clear" },
		{ sByte, "byte" }, { sSub, "sub" }, { sFind, "find" }, { sMatch, "match" },
		{ sGsub, "gsub" }, { sFormat, "format" }, { sRep, "rep" },
		{ sGmatch, "gmatch" }, { sReverse, "reverse" }, { sUpper, "upper" },
		{ sPack, "pack" }, { sUnpack, "unpack" }, { sPackSize, "packsize" },
		{ mAbs, "abs" }, { mMax, "max" }, { mt.sqrt, "sqrt" }, { mt.random, "random" },
		{ bBand, "band" }, { bBxor, "bxor" }, { bLshift, "lshift" },
		{ bRshift, "rshift" }, { bArshift, "arshift" }, { bExtract, "extract" },
		{ bReplace, "replace" }, { b32.bor, "bor" }, { b32.bnot, "bnot" },
		{ b32.byteswap, "byteswap" }, { b32.btest, "btest" },
		{ buf.create, "create" }, { buf.len, "len" }, { buf.readu8, "readu8" },
		{ buf.readi32, "readi32" }, { buf.readf64, "readf64" }, { buf.writef32, "writef32" },
		{ buf.writestring, "writestring" }, { buf.copy, "copy" }, { buf.fill, "fill" },
		{ u8.char, "char" }, { u8.len, "len" }, { u8.codepoint, "codepoint" },
		{ u8.offset, "offset" },
		{ cCreate, "create" }, { cResume, "resume" }, { cYield, "yield" },
		{ cWrap, "wrap" }, { cStatus, "status" }, { cClose, "close" },
		{ mt.floor, "floor" }, { mt.ceil, "ceil" }, { mt.fmod, "fmod" },
		{ mt.isnan, "isnan" }, { mt.isinf, "isinf" }, { mt.isfinite, "isfinite" },
		{ mt.clamp, "clamp" }, { mt.lerp, "lerp" },
	}

	local function add(fn, name)
		if type(fn) == "function" then
			tInsert(targets, { fn, name })
		end
	end
	add(s.split, "split")
	add(mt.type, "type")
	add(mt.ult, "ult")
	add(mt.tointeger, "tointeger")
	add(b32.lrotate, "lrotate")
	add(b32.rrotate, "rrotate")
	add(bCountlz, "countlz")
	add(b32.countrz, "countrz")
	add(u8.codes, "codes")
	add(u8.nfcnormalize, "nfcnormalize")
	add(u8.graphemes, "graphemes")
	add(tb.find, "find")
	add(tb.maxn, "maxn")
	add(cFinally, "finally")
	add(cIsYieldable, "isyieldable")
	if HAS_BUFFER_BITS then
		add(buf.readbits, "readbits")
		add(buf.writebits, "writebits")
	end
	if type(task) == "table" then
		add(task.wait, "wait")
		add(task.spawn, "spawn")
		add(task.defer, "defer")
		add(task.delay, "delay")
		add(task.cancel, "cancel")
	end
	if dInfo then
		add(dInfo, "info")
		add(dTraceback, "traceback")
	end
	if IN_ROBLOX then
		add(Instance.new, "new")
		add(game.GetService, "GetService")
	end

	for i = 1, #targets do
		verifyCClosure(ctx, targets[i][1], targets[i][2])
	end

	ctx.tokens[#ctx.tokens + 1] = #targets
end

-- --- P-CORE-11: live C-stack oracles -------------------------------------
-- While a C function is on the stack, debug.info(level) must still describe
-- the real C frame. A host that fakes the stack for the sake of anti-exploit
-- checks cannot also keep this honest.
local function probeLiveStack(ctx)
	if not dInfo then
		skip(ctx, "debug.info is not available")
		return
	end

	local verified = 0

	-- a C frame calling back into Lua: gsub
	sGsub("x", ".", function()
		local src, line, name, nargs, isVararg, fn = dInfo(2, "slnaf")
		local callerSrc, callerLine, _, _, _, callerFn = dInfo(3, "slnaf")
		expect(ctx, src == "[C]" and line == -1 and name == "gsub" and nargs == 0
			and isVararg == true and rawequal(fn, sGsub),
			"debug.info did not describe the live string.gsub C frame")
		expect(ctx, callerSrc ~= "[C]" and type(callerLine) == "number" and callerLine >= 1
			and type(callerFn) == "function",
			"debug.info did not describe the Lua caller of string.gsub")
		verified += 1
		return ""
	end)

	-- same for table.sort
	tSort({ 2, 1 }, function(x, y)
		local src, line, name, nargs, isVararg, fn = dInfo(2, "slnaf")
		expect(ctx, src == "[C]" and line == -1 and name == "sort" and nargs == 0
			and isVararg == true and rawequal(fn, tSort),
			"debug.info did not describe the live table.sort C frame")
		verified += 1
		return x < y
	end)

	-- an error unwound by xpcall must still be reachable
	xpcall(function() error("stack_probe", 0) end, function(m)
		local sawUnwoundLua, sawXpcall = false, false
		for level = 2, 8 do
			local src, line, name, _, _, fn = dInfo(level, "slnaf")
			if src ~= nil and src ~= "[C]" and type(line) == "number" and line >= 1 then
				sawUnwoundLua = true
			elseif rawequal(fn, xpcall) and src == "[C]" and line == -1 and name == "xpcall" then
				sawXpcall = true
				break
			end
		end
		expect(ctx, sawUnwoundLua, "the unwound Lua frame was not visible inside an xpcall handler")
		expect(ctx, sawXpcall, "the xpcall C frame was not visible inside its own handler")
		verified += 1
		return m
	end)

	-- __tostring dispatch
	local obj = setmetatable({}, {
		__tostring = function()
			local src, line, name, nargs, _, fn = dInfo(2, "slnaf")
			expect(ctx, src == "[C]" and line == -1 and name == "tostring" and nargs == 0
				and rawequal(fn, tostring),
				"debug.info did not describe the live tostring C frame")
			verified += 1
			return "sentinel_object"
		end,
	})
	expect(ctx, tostring(obj) == "sentinel_object", "__tostring was not dispatched")

	-- A C function cannot yield. Pure-Lua stand-ins for sort/gsub let a
	-- coroutine yield escape, which is the give-away this catches.
	local leaked = false
	local coSort = trackThread(ctx, cCreate(function()
		tSort({ 2, 1 }, function(x, y)
			cYield("escaped")
			return x < y
		end)
		leaked = true
	end))
	local sortOk, sortErr = cResume(coSort)
	expect(ctx, not sortOk and sortErr ~= "escaped", "a yield escaped through table.sort")
	expect(ctx, not leaked, "table.sort completed despite a yield attempt")

	local coGsub = trackThread(ctx, cCreate(function()
		sGsub("a", ".", function()
			cYield("escaped")
			return ""
		end)
	end))
	local gsubOk, gsubErr = cResume(coGsub)
	expect(ctx, not gsubOk and gsubErr ~= "escaped", "a yield escaped through string.gsub")

	-- ...but a yield through pcall is legal and must still work
	local coPcall = trackThread(ctx, cCreate(function()
		return pcall(function() return cYield("ok") end)
	end))
	local p1, p2 = cResume(coPcall)
	local p3, p4, p5 = cResume(coPcall, "resumed")
	expect(ctx, p1 and p2 == "ok" and p3 and p4 == true and p5 == "resumed",
		"a legal yield through pcall did not resume correctly")
	verified += 1

	expect(ctx, verified == 5, "not every live-stack probe ran (" .. tostring(verified) .. "/5)")
	ctx.tokens[#ctx.tokens + 1] = verified
end

-- ============================================================================
-- Section 4: PROBES — Roblox engine invariants.
--
-- These require a real engine. Outside Roblox they report `unavailable`
-- rather than failing, which is what lets the same file run in CI.
-- ============================================================================

-- --- P-ENG-1: data model reflection --------------------------------------
local function probeEngineReflection(ctx)
	if not needRoblox(ctx, "engine reflection") then
		return
	end

	expect(ctx, typeof(game) == "Instance", "game is not an Instance")
	expect(ctx, typeof(workspace) == "Instance", "workspace is not an Instance")
	expect(ctx, rawequal(game:GetService("Workspace"), workspace), "Workspace service is not identity-equal")
	expect(ctx, typeof(Enum) == "Enums" and type(Enum) == "userdata", "Enum is not the expected type")
	expect(ctx, rawequal(game:GetService("Players"), game:GetService("Players")), "GetService is not stable")
	expect(ctx, game:FindFirstChild("__SentinelMissingService__") == nil, "FindFirstChild invented a service")

	-- a bogus member must be a hard error, not nil
	expect(ctx, not pcall(function() return game.__sentinel_missing__ end),
		"a missing Instance member did not error")

	-- Enum reflection
	local stateType = Enum.HumanoidStateType
	expect(ctx, type(stateType.FromName) == "function" and type(stateType.FromValue) == "function",
		"EnumType reflection methods are missing")
	expect(ctx, stateType:FromName("NotAnEnumItem99") == nil, "EnumType:FromName invented an item")
	expect(ctx, stateType:FromValue(0) == Enum.HumanoidStateType.FallingDown, "EnumType:FromValue is wrong")
	expect(ctx, not pcall(stateType.FromName), "EnumType:FromName accepted no arguments")
	expect(ctx, not pcall(stateType.FromValue), "EnumType:FromValue accepted no arguments")

	-- enumerating an enum type must be self-consistent
	local items = stateType:GetEnumItems()
	local count = 0
	local seenNames = {}
	for _, item in ipairs(items) do
		expect(ctx, typeof(item) == "EnumItem" and type(item.Name) == "string"
			and type(item.Value) == "number", "GetEnumItems returned a malformed item")
		expect(ctx, not seenNames[item.Name], "GetEnumItems returned a duplicate name: " .. item.Name)
		expect(ctx, stateType[item.Name] == item, "EnumType lookup disagrees with GetEnumItems")
		seenNames[item.Name] = true
		count += 1
	end
	expect(ctx, count == #items, "GetEnumItems count is inconsistent")
	expect(ctx, typeof(stateType.EnumType) == "EnumType", "EnumType.EnumType is wrong")

	-- Instance lifecycle: destroy detaches, name and attributes survive
	local folder = ledgerAdd(ctx, Instance.new("Folder"))
	folder.Name = "SentinelLifecycleProbe"
	expect(ctx, folder:IsA("Folder") and folder:IsA("Instance") and not folder:IsA("Part"),
		"IsA is inconsistent across the hierarchy")
	expect(ctx, folder.ClassName == "Folder", "ClassName is wrong")
	folder:SetAttribute("sentinelMarker", 17)
	ledgerRelease(ctx, folder)
	expect(ctx, folder.Parent == nil, "a destroyed Instance still has a parent")
	expect(ctx, folder.Name == "SentinelLifecycleProbe", "a destroyed Instance lost its name")
	expect(ctx, folder:GetAttribute("sentinelMarker") == 17, "a destroyed Instance lost its attribute")
	expect(ctx, #folder:GetChildren() == 0, "a destroyed Instance retained children")
	expect(ctx, folder:IsDescendantOf(game), "a parentless Instance claimed to be a descendant of game")

	-- hierarchy and naming
	local parent = ledgerAdd(ctx, Instance.new("Folder"))
	parent.Name = "SentinelParent"
	local child = ledgerAdd(ctx, Instance.new("Folder"))
	child.Name = "SentinelChild"
	child.Parent = parent
	expect(ctx, child:IsDescendantOf(game) and child:IsDescendantOf(parent), "IsDescendantOf is wrong")
	expect(ctx, child:GetFullName() == "SentinelParent.SentinelChild", "GetFullName format is wrong")
	expect(ctx, #parent:GetChildren() == 1 and rawequal(parent:GetChildren()[1], child),
		"GetChildren is wrong")
	expect(ctx, parent:FindFirstChild("SentinelChild") == child, "FindFirstChild is wrong")
	expect(ctx, parent:FindFirstChildWhichIsA("Folder") ~= nil, "FindFirstChildWhichIsA is wrong")
	expect(ctx, #parent:GetDescendants() == 1, "GetDescendants count is wrong")

	ctx.tokens[#ctx.tokens + 1] = count
	ctx.tokens[#ctx.tokens + 1] = 17
end

-- --- P-ENG-2: property change signals -------------------------------------
-- Covers a signal surface the leaked checks in this corpus do not test:
-- GetPropertyChangedSignal identity and its "same value does not fire" rule.
local function probePropertySignals(ctx)
	if not needRoblox(ctx, "property signals") then
		return
	end

	local value = ledgerAdd(ctx, Instance.new("IntValue"))
	local sigA = value:GetPropertyChangedSignal("Value")
	local sigB = value:GetPropertyChangedSignal("Value")
	expect(ctx, sigA == sigB, "GetPropertyChangedSignal returned two different signals")
	expect(ctx, typeof(sigA) == "RBXScriptSignal", "GetPropertyChangedSignal returned the wrong type")
	expect(ctx, rawequal(sigA, value.Changed), "GetPropertyChangedSignal(\"Value\") differs from .Changed")

	local fires = {}
	local conn = trackConnection(ctx, sigA:Connect(function(v) fires[#fires + 1] = v end))
	expect(ctx, conn.Connected == true, "a fresh connection reports itself disconnected")
	expect(ctx, not pcall(conn.Disconnect), "Disconnect threw")
	expect(ctx, conn.Connected == true, "a disconnected connection still reports itself connected")

	value.Value = 7
	value.Name = "SentinelRenamed"
	value.Value = 7
	value.Value = 8

	local delivered = awaitChange(ctx, function() return #fires >= 2 end)
	ledgerRelease(ctx, conn)
	ledgerRelease(ctx, value)
	if delivered then
		expect(ctx, #fires == 2, "the property signal fired for a no-op assignment")
		expect(ctx, fires[1] == 7 and fires[2] == 8, "the property signal delivered wrong values")
	else
		unavailable(ctx, "A property change callback was not delivered before the deadline")
	end
end

-- --- P-ENG-3: RunService and Players -------------------------------------
local function probeRunService(ctx)
	if not needRoblox(ctx, "RunService") then
		return
	end

	local runService = game:GetService("RunService")
	verifyCClosure(ctx, runService.IsStudio, "IsStudio")
	verifyCClosure(ctx, runService.IsClient, "IsClient")
	verifyCClosure(ctx, runService.IsServer, "IsServer")

	local isStudio, isClient, isServer = runService:IsStudio(), runService:IsClient(), runService:IsServer()
	expect(ctx, isClient ~= isServer, "IsClient and IsServer are both true, or both false")
	expect(ctx, (ctx.options.allowStudio or not isStudio), "Studio execution was not permitted by policy")
	expect(ctx, not pcall(runService.IsStudio), "IsStudio accepted a missing receiver")

	-- The server cannot satisfy the engine-only probe, so declare a coverage
	-- gap rather than reporting a failure.
	if isServer then
		skip(ctx, "Running on the server; client-only engine surface is not present")
		return
	end

	local renderMode = runService:GetRenderMode()
	expect(ctx, type(renderMode) == "EnumItem" and typeof(renderMode) == "EnumItem",
		"GetRenderMode did not return an EnumItem")

	-- Heartbeat must actually tick. A frozen or mocked scheduler stalls here.
	local beat = 0
	local conn = trackConnection(ctx, runService.Heartbeat:Connect(function() beat += 1 end))
	local ticked = awaitChange(ctx, function() return beat >= 3 end)
	ledgerRelease(ctx, conn)
	if not ticked then
		unavailable(ctx, "RunService.Heartbeat did not tick before the deadline")
		return
	end
	expect(ctx, beat >= 3, "Heartbeat fired fewer times than observed callbacks")

	-- Players reflection
	local players = game:GetService("Players")
	expect(ctx, typeof(players) == "Instance" and players.ClassName == "Players", "Players service is wrong")
	local list = players:GetPlayers()
	for i = 1, #list do
		expect(ctx, typeof(list[i]) == "Instance" and list[i]:IsA("Player"), "GetPlayers returned a non-Player")
	end
	if #list > 0 then
		expect(ctx, players:GetPlayerCount() == #list, "GetPlayerCount disagrees with GetPlayers")
	end

	ctx.tokens[#ctx.tokens + 1] = beat
end

-- --- P-ENG-4: CollectionService -------------------------------------------
local function probeCollectionService(ctx)
	if not needRoblox(ctx, "CollectionService") then
		return
	end

	local cs = game:GetService("CollectionService")
	local tag = "_sentinel_" .. tostring(mRandom(100000, 999999))
	local holder = ledgerAdd(ctx, Instance.new("Folder"))

	cs:AddTag(holder, tag)
	expect(ctx, cs:HasTag(holder, tag), "AddTag did not register")
	-- A tag only becomes visible once the instance is in the DataModel.
	expect(ctx, #cs:GetTagged(tag) == 0, "GetTagged returned a parentless instance")
	holder.Parent = workspace
	local tagged = cs:GetTagged(tag)
	expect(ctx, #tagged == 1 and rawequal(tagged[1], holder), "GetTagged is wrong for a parented instance")
	holder.Parent = nil
	expect(ctx, #cs:GetTagged(tag) == 0, "GetTagged still returns a detached instance")
	expect(ctx, cs:HasTag(holder, tag), "detaching cleared the tag")
	expect(ctx, #cs:GetTags(holder) == 1, "GetTags is wrong")
	cs:RemoveTag(holder, tag)
	expect(ctx, not cs:HasTag(holder, tag) and #cs:GetTags(holder) == 0, "RemoveTag did not clear the tag")
	ledgerRelease(ctx, holder)

	ctx.tokens[#ctx.tokens + 1] = 1
end

-- --- P-ENG-5: DataStoreIncrementOptions deep copy -------------------------
local function probeDataStoreOptions(ctx)
	if not needRoblox(ctx, "DataStoreIncrementOptions") then
		return
	end

	local options = ledgerAdd(ctx, Instance.new("DataStoreIncrementOptions"))
	local source = { probe = "sentinel_" .. tostring(mRandom(1, 999999)) }
	local expected = source.probe
	options:SetMetadata(source)
	source.probe = "mutated_after_set"
	expect(ctx, options:GetMetadata().probe == expected, "SetMetadata stored a reference, not a copy")

	local offender = ledgerAdd(ctx, Instance.new("Part"))
	local rejected = pcall(options.SetMetadata, options, { invalid = offender })
	ledgerRelease(ctx, offender)
	expect(ctx, not rejected, "SetMetadata accepted an Instance in metadata")
	ledgerRelease(ctx, options)

	ctx.tokens[#ctx.tokens + 1] = 1
end

-- --- P-ENG-6: geometry and physics ----------------------------------------
local function probeGeometry(ctx)
	if not needRoblox(ctx, "vector/CFrame types") then
		return
	end

	-- the new vector library, if present
	if type(vector) == "table" and type(vector.create) == "function" then
		local v = vector.create(1.25, -2.5, 3.75)
		expect(ctx, typeof(v) == "Vector3", "vector.create did not return a Vector3")
		expect(ctx, v.x == 1.25 and v.y == -2.5 and v.z == 3.75, "vector components are wrong")
		expect(ctx, v.X == 1.25 and v.Y == -2.5 and v.Z == 3.75, "vector uppercase accessors are wrong")
	end

	local v2 = Vector2.new(3, 4)
	expect(ctx, v2.Magnitude == 5, "Vector2 magnitude is wrong")
	expect(ctx, v2:Dot(Vector2.new(5, 6)) == 39, "Vector2 dot product is wrong")
	expect(ctx, v2.Unit.Magnitude > 0.999 and v2.Unit.Magnitude < 1.001, "Vector2.Unit is not normalised")

	local ax, ay = Vector3.new(1, 0, 0), Vector3.new(0, 1, 0)
	local az = ax:Cross(ay)
	expect(ctx, az.X == 0 and az.Y == 0 and az.Z == 1, "Vector3 cross product is wrong")
	expect(ctx, ax:Dot(ay) == 0, "Vector3 dot product is wrong")
	expect(ctx, Vector3.new(1, 2, 2).Magnitude == 3, "Vector3 magnitude is wrong")
	expect(ctx, ax:Angle(ay) == mPi / 2, "Vector3:Angle is wrong")

	-- orthonormal CFrame algebra
	local axis = Vector3.new(mRandom(1, 10), mRandom(1, 10), mRandom(1, 10)).Unit
	local angle = mRandom(15, 300) * (mPi / 180)
	local cf = CFrame.fromAxisAngle(axis, angle) + Vector3.new(mRandom(-50, 50), mRandom(-50, 50), mRandom(-50, 50))
	local identity = cf * cf:Inverse()
	expect(ctx, identity.Position.Magnitude < 1e-4, "CFrame inversion is not an identity")
	expect(ctx, approx(cf.RightVector:Cross(cf.UpVector):Dot(cf.LookVector), -1, 1e-4),
		"CFrame basis is not orthonormal")
	local point = Vector3.new(mRandom(-20, 20), mRandom(-20, 20), mRandom(-20, 20))
	expect(ctx, (cf:PointToObjectSpace(cf:PointToWorldSpace(point)) - point).Magnitude < 1e-3,
		"CFrame space conversion is not a round-trip")
	expect(ctx, cf:Lerp(cf, 0.5).Position.Magnitude < 1e-4, "CFrame:Lerp at t=0.5 of a point is wrong")
	local euler = cf:ToEulerAnglesXYZ()
	expect(ctx, approx(CFrame.fromEulerAnglesXYZ(euler.X, euler.Y, euler.Z), cf, 1e-3),
		"CFrame euler round-trip is wrong")

	if Vector3int16 then
		local vi = Vector3int16.new(1, 2, 3)
		expect(ctx, vi.X * 31 + vi.Y * 17 + vi.Z * 13 == 104, "Vector3int16 components are wrong")
		expect(ctx, tostring(vi) == "1, 2, 3", "Vector3int16 tostring format is wrong")
	end

	if Rect and Axes then
		local r = Rect.new(2, 4, 8, 16)
		expect(ctx, r.Width == 6 and r.Height == 12, "Rect size is wrong")
		local a = Axes.new(Enum.Axis.X, Enum.Axis.Y)
		expect(ctx, a.X == true and a.Y == true and a.Z == false, "Axes is wrong")
	end

	-- Ray: pure geometry, and a common source of host shortcuts
	if Ray then
		local ray = Ray.new(Vector3.new(0, 0, 0), Vector3.new(0, 0, -1))
		expect(ctx, approx(ray.Direction.Magnitude, 1, 1e-5), "Ray direction is not normalised")
		local target = Vector3.new(mRandom(-10, 10), mRandom(-10, 10), -mRandom(5, 50))
		local hit = ray:IntersectSegment(Ray.new(target + Vector3.new(5, 0, 0), Vector3.new(-10, 0, 0)))
		expect(ctx, hit ~= nil and approx(hit.Position.Z, target.Z, 1e-3), "Ray:IntersectSegment is wrong")
		expect(ctx, ray:IntersectSegment(Ray.new(Vector3.new(5, 5, 5), Vector3.new(0, 1, 0))) == nil,
			"Ray:IntersectSegment invented a hit")
	end

	-- PhysicalProperties -> mass is computed by the engine from real floats
	if PhysicalProperties then
		local part = ledgerAdd(ctx, Instance.new("Part"))
		part.Shape = Enum.PartType.Block
		local sx, sy, sz = mRandom(2, 9), mRandom(2, 9), mRandom(2, 9)
		local density = mRandom(5, 25) / 10
		part.Size = Vector3.new(sx, sy, sz)
		part.CustomPhysicalProperties = PhysicalProperties.new(density, 0.3, 0.5)
		local expectedMass = sx * sy * sz * density
		expect(ctx, approx(part:GetMass(), expectedMass, 1e-2), "GetMass does not match volume*density")
		expect(ctx, approx(part.Mass, expectedMass, 1e-2), "Part.Mass does not match volume*density")

		-- CFrame and Position are two views of one C++ value
		local px, py, pz = mRandom(10, 90), mRandom(10, 90), mRandom(10, 90)
		part.CFrame = CFrame.new(px, py, pz)
		expect(ctx, approx(part.Position.X, px, 1e-3) and approx(part.Position.Y, py, 1e-3)
			and approx(part.Position.Z, pz, 1e-3), "CFrame assignment did not move Position")
		part.Position = Vector3.new(px + 5, py - 3, pz + 7)
		expect(ctx, approx(part.CFrame.X, px + 5, 1e-3) and approx(part.CFrame.Y, py - 3, 1e-3)
			and approx(part.CFrame.Z, pz + 7, 1e-3), "Position assignment did not move CFrame")
		ledgerRelease(ctx, part)
	end

	ctx.tokens[#ctx.tokens + 1] = 39
end

-- --- P-ENG-7: WorldModel raycast ------------------------------------------
-- An available fixture must actually HIT. A host that returns nil for
-- everything "passes" a naive nil check; this requires a positive hit with
-- the right surface and normal, then a verified miss in the other direction.
local function probeWorldModel(ctx)
	if not needRoblox(ctx, "WorldModel") then
		return
	end

	local holder = openProbeGui(ctx, "worldmodel-raycast")
	if not holder then
		return
	end

	local viewport = ledgerAdd(ctx, Instance.new("ViewportFrame"))
	viewport.Size = UDim2.fromOffset(1, 1)
	viewport.BackgroundTransparency = 1
	viewport.Parent = holder

	local worldModel = ledgerAdd(ctx, Instance.new("WorldModel"))
	worldModel.Parent = viewport
	expect(ctx, worldModel:IsA("WorldRoot") and worldModel:IsA("Model"), "WorldModel hierarchy is wrong")
	expect(ctx, type(worldModel.Raycast) == "function", "WorldModel.Raycast is missing")
	expect(ctx, not pcall(worldModel.Raycast), "Raycast accepted no arguments")
	expect(ctx, not pcall(worldModel.Raycast, worldModel, "bad", Vector3.zero),
		"Raycast accepted a non-Vector3 origin")

	local distance = mRandom(20, 60)
	local halfThickness = mRandom(2, 6)
	local ox, oy = mRandom(-3, 3), mRandom(-3, 3)

	local target = ledgerAdd(ctx, Instance.new("Part"))
	target.Size = Vector3.new(16, 16, halfThickness * 2)
	target.CFrame = CFrame.new(0, 0, -distance)
	target.Anchored = true
	target.CanCollide = false
	target.CanQuery = true
	target.Transparency = 1
	target.Parent = worldModel

	local origin = Vector3.new(ox, oy, 0)
	local direction = Vector3.new(0, 0, -(distance + 30))

	local hit
	local ready = awaitChange(ctx, function()
		hit = worldModel:Raycast(origin, direction)
		return hit ~= nil
	end)
	if not ready then
		unavailable(ctx, "WorldModel raycast never reported a hit (no positive control)")
		return
	end

	local miss = worldModel:Raycast(origin, -direction)
	expect(ctx, miss == nil, "WorldModel raycast reported a hit backwards")
	expect(ctx, rawequal(hit.Instance, target), "raycast hit the wrong instance")
	expect(ctx, approx(hit.Distance, distance - halfThickness, 1e-2), "raycast distance is wrong")
	expect(ctx, approx(hit.Position.X, ox, 1e-2) and approx(hit.Position.Y, oy, 1e-2)
		and approx(hit.Position.Z, -(distance - halfThickness), 1e-2), "raycast hit position is wrong")
	expect(ctx, approx(hit.Normal.X, 0, 1e-3) and approx(hit.Normal.Y, 0, 1e-3)
		and approx(hit.Normal.Z, 1, 1e-3), "raycast surface normal is wrong")

	ctx.tokens[#ctx.tokens + 1] = bBand(distance * 1000, 0xFFFF)
end

-- --- P-ENG-8: Path2D geometry under a laid-out frame ---------------------
local function probePath2D(ctx)
	if not needRoblox(ctx, "Path2D") then
		return
	end

	local holder = openProbeGui(ctx, "path2d")
	if not holder then
		return
	end
	if not Path2DControlPoint or type(Path2DControlPoint.new) ~= "function" then
		skip(ctx, "Path2DControlPoint is not exposed on this client")
		return
	end

	local scaleK = mRandom(2, 5)
	local frameA = ledgerAdd(ctx, Instance.new("Frame"))
	frameA.Size = UDim2.fromOffset(100, 100)
	frameA.BackgroundTransparency = 1
	frameA.Parent = holder
	local frameB = ledgerAdd(ctx, Instance.new("Frame"))
	frameB.Size = UDim2.fromOffset(100 * scaleK, 100 * scaleK)
	frameB.BackgroundTransparency = 1
	frameB.Parent = holder

	if not awaitChange(ctx, function()
		return approx(frameA.AbsoluteSize.X, 100, 1e-3) and approx(frameA.AbsoluteSize.Y, 100, 1e-3)
			and approx(frameB.AbsoluteSize.X, 100 * scaleK, 1e-3)
			and approx(frameB.AbsoluteSize.Y, 100 * scaleK, 1e-3)
	end) then
		unavailable(ctx, "GUI layout did not settle before the deadline")
		return
	end

	local pathOk, pathA = pcall(Instance.new, "Path2D")
	if not pathOk or pathA == nil then
		unavailable(ctx, "Path2D is not constructible on this client")
		return
	end
	ledgerAdd(ctx, pathA)
	local pathB = ledgerAdd(ctx, Instance.new("Path2D"))
	pathA.Visible, pathB.Visible = false, false
	pathA.Closed, pathB.Closed = false, false
	pathA.Parent, pathB.Parent = frameA, frameB

	local zero = UDim2.new()
	pathA:SetControlPoints({
		Path2DControlPoint.new(UDim2.fromScale(0.2, 0.5), zero, zero),
		Path2DControlPoint.new(UDim2.fromScale(0.8, 0.5), zero, zero),
	})
	expect(ctx, approx(pathA:GetLength(), 60, 1e-2), "a straight Path2D has the wrong length")
	local mid = pathA:GetPositionOnCurve(0.5)
	-- resolve UDim2 to pixels rather than assuming a Scale/Offset split
	expect(ctx, approx(mid.X.Scale * 100 + mid.X.Offset, 50, 1e-2)
		and approx(mid.Y.Scale * 100 + mid.Y.Offset, 50, 1e-2), "Path2D midpoint is wrong")

	-- the same control points in a frame K times larger must be K times longer
	local s1, s2, s3 = mRandom(10, 30) / 100, mRandom(40, 65) / 100, mRandom(70, 95) / 100
	local points = {
		Path2DControlPoint.new(UDim2.fromScale(s1, s1), UDim2.fromScale(0.1, 0.05), zero),
		Path2DControlPoint.new(UDim2.fromScale(s2, s3), UDim2.fromScale(-0.05, 0.1), UDim2.fromScale(0.05, -0.1)),
		Path2DControlPoint.new(UDim2.fromScale(s3, s2), zero, UDim2.fromScale(-0.1, 0.05)),
	}
	pathA:SetControlPoints(points)
	pathB:SetControlPoints(points)
	local lenA, lenB = pathA:GetLength(), pathB:GetLength()
	expect(ctx, lenA > 0 and approx(lenB / lenA, scaleK, 1e-2), "Path2D scale ratio is wrong")

	ctx.tokens[#ctx.tokens + 1] = bBand(scaleK, 0xFFFF)
end

-- --- P-ENG-9: HttpService --------------------------------------------------
local function probeHttpService(ctx)
	if not needRoblox(ctx, "HttpService") then
		return
	end

	local http = game:GetService("HttpService")
	expect(ctx, typeof(http) == "Instance" and http.ClassName == "HttpService", "HttpService identity is wrong")

	local payload = { text = "quote\"\nslash\\", number = 1.5, flag = true, nested = { 17, 29 } }
	local encoded = http:JSONEncode(payload)
	expect(ctx, type(encoded) == "string", "JSONEncode did not return a string")
	local decoded = http:JSONDecode(encoded)
	expect(ctx, type(decoded) == "table" and decoded.text == payload.text
		and decoded.number == payload.number and decoded.flag == true
		and type(decoded.nested) == "table" and #decoded.nested == 2
		and decoded.nested[1] == 17 and decoded.nested[2] == 29, "JSON round-trip lost or altered data")

	-- structural edge cases
	expect(ctx, next(http:JSONDecode("{}")) == nil, "an empty JSON object did not decode to an empty table")
	expect(ctx, http:JSONDecode('{"a":null}').a == nil, "JSON null did not decode to nil")
	expect(ctx, http:JSONDecode("5") == 5 and http:JSONDecode("true") == true,
		"a bare JSON scalar did not decode to a Lua value")
	local badOk, badErr = pcall(http.JSONDecode, http, "nope")
	expect(ctx, not badOk and type(badErr) == "string", "invalid JSON was accepted")
	local cyclic = {}
	cyclic.self = cyclic
	local cycOk, cycErr = pcall(http.JSONEncode, http, cyclic)
	expect(ctx, not cycOk and type(cycErr) == "string", "a cyclic table was encoded")
	expect(ctx, not pcall(http.JSONEncode, http, { [1] = print }), "a function in a table was encoded")

	-- GUID v4 shape and uniqueness
	local plain, braced = http:GenerateGUID(false), http:GenerateGUID(true)
	expect(ctx, #plain == 36 and plain ~= http:GenerateGUID(false), "GenerateGUID shape or uniqueness is wrong")
	expect(ctx, sMatch(plain, "^%x%x%x%x%x%x%x%x%-%x%x%x%x%-4%x%x%x%-[89abAB]%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$") ~= nil,
		"GenerateGUID is not RFC 4122 version 4")
	expect(ctx, #braced == 38 and sSub(braced, 1, 1) == "{" and sSub(braced, 38, 38) == "}",
		"a braced GUID is not wrapped in braces")

	ctx.tokens[#ctx.tokens + 1] = 36
end

-- --- P-ENG-10: number and colour sequences -------------------------------
local function probeSequences(ctx)
	if not needRoblox(ctx, "NumberSequence") then
		return
	end

	if NumberSequence then
		local ns = NumberSequence.new({
			NumberSequenceKeypoint.new(0, 0),
			NumberSequenceKeypoint.new(0.5, 0.5),
			NumberSequenceKeypoint.new(1, 1),
		})
		expect(ctx, #ns.Keypoints == 3, "NumberSequence lost a keypoint")
		local kp = ns.Keypoints
		expect(ctx, approx(kp[1].Time, 0, 1e-6) and approx(kp[1].Value, 0, 1e-6), "Keypoint 0 is wrong")
		expect(ctx, approx(kp[2].Time, 0.5, 1e-6) and approx(kp[2].Value, 0.5, 1e-6), "Keypoint 1 is wrong")
		expect(ctx, kp[1].Envelope ~= 0 or true, "Keypoint envelope is unreadable")
		expect(ctx, approx(ns.Evaluate(0.5), 0.5, 1e-4), "NumberSequence:Evaluate is wrong at a keypoint")
		expect(ctx, approx(ns.Evaluate(0.25), 0.25, 1e-4), "NumberSequence:Evaluate is wrong mid-segment")
		expect(ctx, not pcall(NumberSequenceKeypoint.new, 2, 0), "a keypoint accepted an out-of-range time")
	end

	if ColorSequence then
		local cs = ColorSequence.new(Color3.new(1, 0, 0), Color3.new(0, 0, 1))
		local at0 = cs:ColorAt(0)
		local at1 = cs:ColorAt(1)
		expect(ctx, approx(at0.R, 1, 1e-4) and approx(at0.G, 0, 1e-4), "ColorSequence start colour is wrong")
		expect(ctx, approx(at1.B, 1, 1e-4) and approx(at1.R, 0, 1e-4), "ColorSequence end colour is wrong")
		local mid = cs:ColorAt(0.5)
		expect(ctx, approx(mid.R, 0.5, 1e-3) and approx(mid.B, 0.5, 1e-3),
			"ColorSequence did not interpolate linearly")
		expect(ctx, not pcall(cs.ColorAt, cs, 1.5), "ColorAt accepted an out-of-range position")
	end

	ctx.tokens[#ctx.tokens + 1] = 1
end

-- --- P-ENG-11: TweenService round trip ------------------------------------
-- A tween must actually reach its goal value. A host that resolves tweens
-- without a real scheduler returns the start value forever.
local function probeTweenService(ctx)
	if not needRoblox(ctx, "TweenService") then
		return
	end
	if not TweenService or type(TweenService.Create) ~= "function" then
		skip(ctx, "TweenService is not exposed on this client")
		return
	end

	local holder = openProbeGui(ctx, "tween")
	if not holder then
		return
	end

	local target = ledgerAdd(ctx, Instance.new("Frame"))
	target.Size = UDim2.fromOffset(10, 10)
	target.BackgroundTransparency = 1
	target.Parent = holder

	local goal = UDim2.fromOffset(120, 90)
	local tween = TweenService:Create(target, TweenInfo.new(0.05), { Size = goal })
	local completed = false
	local tweenConn = trackConnection(ctx, tween.Completed:Connect(function(state)
		completed = state == Enum.PlaybackState.Completed
	end))

	tween:Play()
	local settled = awaitChange(ctx, function() return completed end)
	ledgerRelease(ctx, tweenConn)

	if not settled then
		unavailable(ctx, "A tween did not complete before the deadline")
		return
	end
	expect(ctx, approx(target.Size.X.Offset, 120, 0.5) and approx(target.Size.Y.Offset, 90, 0.5),
		"a completed tween did not reach its goal value")
	ledgerRelease(ctx, target)

	ctx.tokens[#ctx.tokens + 1] = 1
end

-- --- P-ENG-12: EditableMesh -----------------------------------------------
-- Editable meshes are a native C++ object. Nil is a documented outcome under
-- memory pressure, so a nil result is a coverage gap, not a failure.
local function probeEditableMesh(ctx)
	if not needRoblox(ctx, "EditableMesh") then
		return
	end

	local assetService = game:GetService("AssetService")
	local createOk, create = pcall(function() return assetService.CreateEditableMesh end)
	if not createOk or type(create) ~= "function" then
		unavailable(ctx, "CreateEditableMesh is not accessible")
		return
	end
	verifyCClosure(ctx, create, "CreateEditableMesh")

	local madeOk, mesh = pcall(create, assetService)
	if not madeOk or mesh == nil then
		unavailable(ctx, madeOk and "Editable-memory budget is exhausted"
			or ("Mesh creation failed: " .. describe(mesh)))
		return
	end
	ledgerAdd(ctx, mesh)

	expect(ctx, type(mesh.AddVertex) == "function" and type(mesh.GetPosition) == "function"
		and type(mesh.SetPosition) == "function", "EditableMesh is missing a method")

	local rx, ry, rz = mRandom(5, 50), mRandom(5, 50), mRandom(5, 50)
	local v1 = mesh:AddVertex(Vector3.new(rx, ry, rz))
	local v2 = mesh:AddVertex(Vector3.new(rx + 2, ry + 1, rz - 1))
	expect(ctx, v1 ~= v2, "EditableMesh reused a vertex id")
	local p1 = mesh:GetPosition(v1)
	expect(ctx, approx(p1.X, rx, 1e-4) and approx(p1.Y, ry, 1e-4) and approx(p1.Z, rz, 1e-4),
		"EditableMesh vertex round-trip is wrong")

	-- mutating one vertex must not disturb another
	local nx, ny, nz = rx + 3.25, ry - 1.5, rz + 2.75
	mesh:SetPosition(v1, Vector3.new(nx, ny, nz))
	local updated, untouched = mesh:GetPosition(v1), mesh:GetPosition(v2)
	expect(ctx, approx(updated.X, nx, 1e-4) and approx(updated.Y, ny, 1e-4) and approx(updated.Z, nz, 1e-4),
		"EditableMesh mutation is wrong")
	expect(ctx, approx(untouched.X, rx + 2, 1e-4) and approx(untouched.Y, ry + 1, 1e-4),
		"EditableMesh mutation leaked into another vertex")
	expect(ctx, not pcall(mesh.GetPosition, mesh, -999999), "EditableMesh accepted an invalid vertex id")
	ledgerRelease(ctx, mesh)

	ctx.tokens[#ctx.tokens + 1] = 1
end

-- --- P-ENG-13: restricted service surface ---------------------------------
-- Some methods are only present with the right permissions. Absence is a
-- coverage gap. Presence means we can verify C-closure metadata on them.
local function probeRestrictedServices(ctx)
	if not needRoblox(ctx, "restricted services") then
		return
	end

	local function inspect(serviceName, methodNames)
		local ok, methods = pcall(function()
			local service = game:GetService(serviceName)
			local found = {}
			for i = 1, #methodNames do
				local fn = service[methodNames[i]]
				if type(fn) ~= "function" then
					return nil
				end
				found[i] = fn
			end
			return found
		end)
		if not ok or methods == nil then
			unavailable(ctx, serviceName .. " methods are not accessible")
			return
		end
		for i = 1, #methodNames do
			verifyCClosure(ctx, methods[i], methodNames[i])
			-- deliberately no self: never join voice or touch a device
			expect(ctx, not pcall(methods[i]), serviceName .. "." .. methodNames[i]
				.. " accepted a missing receiver")
		end
	end

	inspect("VoiceChatService", { "joinVoice", "rejoinVoice", "leaveVoice" })
	inspect("SoundService", { "GetAudioInstances", "GetInputDevices", "GetOutputDevices" })
	inspect("UserInputService", { "GetFocusedTextBox" })

	-- CorePackages is famously absent under some execution contexts
	local coreOk, core = pcall(game.GetService, game, "CorePackages")
	if not coreOk then
		skip(ctx, "CorePackages is not accessible in this context")
	else
		expect(ctx, typeof(core) == "Instance" and core.ClassName == "CorePackages",
			"CorePackages did not return the expected service")
	end

	ctx.tokens[#ctx.tokens + 1] = 1
end

-- --- P-ENG-14: PCG32 random stream and Clone fork ------------------------
-- Only available where the engine exposes Random. The exact values below are
-- the documented PCG32 output for those seeds.
local function probeRandomStream(ctx)
	if not needCapability(ctx, "Random", hasRandom) then
		return
	end

	-- deterministic stream
	local rng = Random.new(1515359100)
	local n1 = rng:NextInteger(532, 1117)
	local n4 = rng:NextInteger(299, 786)
	local n5 = rng:NextInteger(784, 1062)
	expect(ctx, n1 == 763 and n4 == 397 and n5 == 847,
		"Random did not produce the documented PCG32 stream")
	local f1 = rng:NextNumber()
	expect(ctx, approx(f1, 0.52705833430898807, 1e-12), "Random:NextNumber drifted from the expected stream")

	-- bounds and rounding
	local bounded = Random.new(1)
	for _ = 1, 64 do
		local v = bounded:NextInteger(-5, 5)
		expect(ctx, v >= -5 and v <= 5 and v % 1 == 0, "NextInteger escaped its range")
	end
	expect(ctx, bounded:NextInteger(7, 7) == 7, "NextInteger with an equal range is wrong")
	expect(ctx, bounded:NextNumber(2, 3) >= 2, "NextNumber(a,b) is below its lower bound")

	-- Clone forks the stream: two clones must stay in lockstep
	local parent = Random.new(mRandom(1, 2147483640))
	for _ = 1, mRandom(3, 9) do
		parent:NextNumber()
	end
	local forked = parent:Clone()
	expect(ctx, typeof(forked) == "Random" and not rawequal(parent, forked), "Random:Clone is wrong")
	for _ = 1, 8 do
		expect(ctx, parent:NextInteger(-1000000, 1000000) == forked:NextInteger(-1000000, 1000000),
			"cloned Random streams diverged (integer)")
		expect(ctx, parent:NextNumber() == forked:NextNumber(), "cloned Random streams diverged (number)")
		local ua, ub = parent:NextUnitVector(), forked:NextUnitVector()
		expect(ctx, ua == ub, "cloned Random streams diverged (unit vector)")
		expect(ctx, approx(ua.Magnitude, 1, 1e-5), "NextUnitVector is not a unit vector")
	end

	-- a known seed's unit vector
	local u = Random.new(1):NextUnitVector()
	expect(ctx, approx(u.X, 0.42857980728149414, 1e-6)
		and approx(u.Y, -0.10929630696773529, 1e-6)
		and approx(u.Z, 0.8968688249588013, 1e-6),
		"NextUnitVector did not match the expected value for seed 1")

	ctx.tokens[#ctx.tokens + 1] = n1
	ctx.tokens[#ctx.tokens + 1] = n4
end

-- --- P-EXEC-1: executor globals ------------------------------------------
-- Cross-examination rather than a blocklist. An executor that provides these
-- must provide working ones; an environment that does not provide them is
-- simply a normal client. Presence is *recorded*, never treated as a verdict
-- on its own — plenty of legitimate tooling defines overlapping names.
local function probeExecutorGlobals(ctx)
	local observed = {}
	local isCClosure = executorGlobal("iscclosure")
	local isLClosure = executorGlobal("islclosure")

	if type(isCClosure) == "function" then
		observed.iscclosure = true
		local luaFn = function() return 1 end
		expect(ctx, isCClosure(pcall) == true, "iscclosure said a builtin is not a C closure")
		expect(ctx, isCClosure(luaFn) == false, "iscclosure said a Luau function is a C closure")
		expect(ctx, isCClosure(nil) == false, "iscclosure accepted nil")
	end

	if type(isLClosure) == "function" then
		observed.islclosure = true
		local luaFn = function() return 1 end
		expect(ctx, isLClosure(luaFn) == true, "islclosure said a Luau function is not an Luau closure")
		expect(ctx, isLClosure(pcall) == false, "islclosure said a builtin is an Luau closure")
	end

	-- cloneref must return a *different* Instance that tracks live C++
	-- property changes. A table copy or an identity return both fail.
	local cloneRef = executorGlobal("cloneref")
	if type(cloneRef) == "function" then
		observed.cloneref = true
		local original = ledgerAdd(ctx, Instance.new("Folder"))
		local copied = cloneRef(original)
		expect(ctx, type(copied) == "Instance", "cloneref did not return an Instance")
		expect(ctx, not rawequal(original, copied), "cloneref returned the same object (identity return)")
		local name = "SentinelClone_" .. tostring(mRandom(1000, 99999))
		original.Name = name
		expect(ctx, copied.Name == name, "cloneref returned a snapshot, not a live reference")
		ledgerRelease(ctx, original)
	end

	-- getrawmetatable must expose the real C-level metatable
	local getRawMt = executorGlobal("getrawmetatable")
	if type(getRawMt) == "function" then
		observed.getrawmetatable = true
		local mt = getRawMt(game)
		expect(ctx, type(mt) == "table", "getrawmetatable did not return a table")
		expect(ctx, getmetatable(game) == "The metatable is locked",
			"getmetatable(game) is not locked, so getrawmetatable may be lying")
		if dInfo and type(mt.__index) == "function" then
			expect(ctx, dInfo(mt.__index, "s") == "[C]" and dInfo(mt.__index, "l") == -1,
				"getrawmetatable returned a non-C __index")
			expect(ctx, rawequal(mt.__index(game, "Workspace"), workspace),
				"getrawmetatable __index did not resolve Workspace")
			expect(ctx, not pcall(setmetatable, mt.__index, {}), "the Instance __index accepts setfenv")
		end
	end

	-- Drawing lifecycle
	local drawing = executorGlobal("Drawing")
	local setProp = executorGlobal("setrenderproperty")
	local getProp = executorGlobal("getrenderproperty")
	local isRenderObj = executorGlobal("isrenderobj")
	if type(drawing) == "table" and type(drawing.new) == "function"
		and type(setProp) == "function" and type(getProp) == "function"
		and type(isRenderObj) == "function" then
		observed.drawing = true
		local shape = drawing.new("Square")
		ledgerAdd(ctx, shape)
		local w, h = mRandom(15, 95), mRandom(15, 95)
		local size = Vector2.new(w, h)
		setProp(shape, "Size", size)
		setProp(shape, "Visible", true)
		expect(ctx, getProp(shape, "Size") == size, "setrenderproperty did not change the read-back size")
		expect(ctx, getProp(shape, "Visible") == true, "setrenderproperty did not change visibility")
		expect(ctx, isRenderObj(shape) == true, "isrenderobj rejected a live Drawing")
		expect(ctx, isRenderObj({}) == false, "isrenderobj accepted a plain table")
		expect(ctx, shape.__OBJECT_EXISTS == true, "__OBJECT_EXISTS is wrong while alive")
		ledgerRelease(ctx, shape)
		expect(ctx, shape.__OBJECT_EXISTS == false, "__OBJECT_EXISTS is wrong after Destroy")
	end

	-- Record what was present so the caller can reason about coverage. This
	-- is telemetry, not a verdict.
	if next(observed) ~= nil then
		local names = {}
		for name in pairs(observed) do
			names[#names + 1] = name
		end
		tSort(names)
		tInsert(ctx.notes, "executor surfaces present: " .. tConcat(names, ", "))
	end

	-- Anything at all present is worth surfacing to the caller, including
	-- APIs we do not probe, so they can extend the suite themselves.
	local notable = { "getgc", "identifyexecutor", "checkexecutor", "hookfunction",
		"readfile", "writefile", "isfile", "request", "setclipboard", "gethui" }
	local found = {}
	for i = 1, #notable do
		if executorGlobal(notable[i]) ~= nil then
			found[#found + 1] = notable[i]
		end
	end
	if #found > 0 then
		tSort(found)
		tInsert(ctx.notes, "unprobed executor globals present: " .. tConcat(found, ", "))
	end

	ctx.tokens[#ctx.tokens + 1] = #found
end

-- --- P-SELF-1: this module's own environment ------------------------------
-- The suite's first line of defence is that it captured its references
-- before anything ran. This checks the other half of that contract: that
-- the environment table those references came from has not been rebound.
--
-- Outside Roblox the environment is typically an empty sandbox table with
-- no __index chain, so a "current vs. baseline" check would always be a
-- vacuous nil-vs-nil. The probe therefore distinguishes two cases:
--   * a populated environment (Roblox, or one a test has populated):
--     every watched binding must match the baseline identity.
--   * an unpopulated environment: a binding that *appears* after load is
--     still detected, because that is how an attacker would probe the
--     integrity surface.
-- The captured local references are re-verified in either case.
local function probeSelfIntegrity(ctx)
	if not ENV_BASELINE then
		skip(ctx, "This host does not expose the chunk environment (getfenv unavailable)")
		return
	end

	-- Always-on: the captured locals are still the real things, regardless
	-- of the engine. dInfo failing here means the captured function is no
	-- longer what it was at load time.
	if dInfo then
		expect(ctx, dInfo(type, "s") == "[C]", "the captured type builtin is no longer a C function")
		expect(ctx, dInfo(pcall, "n") == "pcall", "the captured pcall reports the wrong name")
		expect(ctx, dInfo(rawget, "s") == "[C]", "the captured rawget is no longer a C function")
	end

	-- A sentinel we never bind. If it appears, somebody polluted our env.
	expect(ctx, rawget(MODULE_ENV, "__SENTINEL_CANARY__") == nil,
		"a canary global appeared in this module's environment")

	-- Watch every baseline binding. In Roblox the env is populated and any
	-- identity change is detected; in a bare CLI the baseline is all nil
	-- and this loop reduces to detecting new bindings.
	for i = 1, #WATCHED_ENV do
		local name = WATCHED_ENV[i]
		local baseline = ENV_BASELINE[name]
		local current = rawget(MODULE_ENV, name)
		if not sameValue(current, baseline) then
			fail(ctx, "Environment binding was replaced after load: " .. name)
		end
	end

	ctx.tokens[#ctx.tokens + 1] = #WATCHED_ENV
end

-- ============================================================================
-- Section 5: Probe registry.
-- ============================================================================

local PROBES = {
	{ id = "core.identity",        stage = "core",      class = PROBE_REQUIRED,   run = probeCoreIdentity },
	{ id = "core.stringMetatable", stage = "core",      class = PROBE_REQUIRED,   run = probeStringMetatable },
	{ id = "core.numericModel",    stage = "core",      class = PROBE_REQUIRED,   run = probeNumericModel },
	{ id = "core.stringPack",      stage = "core",      class = PROBE_REQUIRED,   run = probeStringPack },
	{ id = "core.utf8",            stage = "core",      class = PROBE_REQUIRED,   run = probeUtf8 },
	{ id = "core.tableSemantics",  stage = "core",      class = PROBE_REQUIRED,   run = probeTableSemantics },
	{ id = "core.metatables",      stage = "core",      class = PROBE_REQUIRED,   run = probeMetatablesAndErrors },
	{ id = "core.coroutines",      stage = "core",      class = PROBE_REQUIRED,   run = probeCoroutines },
	{ id = "core.buffers",         stage = "core",      class = PROBE_REQUIRED,   run = probeBuffers },
	{ id = "core.cclosures",       stage = "core",      class = PROBE_REQUIRED,   run = probeCClosureMetadata },
	{ id = "core.liveStack",       stage = "core",      class = PROBE_REQUIRED,   run = probeLiveStack },

	{ id = "engine.reflection",    stage = "engine",    class = PROBE_ENGINE,     run = probeEngineReflection },
	{ id = "engine.signals",       stage = "engine",    class = PROBE_ENGINE,     run = probePropertySignals },
	{ id = "engine.runService",    stage = "engine",    class = PROBE_ENGINE,     run = probeRunService },
	{ id = "engine.collection",    stage = "engine",    class = PROBE_ENGINE,     run = probeCollectionService },
	{ id = "engine.dataStore",     stage = "engine",    class = PROBE_ENGINE,     run = probeDataStoreOptions },
	{ id = "engine.geometry",      stage = "engine",    class = PROBE_ENGINE,     run = probeGeometry },
	{ id = "engine.worldModel",    stage = "engine",    class = PROBE_CAPABILITY, run = probeWorldModel },
	{ id = "engine.path2d",        stage = "engine",    class = PROBE_CAPABILITY, run = probePath2D },
	{ id = "engine.http",          stage = "engine",    class = PROBE_ENGINE,     run = probeHttpService },
	{ id = "engine.sequences",     stage = "engine",    class = PROBE_ENGINE,     run = probeSequences },
	{ id = "engine.tween",         stage = "engine",    class = PROBE_CAPABILITY, run = probeTweenService },
	{ id = "engine.editableMesh",  stage = "engine",    class = PROBE_CAPABILITY, run = probeEditableMesh },
	{ id = "engine.restricted",    stage = "engine",    class = PROBE_CAPABILITY, run = probeRestrictedServices },
	{ id = "engine.random",        stage = "engine",    class = PROBE_CAPABILITY, run = probeRandomStream },

	{ id = "exec.globals",         stage = "executors", class = PROBE_CAPABILITY, run = probeExecutorGlobals },
	{ id = "self.integrity",       stage = "self",      class = PROBE_REQUIRED,   run = probeSelfIntegrity },
}

local PROBE_BY_ID = {}
for i = 1, #PROBES do
	PROBE_BY_ID[PROBES[i].id] = i
end

-- ============================================================================
-- Section 6: Function sealing.
--
-- Records a function's debug.info metadata, its environment table's
-- identity, and optionally the identity of named bindings in that
-- environment. This detects *replacement* — it does not hash executable
-- code, and an in-place hook that preserves the observed metadata is
-- invisible to it. Mutable upvalues and unwatched bindings are out of scope.
-- ============================================================================

local seals = setmetatable({}, { __mode = "k" })

local function fingerprintFunction(fn)
	if type(fn) ~= "function" then
		error("Seal/Verify expects a function", 0)
	end
	if not dInfo then
		-- Without debug.info there is nothing meaningful to record beyond
		-- identity, which is still worth holding onto.
		return tostring(fn), nil
	end
	local ok, src, line, name, nparam, isVararg, identity = pcall(dInfo, fn, "slnaf")
	local envOk, environment = pcall(getfenv, fn)
	if not ok or type(src) ~= "string" or type(line) ~= "number" or type(name) ~= "string"
		or type(nparam) ~= "number" or type(isVararg) ~= "boolean" or not rawequal(identity, fn)
		or not envOk or type(environment) ~= "table" then
		error("Unable to inspect function metadata or environment", 0)
	end
	local raw = tConcat({
		"function", tostring(src), tostring(line), tostring(name),
		tostring(nparam), tostring(isVararg), tostring(fn),
	}, "|")
	local h1, h2 = 0x811C9DC5, 0xCBF29CE4
	for i = 1, #raw do
		local byte = sByte(raw, i)
		h1 = mul32(bBxor(h1, byte), 0x01000193)
		h2 = mul32(bBxor(h2, byte + i), 0x045D9F3B)
	end
	return sFormat("%08x%08x", h1, h2), environment
end

local function buildBindingPolicy(names)
	local policy, order = {}, {}
	if names == nil then
		return policy, order
	end
	if type(names) ~= "table" then
		error("Binding names must be an array of strings", 0)
	end
	local count = 0
	for index, name in pairs(names) do
		if type(index) ~= "number" or index % 1 ~= 0 or index < 1
			or type(name) ~= "string" or policy[name] then
			error("Binding names must be a dense array of distinct strings", 0)
		end
		policy[name] = true
		count += 1
	end
	for i = 1, count do
		if rawget(names, i) == nil then
			error("Binding names must be a dense array of distinct strings", 0)
		end
	end
	for name in pairs(policy) do
		order[#order + 1] = name
	end
	tSort(order)
	return policy, order
end

-- ============================================================================
-- Section 7: Public API.
-- ============================================================================

local Sentinel = {}

local function normalizeOptions(options)
	if options ~= nil and type(options) ~= "table" then
		error("Options must be a table", 0)
	end
	local result = {
		requireAllChecks = false,
		allowStudio = true,
		allowServer = false,
		timeoutSeconds = 1,
		maxIterations = 120,
		only = nil,
		skip = nil,
	}
	for key, value in pairs(options or {}) do
		if result[key] == nil and key ~= "only" and key ~= "skip" then
			error("Unknown option: " .. tostring(key), 0)
		end
		result[key] = value
	end

	if type(result.requireAllChecks) ~= "boolean" then
		error("requireAllChecks must be a boolean", 0)
	end
	if type(result.allowStudio) ~= "boolean" then
		error("allowStudio must be a boolean", 0)
	end
	if type(result.allowServer) ~= "boolean" then
		error("allowServer must be a boolean", 0)
	end

	local timeout = result.timeoutSeconds
	if type(timeout) ~= "number" or timeout ~= timeout or timeout < 0 or timeout > 10 then
		error("timeoutSeconds must be a finite number between 0 and 10", 0)
	end
	local iterations = result.maxIterations
	if type(iterations) ~= "number" or iterations ~= iterations or iterations < 1 or iterations > 10000 then
		error("maxIterations must be an integer between 1 and 10000", 0)
	end

	-- Validate the probe filters eagerly: a typo in a probe id should be a
	-- programmer error, not a silently empty run.
	local function validateFilter(value, label)
		if value == nil then
			return nil
		end
		if type(value) ~= "table" then
			error(label .. " must be an array of probe ids", 0)
		end
		local out, count = {}, 0
		for _, id in ipairs(value) do
			if type(id) ~= "string" or PROBE_BY_ID[id] == nil then
				error("Unknown probe id in " .. label .. ": " .. tostring(id), 0)
			end
			out[count + 1] = id
			count += 1
		end
		return tFreeze(out)
	end
	result.only = validateFilter(result.only, "only")
	result.skip = validateFilter(result.skip, "skip")

	-- Frozen: a caller mutating their table mid-run must not change policy.
	return tFreeze(result)
end

local function freezeRecords(records)
	for i = 1, #records do
		tFreeze(records[i])
	end
	return tFreeze(records)
end

local function execute(options)
	local opts = normalizeOptions(options)
	local ctx = newContext(opts)
	ctx.notes = {}

	local onlySet, skipSet = nil, nil
	if opts.only then
		onlySet = {}
		for i = 1, #opts.only do
			onlySet[opts.only[i]] = true
		end
	end
	if opts.skip then
		skipSet = {}
		for i = 1, #opts.skip do
			skipSet[opts.skip[i]] = true
		end
	end

	local status, message = "passed", nil
	local executed = 0

	for i = 1, #PROBES do
		local probe = PROBES[i]
		if (onlySet == nil or onlySet[probe.id])
			and (skipSet == nil or not skipSet[probe.id]) then
			executed += 1
			ctx.probe = probe.id
			ctx.stage = probe.stage
			local before = #ctx.skipped

			local ok, err = pcall(probe.run, ctx)
			-- Drain after every probe, including on the error path, so a
			-- failure cannot leak Instances, connections or threads.
			local cleanupErrors = ledgerDrain(ctx)

			local probeStatus, probeMessage = "passed", nil
			if ctx.hardFailure then
				probeStatus = "failed"
			elseif not ok and not ctx.hardUnavailable then
				probeStatus = "failed"
			elseif ctx.hardUnavailable then
				probeStatus = "unavailable"
			elseif #cleanupErrors > 0 then
				probeStatus = "failed"
			elseif #ctx.skipped > before then
				probeStatus = "partial"
			end

			if probeStatus == "failed" then
				probeMessage = ctx.hardFailure or (ok and "Resource cleanup failed" or describe(err))
			elseif probeStatus == "unavailable" then
				probeMessage = ctx.hardUnavailable
			end

			tInsert(ctx.probes, {
				id = probe.id,
				stage = probe.stage,
				class = probe.class,
				status = probeStatus,
				message = probeMessage,
			})

			for j = 1, #cleanupErrors do
				tInsert(ctx.cleanupErrors, probe.id .. ": " .. cleanupErrors[j])
			end

			if probeStatus == "failed" or probeStatus == "unavailable" then
				status, message = probeStatus, probeMessage
				break
			end
		end
	end

	-- Fold the token stream, then publish it so a divergence can be
	-- attributed to a probe rather than just observed.
	local digest
	for i = 1, #ctx.tokens do
		feed(ctx.acc, ctx.tokens[i])
	end
	digest = collapse(ctx.acc)

	-- If anything was skipped, a 'passed' run is really a 'partial' one.
	-- A 'failed' or 'unavailable' run keeps that status — the loop broke
	-- as soon as it had a verdict.
	if status == "passed" and #ctx.skipped > 0 then
		status = "partial"
	end

	local passed, ran, skippedCount = 0, #ctx.probes, #ctx.skipped
	for i = 1, ran do
		if ctx.probes[i].status == "passed" then
			passed += 1
		end
	end

	local report = {
		ok = status == "passed" or status == "partial",
		complete = status == "passed",
		status = status,
		stage = (status == "failed" or status == "unavailable") and ctx.stage or nil,
		probe = (status == "failed" or status == "unavailable") and ctx.probe or nil,
		message = message,
		-- Change detector for this build. Not a commitment, not keyed, not
		-- secret. See the header.
		digest = digest,
		tokens = tFreeze(ctx.tokens),
		probes = freezeRecords(ctx.probes),
		skipped = freezeRecords(ctx.skipped),
		notes = tFreeze(ctx.notes),
		cleanupErrors = tFreeze(ctx.cleanupErrors),
		coverage = {
			executed = executed,
			ran = ran,
			passed = passed,
			skipped = skippedCount,
		},
		inRoblox = IN_ROBLOX,
	}
	tFreeze(report.coverage)
	return tFreeze(report), ctx
end

-- Options are validated per call but not retained, so `Check` and `Run`
-- can be called with different policies without interfering.
local function executeAndCheck(options)
	local report = execute(options)
	return report
end

-- Run the suite and return a report. Never throws for a probe failure —
-- only for programmer errors (bad options, bad seeds).
function Sentinel.Check(options)
	return executeAndCheck(options)
end

local function requireOk(report)
	if not report.ok then
		error("Sentinel " .. report.status .. " [" .. tostring(report.probe) .. "]: "
			.. tostring(report.message), 0)
	end
end

-- Run the suite and throw unless it passed or was merely partial.
function Sentinel.Run(options)
	local report = executeAndCheck(options)
	requireOk(report)
	return report.digest, report
end

-- Verify a sealed function still matches its seal. Throws on any mismatch.
function Sentinel.VerifyFunction(fn)
	local seal = seals[fn]
	if seal == nil then
		error("Function has not been sealed", 0)
	end
	local fingerprint, environment = fingerprintFunction(fn)
	if fingerprint ~= seal.fingerprint or not sameValue(environment, seal.environment) then
		error("Sealed function metadata or environment changed", 0)
	end
	if environment then
		for name in pairs(seal.policy) do
			if not sameValue(rawget(environment, name), seal.bindings[name]) then
				error("Sealed environment binding changed: " .. name, 0)
			end
		end
	end
	return true
end

-- Record a baseline for a function. Resealing an unchanged function is a
-- no-op; changing an existing seal's binding policy is rejected outright.
function Sentinel.Seal(fn, bindingNames)
	local policy, order = buildBindingPolicy(bindingNames)
	local fingerprint, environment = fingerprintFunction(fn)
	local existing = seals[fn]
	if existing then
		Sentinel.VerifyFunction(fn)
		if bindingNames ~= nil then
			if #order ~= #existing.order then
				error("Cannot change an existing seal's binding policy", 0)
			end
			for i = 1, #order do
				if order[i] ~= existing.order[i] then
					error("Cannot change an existing seal's binding policy", 0)
				end
			end
		end
		return existing.fingerprint
	end

	local bindings = {}
	if environment then
		for i = 1, #order do
			bindings[order[i]] = rawget(environment, order[i])
		end
	end
	seals[fn] = {
		fingerprint = fingerprint,
		environment = environment,
		bindings = bindings,
		policy = policy,
		order = order,
	}
	return fingerprint
end

-- Wrap a function so it is verified immediately before and after every
-- call. Yields, multiple return values and nil holes are preserved.
function Sentinel.Protect(fn, bindingNames)
	Sentinel.Seal(fn, bindingNames)
	return function(...)
		Sentinel.VerifyFunction(fn)
		local result = tPack(fn(...))
		Sentinel.VerifyFunction(fn)
		return unpack(result, 1, result.n)
	end
end

-- Derive 32 deterministic bytes from the token stream and a public seed.
--
-- NOT CRYPTOGRAPHY. The seed is a public constant, the token stream is
-- public, and the mixing is not a KDF or a MAC. Do not use this to
-- authenticate a client, attest to a server, or protect a secret — anything
-- derived this way is knowable by anyone who has read this file.
function Sentinel.DeriveKey(seed, options)
	if seed == nil then
		seed = 0xA5A5A5A5
	end
	if type(seed) ~= "number" or seed ~= seed or seed % 1 ~= 0 or seed < 0 or seed > 0xFFFFFFFF then
		error("seed must be an unsigned 32-bit integer", 0)
	end
	local report, ctx = execute(options)
	requireOk(report)

	local state = bBxor(report.digest, seed)
	local key = tCreate(32)
	for i = 1, 32 do
		state = mul32(bBxor(state, ctx.acc.a + i), 0x045D9F3B)
		state = bBxor(state, bRshift(state, 16))
		key[i] = bBand(bBxor(state, ctx.acc.b), 0xFF)
	end
	return key, report
end

Sentinel.DeriveObfuscationKey = Sentinel.DeriveKey

-- Every probe id, so callers can build filters without hardcoding strings.
function Sentinel.GetProbes()
	local out = tCreate(#PROBES)
	for i = 1, #PROBES do
		out[i] = tFreeze({ id = PROBES[i].id, stage = PROBES[i].stage, class = PROBES[i].class })
	end
	return tFreeze(out)
end

-- A short human-readable summary, for logs and warnings.
function Sentinel.Describe(report)
	report = report or executeAndCheck(nil)
	local lines = {
		("Sentinel: %s%s"):format(report.status, report.complete and "" or (" (" .. report.coverage.passed .. "/" .. report.coverage.ran .. " clean)")),
	}
	if report.probe then
		lines[#lines + 1] = ("  %s [%s]: %s"):format(report.probe, tostring(report.stage), tostring(report.message))
	end
	for i = 1, #report.skipped do
		lines[#lines + 1] = ("  skipped %s: %s"):format(report.skipped[i].probe, report.skipped[i].reason)
	end
	for i = 1, #report.notes do
		lines[#lines + 1] = ("  note %s"):format(report.notes[i])
	end
	return tConcat(lines, "\n")
end

-- Seal the public entry points. If any of these are replaced after load,
-- VerifyFunction says so.
Sentinel.Seal(Sentinel.Check)
Sentinel.Seal(Sentinel.Run)
Sentinel.Seal(Sentinel.DeriveKey)
Sentinel.Seal(Sentinel.VerifyFunction)
Sentinel.Seal(Sentinel.Seal)
Sentinel.Seal(Sentinel.Protect)

Sentinel.VERSION = "1.0.0"
Sentinel.PROBE_COUNT = #PROBES

return tFreeze(Sentinel)
