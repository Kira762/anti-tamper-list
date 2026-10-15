-- Roblox Luau runtime consistency checks (v3.1).
-- Detects inconsistencies in incomplete environments; NOT a client trust boundary.
-- The rolling digest / DeriveKey are deterministic obfuscation aids, not cryptography.
-- Checks may yield. Each invocation owns its state, diagnostics, and temporary objects.
-- See readme.md for partial coverage, strict mode, and function-sealing limitations.

local type0 = type
local typeof0 = typeof
local pcall0 = pcall
local xpcall0 = xpcall
local error0 = error
local tostring0 = tostring
local tonumber0 = tonumber
local select0 = select
local rawget0 = rawget
local rawset0 = rawset
local rawequal0 = rawequal
local next0 = next
local pairs0 = pairs
local getmetatable0 = getmetatable
local setmetatable0 = setmetatable
local getfenv0 = getfenv
local setfenv0 = setfenv
local newproxy0 = newproxy

local string0 = string
local table0 = table
local math0 = math
local bit320 = bit32
local buffer0 = buffer
local coroutine0 = coroutine
local task0 = task
local debug0 = debug
local vector0 = vector

local game0 = game
local workspace0 = workspace
local Instance0 = Instance
local Enum0 = Enum
local Random0 = Random
local Vector20 = Vector2
local Vector30 = Vector3
local Vector3int160 = Vector3int16
local CFrame0 = CFrame
local UDim20 = UDim2
local Rect0 = Rect
local Axes0 = Axes
local PhysicalProperties0 = PhysicalProperties
local Path2DControlPoint0 = Path2DControlPoint

local sByte = string0 and string0.byte
local sSub = string0 and string0.sub
local sFind = string0 and string0.find
local sMatch = string0 and string0.match
local sGsub = string0 and string0.gsub
local sFormat = string0 and string0.format

local tInsert = table0 and table0.insert
local tConcat = table0 and table0.concat
local tSort = table0 and table0.sort
local tPack = table0 and table0.pack
local tUnpack = table0 and table0.unpack
local tCreate = table0 and table0.create
local tFreeze = table0 and table0.freeze
local tIsFrozen = table0 and table0.isfrozen
local tClear = table0 and table0.clear

local mAbs = math0 and math0.abs
local mRandom = math0 and math0.random
local mPi = math0 and math0.pi

local bBand = bit320 and bit320.band
local bBxor = bit320 and bit320.bxor
local bLshift = bit320 and bit320.lshift
local bRshift = bit320 and bit320.rshift
local bArshift = bit320 and bit320.arshift
local bExtract = bit320 and bit320.extract
local bReplace = bit320 and bit320.replace

local dInfo = debug0 and debug0.info
local dTraceback = debug0 and debug0.traceback

local cCreate = coroutine0 and coroutine0.create
local cResume = coroutine0 and coroutine0.resume
local cYield = coroutine0 and coroutine0.yield
local cWrap = coroutine0 and coroutine0.wrap
local cStatus = coroutine0 and coroutine0.status
local cClose = coroutine0 and coroutine0.close

-- ============================================================================
-- Per-run consistency accumulator (public, deterministic, non-cryptographic)
-- ============================================================================
local EXPECTED_DIGEST = 0xEAECA79E
local sealedFunctions = setmetatable0({}, { __mode = "k" })
local clock0 = os and os.clock

local function mul32(a, b)
    a = bBand(a, 0xFFFFFFFF)
    b = bBand(b, 0xFFFFFFFF)
    local alo = bBand(a, 0xFFFF)
    local ahi = bRshift(a, 16)
    local blo = bBand(b, 0xFFFF)
    local bhi = bRshift(b, 16)
    return bBand(alo * blo + bBand(alo * bhi + ahi * blo, 0xFFFF) * 65536, 0xFFFFFFFF)
end

local function feedState(ctx, token)
    token = bBand(token, 0xFFFFFFFF)
    ctx.state1 = mul32(bBxor(ctx.state1, token), 0x01000193)
    ctx.state2 = bBand(mul32(ctx.state2, 0x045D9F3B) + bBxor(token, ctx.state1) + 0x9E3779B9, 0xFFFFFFFF)
    local rot = bBxor(bLshift(ctx.state3, 13), bRshift(ctx.state3, 19))
    ctx.state3 = mul32(bBxor(rot, token), 0x1B873593)
    ctx.state4 = bBxor(ctx.state4, bBand(ctx.state1 + ctx.state2 + ctx.state3 + token, 0xFFFFFFFF))
end

local function trap(ctx, message)
    -- Latch within this invocation, including failures caught inside a probe's pcall.
    -- Never poison other callers, schedule orphan tasks, or spin the client forever.
    ctx.failure = ctx.failure or message or "Runtime consistency check failed"
    error0(ctx.failure, 0)
end

local function requireTrue(ctx, cond, message)
    if not cond then
        trap(ctx, message)
    end
end

local function unavailable(ctx, check, reason)
    tInsert(ctx.skipped, { check = check, stage = ctx.stage, reason = reason })
    if ctx.options.requireAllChecks then
        ctx.unavailable = check .. ": " .. reason
        error0(ctx.unavailable, 0)
    end
end

-- Register immediately after allocation. The runner drains this stack after EVERY
-- stage, including unexpected API errors, timeouts, and swallowed probe failures.
local function own(ctx, resource, dispose)
    requireTrue(ctx, resource ~= nil, "Resource allocation returned nil")
    dispose = dispose or resource.Destroy
    requireTrue(ctx, type0(dispose) == "function", "Resource has no cleanup method")
    tInsert(ctx.cleanups, { resource = resource, dispose = dispose, released = false })
    return resource
end

local function release(ctx, resource)
    for i = #ctx.cleanups, 1, -1 do
        local entry = ctx.cleanups[i]
        if rawequal0(entry.resource, resource) then
            if not entry.released then
                entry.dispose(entry.resource)
                entry.released = true
            end
            return
        end
    end
    trap(ctx, "Attempted to release an unowned resource")
end

local function describeError(value)
    local ok, message = pcall0(tostring0, value)
    return ok and type0(message) == "string" and message or "Unprintable error value"
end

local function cleanup(ctx)
    local errors = {}
    for i = #ctx.cleanups, 1, -1 do
        local entry = ctx.cleanups[i]
        if not entry.released then
            local ok, err = pcall0(entry.dispose, entry.resource)
            entry.released = true
            if not ok then
                tInsert(errors, describeError(err))
            end
        end
    end
    tClear(ctx.cleanups)
    return errors
end

local function waitFor(ctx, predicate)
    if predicate() then
        return true
    end
    if not task0 or type0(task0.wait) ~= "function" or type0(clock0) ~= "function" then
        return false
    end
    local deadline = clock0() + ctx.options.timeoutSeconds
    -- The iteration limit also bounds a broken clock / scheduler mock.
    for _ = 1, 120 do
        if clock0() >= deadline then
            break
        end
        task0.wait()
        if predicate() then
            return true
        end
    end
    return false
end

local function approxEq(a, b, eps)
    if type0(a) ~= "number" or type0(b) ~= "number" then
        return false
    end
    return mAbs(a - b) <= (eps or 1e-4)
end

-- ============================================================================
-- Stage 1: VM Identity, Sandbox / Emulator Rejection & Environment Isolation
-- ============================================================================
local function checkStage1_RuntimeAndSandbox(ctx)
    requireTrue(ctx,
        type0(pcall0) == "function"
        and type0(xpcall0) == "function"
        and type0(rawget0) == "function"
        and type0(rawset0) == "function"
        and type0(rawequal0) == "function"
        and type0(getmetatable0) == "function"
        and type0(setmetatable0) == "function"
        and type0(getfenv0) == "function"
        and type0(setfenv0) == "function"
        and type0(typeof0) == "function"
        and type0(dInfo) == "function"
        and type0(dTraceback) == "function"
    )

    requireTrue(ctx, _VERSION == "Luau")
    requireTrue(ctx, type0(_G) == "table" and sFind(tostring0(_G), "table: ") ~= nil)
    requireTrue(ctx, #tostring0(true) + #tostring0(false) == 9)
    requireTrue(ctx, sByte(tostring0(true)) ~= sByte(tostring0(false)))

    -- Reject non-Roblox standalone runtimes (Lune, Luau CLI, Lua 5.x, Python-Lua bridges)
    local forbiddenGlobals = {
        "io", "package", "__builtins__", "__name__",
        "fenv", "_fenv", "__fenv", "rawenv", "hookenv", "scriptenv"
    }
    for i = 1, #forbiddenGlobals do
        if rawget0(_G, forbiddenGlobals[i]) ~= nil then
            trap(ctx)
        end
    end
    requireTrue(ctx, rawget0(string0, "dump") == nil)
    if type0(os) == "table" then
        requireTrue(ctx,
            rawget0(os, "execute") == nil
            and rawget0(os, "exit") == nil
            and rawget0(os, "remove") == nil
            and rawget0(os, "rename") == nil
            and rawget0(os, "getenv") == nil
        )
    end

    if type0(require) == "function" then
        local luneModules = {
            "@lune/fs", "@lune/process", "@lune/net",
            "@lune/task", "@lune/roblox", "@lune/luau"
        }
        for i = 1, #luneModules do
            local ok = pcall0(require, luneModules[i])
            if ok then
                trap(ctx)
            end
        end
    end

    -- Verify VM error formatting and stack line delta invariants
    local okErr, rawErr = pcall0(function()
        local nilCall = nil
        return nilCall()
    end)
    requireTrue(ctx, not okErr and type0(rawErr) == "string")
    requireTrue(ctx,
        not sFind(rawErr, "luau%.load")
        and not sFind(rawErr, "@lune")
        and not sFind(rawErr, "stdin:")
    )

    -- Verify getfenv(0) / getfenv(1) / setfenv isolation
    local okF0, env0 = pcall0(getfenv0, 0)
    local okF1, env1 = pcall0(getfenv0, 1)
    requireTrue(ctx, okF0 and type0(env0) == "table" and env0 ~= _G)
    requireTrue(ctx, okF1 and type0(env1) == "table" and env1 ~= _G)
    requireTrue(ctx, env0.game ~= nil and env0.workspace ~= nil and rawequal0(env0.getfenv, getfenv0))

    -- Pack "Luau" bytes into Token 1
    local vToken = bLshift(sByte(_VERSION, 1), 24)
        + bLshift(sByte(_VERSION, 2), 16)
        + bLshift(sByte(_VERSION, 3), 8)
        + sByte(_VERSION, 4)
    feedState(ctx, vToken)
end

-- ============================================================================
-- Stage 2: Buffer IEEE-754 Memory Aliasing & Cross-Width Endianness Oracle
-- (Defeats key-value table mocks of Luau's buffer library)
-- ============================================================================
local function checkStage2_BufferMemoryAliasing(ctx)
    requireTrue(ctx, type0(buffer0) == "table")
    local bufMethods = {
        "create", "fromstring", "tostring", "len",
        "readu8", "readu16", "readi16", "readi32", "readu32", "readf32", "readf64", "readstring",
        "writeu8", "writeu16", "writei16", "writei32", "writeu32", "writef32", "writef64", "writestring",
        "fill", "copy"
    }
    for i = 1, #bufMethods do
        requireTrue(ctx, type0(buffer0[bufMethods[i]]) == "function")
    end

    local buf = buffer0.create(48)
    requireTrue(ctx, buffer0.len(buf) == 48)

    -- Write IEEE-754 float64 math.pi at offset 0, read back as two overlapping little-endian u32s
    buffer0.writef64(buf, 0, mPi)
    local piLow = buffer0.readu32(buf, 0)
    local piHigh = buffer0.readu32(buf, 4)
    requireTrue(ctx, piLow == 0x54442D18 and piHigh == 0x400921FB)

    -- Write float32 1.5 and -2.25, read back raw IEEE-754 u32 bit patterns
    buffer0.writef32(buf, 8, 1.5)
    buffer0.writef32(buf, 12, -2.25)
    local f32Pos = buffer0.readu32(buf, 8)
    local f32Neg = buffer0.readu32(buf, 12)
    requireTrue(ctx, f32Pos == 0x3FC00000 and f32Neg == 0xC0100000)

    -- Write two u16 halves (0x0000, 0x4040 -> 0x40400000) and read back as float32 (must equal 3.0)
    buffer0.writeu16(buf, 16, 0x0000)
    buffer0.writeu16(buf, 18, 0x4040)
    local f32Alias = buffer0.readf32(buf, 16)
    requireTrue(ctx, f32Alias == 3)

    -- Dynamic runtime float32 bit-decomposition check
    local randInt = mRandom(2, 63)
    local dynamicVal = randInt * 1.5
    buffer0.writef32(buf, 20, dynamicVal)
    local rawBits = buffer0.readu32(buf, 20)
    buffer0.writeu32(buf, 24, rawBits)
    requireTrue(ctx, buffer0.readf32(buf, 24) == dynamicVal)
    requireTrue(ctx, bExtract(rawBits, 31, 1) == 0)

    -- Out-of-bounds access must throw a C error
    requireTrue(ctx, not pcall0(buffer0.readu8, buf, 48))
    requireTrue(ctx, not pcall0(buffer0.writeu32, buf, 46, 1))
    requireTrue(ctx, not pcall0(buffer0.create, -1))

    -- Copy & fill verification
    local srcBuf = buffer0.fromstring("RBLX_AT")
    buffer0.copy(buf, 32, srcBuf, 0, 7)
    requireTrue(ctx, buffer0.readstring(buf, 32, 7) == "RBLX_AT")
    buffer0.fill(buf, 32, 0x5A, 4)
    requireTrue(ctx, buffer0.readu32(buf, 32) == 0x5A5A5A5A)

    feedState(ctx, piLow)
    feedState(ctx, piHigh)
    feedState(ctx, f32Pos)
    feedState(ctx, f32Alias)
end

-- ============================================================================
-- Stage 3: PCG32 Random.new Stream, Dynamic :Clone() Fork & Unit-Sphere Manifold
-- ============================================================================
local function checkStage3_RandomAndManifold(ctx)
    requireTrue(ctx, type0(Random0) == "table" and type0(Random0.new) == "function")

    -- Deterministic stream verification
    local rng = Random0.new(1515359100)
    local r1 = rng:NextInteger(532, 1117)
    local r2 = rng:NextNumber()
    local r3 = rng:NextNumber()
    local r4 = rng:NextInteger(299, 786)
    local r5 = rng:NextInteger(784, 1062)
    requireTrue(ctx, r1 == 763 and r4 == 397 and r5 == 847)
    requireTrue(ctx, approxEq(r2, 0.52705833430898807, 1e-12))
    requireTrue(ctx, approxEq(r3, 0.44671507908619318, 1e-12))

    -- Dynamic runtime seed + mid-stream Clone() fork equivalence
    local dynSeed = mRandom(1, 2147483640)
    local dynRng = Random0.new(dynSeed)
    local burnCount = mRandom(3, 9)
    for _ = 1, burnCount do
        dynRng:NextNumber()
    end
    local forkedRng = dynRng:Clone()
    requireTrue(ctx, typeof0(forkedRng) == "Random" and not rawequal0(dynRng, forkedRng))
    for _ = 1, 8 do
        requireTrue(ctx, dynRng:NextInteger(-1000000, 1000000) == forkedRng:NextInteger(-1000000, 1000000))
        requireTrue(ctx, dynRng:NextNumber() == forkedRng:NextNumber())
        local uA = dynRng:NextUnitVector()
        local uB = forkedRng:NextUnitVector()
        requireTrue(ctx, uA == uB and approxEq(uA.Magnitude, 1, 1e-5))
    end

    -- Known seed 1 NextUnitVector exact components
    local u1 = Random0.new(1):NextUnitVector()
    requireTrue(ctx,
        approxEq(u1.X, 0.42857980728149414, 1e-6)
        and approxEq(u1.Y, -0.10929630696773529, 1e-6)
        and approxEq(u1.Z, 0.8968688249588013, 1e-6)
    )

    feedState(ctx, r1)
    feedState(ctx, r4)
    feedState(ctx, r5)
end

-- ============================================================================
-- Stage 4: Luau Language Semantics, Frozen Tables, Metatable Locks & Proxies
-- ============================================================================
local function checkStage4_LanguageSemantics(ctx)
    -- String primitive metatable lock (in Luau luaL_sandbox getmetatable("") returns "The metatable is locked";
    -- a table with non-nil __metatable returned from getmetatable() is impossible in C luaB_getmetatable and proves hooking)
    local okStrMt, strMt = pcall0(getmetatable0, "")
    requireTrue(ctx,
        okStrMt
        and (
            strMt == "The metatable is locked"
            or (type0(strMt) == "table" and rawequal0(strMt.__index, string0) and strMt.__metatable == nil)
        )
        and rawequal0(sByte, ("A").byte)
    )
    requireTrue(ctx, not pcall0(setmetatable0, "", {}))

    -- pcall / xpcall multi-return & nil-hole preservation
    local pOk, p1, p2, p3 = pcall0(function()
        return 17, nil, 29
    end)
    requireTrue(ctx, pOk and p1 == 17 and p2 == nil and p3 == 29)

    local xOk, xMsg = xpcall0(function()
        error0("sentinel_91", 0)
    end, function(e)
        return "caught:" .. tostring0(e)
    end)
    requireTrue(ctx, not xOk and xMsg == "caught:sentinel_91")

    -- table.pack / table.create / table.freeze (including rawset rejection on frozen tables)
    local packed = tPack("a", nil, "c")
    requireTrue(ctx, packed.n == 3 and packed[1] == "a" and packed[2] == nil and packed[3] == "c")

    local created = tCreate(4, 9)
    requireTrue(ctx, #created == 4 and created[1] == 9 and created[4] == 9)
    requireTrue(ctx, not pcall0(tCreate, -1))

    local frozen = tFreeze({ k = 42 })
    requireTrue(ctx, tIsFrozen(frozen) and frozen.k == 42)
    requireTrue(ctx, not pcall0(function() frozen.k = 1 end))
    requireTrue(ctx, not pcall0(rawset0, frozen, "k", 1))
    requireTrue(ctx, not pcall0(setmetatable0, frozen, {}))

    -- newproxy(true), newproxy(false), and Luau rejection of userdata argument to newproxy
    if type0(newproxy0) == "function" then
        local pTrue = newproxy0(true)
        local pMt = getmetatable0(pTrue)
        requireTrue(ctx, type0(pMt) == "table" and type0(pTrue) == "userdata")
        pMt.__len = function() return 1000159 end
        pMt.__index = { probe = "ok" }
        requireTrue(ctx, #pTrue == 1000159 and pTrue.probe == "ok")
        requireTrue(ctx, not pcall0(newproxy0, pTrue))
        pMt.__metatable = false
        requireTrue(ctx, getmetatable0(pTrue) == false)

        local pFalse = newproxy0(false)
        requireTrue(ctx, type0(pFalse) == "userdata" and getmetatable0(pFalse) == nil)
        requireTrue(ctx, not pcall0(setmetatable0, pFalse, {}))
    end

    -- bit32 identities
    local bx = bBxor(0x12345678, 0xFFFFFFFF)
    requireTrue(ctx, bx == 0xEDCBA987)
    requireTrue(ctx, bArshift(0x80000000, 31) == 0xFFFFFFFF)
    requireTrue(ctx, bExtract(0xABCD1234, 8, 8) == 0x12)
    requireTrue(ctx, bReplace(0xABCD1234, 0xFF, 8, 8) == 0xABCDFF34)

    feedState(ctx, bx)
end

-- UI-dependent probes need a live PlayerGui, not StarterGui (a template).
local function makeProbeGui(ctx, check)
    local ok, playerGui = pcall0(function()
        local player = game0:GetService("Players").LocalPlayer
        return player and player:FindFirstChildOfClass("PlayerGui")
    end)
    if not ok or playerGui == nil then
        unavailable(ctx, check, "A live local PlayerGui is not available")
        return nil
    end
    local holder = own(ctx, Instance0.new("ScreenGui"))
    holder.Name = "RuntimeProbe_" .. tostring0(mRandom(1000, 99999))
    holder.ResetOnSpawn = false
    holder.Parent = playerGui
    return holder
end

local function checkWorldModelRaycast(ctx, part)
    local holder = makeProbeGui(ctx, "worldmodel-raycast")
    if not holder then
        return
    end
    local viewport = own(ctx, Instance0.new("ViewportFrame"))
    viewport.Size = UDim20.fromOffset(1, 1)
    viewport.BackgroundTransparency = 1
    -- No camera, transparent background, and a transparent part: no visible UI.
    viewport.Parent = holder
    local worldModel = own(ctx, Instance0.new("WorldModel"))
    worldModel.Parent = viewport
    requireTrue(ctx,
        typeof0(worldModel) == "Instance" and worldModel:IsA("WorldRoot")
        and worldModel:IsA("Model") and type0(worldModel.Raycast) == "function"
        and not pcall0(worldModel.Raycast)
        and not pcall0(worldModel.Raycast, worldModel, "bad_origin", Vector30.zero),
        "Invalid WorldModel raycast API"
    )
    local rayDist = mRandom(20, 60)
    local halfThick = mRandom(2, 6)
    local offsetX, offsetY = mRandom(-3, 3), mRandom(-3, 3)
    part.Size = Vector30.new(16, 16, halfThick * 2)
    part.CFrame = CFrame0.new(0, 0, -rayDist)
    part.Anchored = true
    part.CanCollide = false
    part.CanQuery = true
    part.Transparency = 1
    part.Parent = worldModel

    local rayOrigin = Vector30.new(offsetX, offsetY, 0)
    local direction = Vector30.new(0, 0, -(rayDist + 30))
    local hit
    requireTrue(ctx, waitFor(ctx, function()
        hit = worldModel:Raycast(rayOrigin, direction)
        return hit ~= nil
    end), "WorldModel raycast did not hit the known test part")
    local miss = worldModel:Raycast(rayOrigin, -direction)
    requireTrue(ctx, miss == nil, "WorldModel raycast reported an unexpected hit")
    requireTrue(ctx,
        rawequal0(hit.Instance, part)
        and approxEq(hit.Distance, rayDist - halfThick, 1e-2)
        and approxEq(hit.Position.X, offsetX, 1e-2)
        and approxEq(hit.Position.Y, offsetY, 1e-2)
        and approxEq(hit.Position.Z, -(rayDist - halfThick), 1e-2)
        and approxEq(hit.Normal.X, 0, 1e-3)
        and approxEq(hit.Normal.Y, 0, 1e-3)
        and approxEq(hit.Normal.Z, 1, 1e-3),
        "WorldModel raycast surface/normal mismatch"
    )
end

-- ============================================================================
-- Stage 5: 3D Vector, Orthonormal CFrame Algebra, Part Mass/CFrame Sync
-- & WorldModel Positive-Hit Raycast Surface/Normal Check
-- ============================================================================
local function checkStage5_GeometryAndPhysicsSync(ctx)
    requireTrue(ctx, type0(vector0) == "table" and type0(vector0.create) == "function")
    local nv = vector0.create(1.25, -2.5, 3.75)
    requireTrue(ctx,
        (type0(nv) == "vector" or type0(nv) == "userdata")
        and typeof0(nv) == "Vector3"
        and nv.x == 1.25 and nv.y == -2.5 and nv.z == 3.75
        and nv.X == 1.25 and nv.Y == -2.5 and nv.Z == 3.75
    )

    local v2 = Vector20.new(3, 4)
    local dotVal = v2:Dot(Vector20.new(5, 6))
    requireTrue(ctx, v2.Magnitude == 5 and dotVal == 39)

    local ux = Vector30.new(1, 0, 0)
    local uy = Vector30.new(0, 1, 0)
    local uz = ux:Cross(uy)
    requireTrue(ctx, uz.X == 0 and uz.Y == 0 and uz.Z == 1)

    if Vector3int160 and type0(Vector3int160.new) == "function" then
        local vi = Vector3int160.new(1, 2, 3)
        requireTrue(ctx, vi.X * 31 + vi.Y * 17 + vi.Z * 13 == 104)
    end

    if Rect0 and Axes0 then
        local r = Rect0.new(2, 4, 8, 16)
        requireTrue(ctx, r.Min.X == 2 and r.Min.Y == 4 and r.Max.X == 8 and r.Max.Y == 16 and r.Width == 6 and r.Height == 12)
        local ax = Axes0.new(Enum0.Axis.X, Enum0.Axis.Y)
        requireTrue(ctx, ax.X == true and ax.Y == true and ax.Z == false)
    end

    -- Dynamic CFrame SE(3) group inversion & orthonormal basis check
    local randAxis = Vector30.new(mRandom(1, 10), mRandom(1, 10), mRandom(1, 10)).Unit
    local randAngle = mRandom(15, 300) * (mPi / 180)
    local cf = CFrame0.fromAxisAngle(randAxis, randAngle) + Vector30.new(mRandom(-50, 50), mRandom(-50, 50), mRandom(-50, 50))
    local idCf = cf * cf:Inverse()
    requireTrue(ctx, approxEq(idCf.Position.Magnitude, 0, 1e-4))
    requireTrue(ctx, approxEq(cf.RightVector:Cross(cf.UpVector):Dot(cf.LookVector), -1, 1e-4))
    local testPt = Vector30.new(mRandom(-20, 20), mRandom(-20, 20), mRandom(-20, 20))
    local roundPt = cf:PointToObjectSpace(cf:PointToWorldSpace(testPt))
    requireTrue(ctx, approxEq((roundPt - testPt).Magnitude, 0, 1e-3))

    -- Part C++ bidirectional CFrame <-> Position sync & dynamic Volume * Density == GetMass()
    local part = own(ctx, Instance0.new("Part"))
    part.Shape = Enum0.PartType.Block
    local sx, sy, sz = mRandom(2, 9), mRandom(2, 9), mRandom(2, 9)
    local density = mRandom(5, 25) / 10
    part.Size = Vector30.new(sx, sy, sz)
    part.CustomPhysicalProperties = PhysicalProperties0.new(density, 0.3, 0.5)
    local expectedMass = sx * sy * sz * density
    requireTrue(ctx, approxEq(part:GetMass(), expectedMass, 1e-2) and approxEq(part.Mass, expectedMass, 1e-2))

    local px, py, pz = mRandom(10, 90), mRandom(10, 90), mRandom(10, 90)
    part.CFrame = CFrame0.new(px, py, pz)
    requireTrue(ctx, approxEq(part.Position.X, px, 1e-3) and approxEq(part.Position.Y, py, 1e-3) and approxEq(part.Position.Z, pz, 1e-3))
    part.Position = Vector30.new(px + 5, py - 3, pz + 7)
    requireTrue(ctx, approxEq(part.CFrame.X, px + 5, 1e-3) and approxEq(part.CFrame.Y, py - 3, 1e-3) and approxEq(part.CFrame.Z, pz + 7, 1e-3))

    checkWorldModelRaycast(ctx, part)
    release(ctx, part)

    feedState(ctx, dotVal)
    feedState(ctx, uz.Z)
end

-- ============================================================================
-- Stage 6: Instance Reflection, Signal Identity, BindableEvent Deep-Copy,
-- IntValue Deduplication, CollectionService & DataStoreIncrementOptions
-- ============================================================================
local function checkStage6_ReflectionAndSignals(ctx)
    requireTrue(ctx, type0(game0) == "userdata" and typeof0(game0) == "Instance")
    requireTrue(ctx, type0(workspace0) == "userdata" and typeof0(workspace0) == "Instance")
    requireTrue(ctx, rawequal0(game0:GetService("Workspace"), workspace0))
    requireTrue(ctx, typeof0(Enum0) == "Enums" and type0(Enum0) == "userdata")

    -- Invalid member access must error, while FindFirstChild for non-existent service returns nil
    requireTrue(ctx, not pcall0(function() return workspace0["__nonexistent_member_991__"](workspace0) end))
    requireTrue(ctx, not pcall0(function() return game0["__nonexistent_member_992__"](game0) end))
    requireTrue(ctx, game0:FindFirstChild("__DefinitelyNotARealService__") == nil)
    requireTrue(ctx, workspace0:FindFirstChildOfClass("__DefinitelyNotARealClass__") == nil)

    -- Validate enum behavior without relying on undocumented wrapper allocation.
    local enumType = Enum0.HumanoidStateType
    requireTrue(ctx, type0(enumType.FromName) == "function" and type0(enumType.FromValue) == "function")
    requireTrue(ctx, enumType:FromName("NonExistentEnum99") == nil)
    requireTrue(ctx, enumType:FromValue(0) == Enum0.HumanoidStateType.FallingDown)
    requireTrue(ctx, typeof0(Enum0.HumanoidStateType.FallingDown) == "EnumItem")
    requireTrue(ctx, not pcall0(enumType.FromName))
    requireTrue(ctx, not pcall0(enumType.FromValue))

    -- Destroyed Instance lifecycle & attribute persistence
    local folder = own(ctx, Instance0.new("Folder"))
    folder.Name = "AntiEnvProbe"
    requireTrue(ctx, folder:IsA("Folder") and folder:IsA("Instance") and not folder:IsA("Part"))
    folder:SetAttribute("marker", 17)
    release(ctx, folder)
    local attrVal = folder:GetAttribute("marker")
    requireTrue(ctx, folder.Parent == nil and folder.Name == "AntiEnvProbe" and attrVal == 17 and #folder:GetChildren() == 0)

    -- BindableEvent signal equality & deep-copy marshaling on Fire
    local bindable = own(ctx, Instance0.new("BindableEvent"))
    local sigA = bindable.Event
    local sigB = bindable.Event
    requireTrue(ctx, sigA == sigB and typeof0(sigA) == "RBXScriptSignal")

    local receivedPayload = nil
    local conn = own(ctx, sigA:Connect(function(payload)
        receivedPayload = payload
    end), function(c) c:Disconnect() end)
    requireTrue(ctx, conn.Connected == true)
    requireTrue(ctx, not pcall0(conn.Disconnect))
    requireTrue(ctx, conn.Connected == true)

    local probeToken = mRandom(1000, 999999)
    local originalPayload = { token = probeToken, nested = { v = probeToken + 1 } }
    bindable:Fire(originalPayload)

    if waitFor(ctx, function() return receivedPayload ~= nil end) then
        requireTrue(ctx,
            type0(receivedPayload) == "table"
            and receivedPayload.token == probeToken
            and type0(receivedPayload.nested) == "table"
            and receivedPayload.nested.v == probeToken + 1
            and not rawequal0(receivedPayload, originalPayload)
            and not rawequal0(receivedPayload.nested, originalPayload.nested),
            "BindableEvent payload/copy mismatch"
        )
    else
        unavailable(ctx, "bindable-event", "Callback was not delivered before the deadline")
    end
    release(ctx, conn)
    requireTrue(ctx, conn.Connected == false)
    release(ctx, bindable)

    -- IntValue.Changed only fires on .Value changes (not .Name changes or duplicate values)
    local intVal = own(ctx, Instance0.new("IntValue"))
    local firedValues = {}
    local ivConn = own(ctx, intVal.Changed:Connect(function(v)
        tInsert(firedValues, v)
    end), function(c) c:Disconnect() end)
    intVal.Value = 7
    intVal.Name = "RenamedInt"
    intVal.Value = 7 -- duplicate assignment must not fire Changed
    intVal.Value = 8
    local delivered = waitFor(ctx, function() return #firedValues >= 2 end)
    release(ctx, ivConn)
    release(ctx, intVal)
    if delivered then
        requireTrue(ctx, #firedValues == 2 and firedValues[1] == 7 and firedValues[2] == 8,
            "IntValue change notification mismatch")
    else
        unavailable(ctx, "intvalue-signals", "Change callbacks were not delivered before the deadline")
    end

    -- CollectionService DataModel hierarchy gating
    local cs = game0:GetService("CollectionService")
    local tag = "_at_" .. tostring0(mRandom(100000, 999999))
    local taggedFolder = own(ctx, Instance0.new("Folder"))
    cs:AddTag(taggedFolder, tag)
    requireTrue(ctx, cs:HasTag(taggedFolder, tag) and #cs:GetTagged(tag) == 0)
    taggedFolder.Parent = workspace0
    local taggedList = cs:GetTagged(tag)
    requireTrue(ctx, #taggedList == 1 and rawequal0(taggedList[1], taggedFolder))
    taggedFolder.Parent = nil
    requireTrue(ctx, #cs:GetTagged(tag) == 0 and cs:HasTag(taggedFolder, tag))
    cs:RemoveTag(taggedFolder, tag)
    requireTrue(ctx, not cs:HasTag(taggedFolder, tag) and #cs:GetTags(taggedFolder) == 0)
    release(ctx, taggedFolder)

    -- DataStoreIncrementOptions metadata deep-copy & type validation
    local dsOpt = own(ctx, Instance0.new("DataStoreIncrementOptions"))
    local metaSource = { probe = "v_" .. tostring0(mRandom(1, 99999)) }
    local expectedProbe = metaSource.probe
    dsOpt:SetMetadata(metaSource)
    metaSource.probe = "mutated_after_set"
    requireTrue(ctx, dsOpt:GetMetadata().probe == expectedProbe)
    local badPart = own(ctx, Instance0.new("Part"))
    local okBadMeta = pcall0(dsOpt.SetMetadata, dsOpt, { invalid = badPart })
    release(ctx, badPart)
    release(ctx, dsOpt)
    requireTrue(ctx, not okBadMeta)

    feedState(ctx, attrVal)
end

-- ============================================================================
-- Stage 7: HttpService JSON Round-Trips, Invalid Input & UUIDv4 Invariants
-- ============================================================================
local function checkStage7_HttpServiceInvariants(ctx)
    local http = game0:GetService("HttpService")
    requireTrue(ctx, typeof0(http) == "Instance" and http.ClassName == "HttpService")

    local payload = { text = "quote\"\nslash\\", number = 1.5, flag = true, nested = { 17, 29 } }
    local encoded = http:JSONEncode(payload)
    requireTrue(ctx, type0(encoded) == "string", "JSONEncode did not return a string")
    local decoded = http:JSONDecode(encoded)
    requireTrue(ctx,
        type0(decoded) == "table" and decoded.text == payload.text
        and decoded.number == payload.number and decoded.flag == true
        and type0(decoded.nested) == "table"
        and #decoded.nested == 2 and decoded.nested[1] == 17 and decoded.nested[2] == 29,
        "JSON round-trip mismatch"
    )
    requireTrue(ctx, next0(http:JSONDecode("{}")) == nil)
    requireTrue(ctx, http:JSONDecode('{"a":null}').a == nil and http:JSONDecode("5") == 5)
    local okBadJson, errBadJson = pcall0(http.JSONDecode, http, "nope")
    requireTrue(ctx, not okBadJson and type0(errBadJson) == "string", "Invalid JSON was accepted")
    local cyclic = {}
    cyclic.self = cyclic
    local okCyclic, errCyclic = pcall0(http.JSONEncode, http, cyclic)
    requireTrue(ctx, not okCyclic and type0(errCyclic) == "string", "Cyclic JSON input was accepted")

    -- Dynamic GUID v4 format & uniqueness check
    local guidPlain = http:GenerateGUID(false)
    local guidBraced = http:GenerateGUID(true)
    requireTrue(ctx,
        type0(guidPlain) == "string"
        and #guidPlain == 36
        and guidPlain ~= http:GenerateGUID(false)
        and sMatch(guidPlain, "^%x%x%x%x%x%x%x%x%-%x%x%x%x%-4%x%x%x%-[89abAB]%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$") ~= nil
        and #guidBraced == 38
        and sSub(guidBraced, 1, 1) == "{"
        and sSub(guidBraced, 38, 38) == "}"
    )

    feedState(ctx, 4)
end

-- ============================================================================
-- Stage 8: Anti-Hook, debug.info Option Permutation ("flsna"), Live Stack-Level
-- Introspection, Non-Yieldable C-Call Boundary & Service/Mesh Verification
-- ============================================================================
local function verifyCClosureMetadata(ctx, fn, expectedName)
    requireTrue(ctx, type0(fn) == "function")

    -- Standard order "slnaf"
    local s1, l1, n1, a1, v1, f1 = dInfo(fn, "slnaf")
    requireTrue(ctx,
        s1 == "[C]"
        and l1 == -1
        and n1 == expectedName
        and a1 == 0
        and v1 == true
        and rawequal0(f1, fn)
    )

    -- Permuted order "flsna" (defeats debug.info hooks that hardcode "slnaf" return order)
    local f2, l2, s2, n2, a2, v2 = dInfo(fn, "flsna")
    requireTrue(ctx,
        rawequal0(f2, fn)
        and l2 == -1
        and s2 == "[C]"
        and n2 == expectedName
        and a2 == 0
        and v2 == true
    )

    -- C closures must reject setfenv
    requireTrue(ctx, not pcall0(setfenv0, fn, {}))
end

local function checkEditableMesh(ctx, assetService)
    local methodOk, createMesh = pcall0(function() return assetService.CreateEditableMesh end)
    if not methodOk or type0(createMesh) ~= "function" then
        unavailable(ctx, "editable-mesh", "CreateEditableMesh is not accessible")
        return
    end
    verifyCClosureMetadata(ctx, createMesh, "CreateEditableMesh")
    local meshOk, mesh = pcall0(createMesh, assetService)
    if not meshOk or mesh == nil then
        -- Documented nil result on editable-memory budget exhaustion. Permission
        -- errors likewise do not prove tampering. Strict mode rejects incomplete coverage.
        unavailable(ctx, "editable-mesh", meshOk and "Editable-memory budget is exhausted"
            or "Mesh creation is unavailable: " .. describeError(mesh))
        return
    end
    own(ctx, mesh)
    requireTrue(ctx, type0(mesh.SetPosition) == "function", "EditableMesh.SetPosition is missing")
    local rx, ry, rz = mRandom(5, 50) + mRandom(), mRandom(5, 50) + mRandom(), mRandom(5, 50) + mRandom()
    local v1 = mesh:AddVertex(Vector30.new(rx, ry, rz))
    local v2 = mesh:AddVertex(Vector30.new(rx + 2, ry + 1, rz - 1))
    local v3 = mesh:AddVertex(Vector30.new(rx - 1, ry + 3, rz + 2))
    requireTrue(ctx, v1 ~= v2 and v1 ~= v3 and v2 ~= v3, "EditableMesh reused a vertex ID")
    local p1 = mesh:GetPosition(v1)
    requireTrue(ctx, p1 ~= nil and approxEq(p1.X, rx, 1e-4)
        and approxEq(p1.Y, ry, 1e-4) and approxEq(p1.Z, rz, 1e-4), "EditableMesh vertex round-trip mismatch")
    local nx, ny, nz = rx + 3.25, ry - 1.5, rz + 2.75
    mesh:SetPosition(v1, Vector30.new(nx, ny, nz))
    local updated, unchanged = mesh:GetPosition(v1), mesh:GetPosition(v2)
    requireTrue(ctx, updated ~= nil and unchanged ~= nil
        and approxEq(updated.X, nx, 1e-4) and approxEq(updated.Y, ny, 1e-4) and approxEq(updated.Z, nz, 1e-4)
        and approxEq(unchanged.X, rx + 2, 1e-4) and approxEq(unchanged.Y, ry + 1, 1e-4)
        and approxEq(unchanged.Z, rz - 1, 1e-4), "EditableMesh mutation/isolation mismatch")
    requireTrue(ctx, not pcall0(mesh.GetPosition, mesh, -999999), "EditableMesh accepted an invalid vertex ID")
    release(ctx, mesh)
end

local function checkRestrictedService(ctx, serviceName, methodNames)
    local ok, methods = pcall0(function()
        local service = game0:GetService(serviceName)
        local result = {}
        for i = 1, #methodNames do
            local fn = service[methodNames[i]]
            if type0(fn) ~= "function" then
                return nil
            end
            result[i] = fn
        end
        return result
    end)
    if not ok or methods == nil then
        unavailable(ctx, serviceName, "Restricted service methods are not accessible")
        return
    end
    for i = 1, #methods do
        verifyCClosureMetadata(ctx, methods[i], methodNames[i])
        -- Intentionally omit self: never join voice or invoke device operations.
        requireTrue(ctx, not pcall0(methods[i]), "Service method accepted a missing receiver")
    end
end

local function checkStage8_AntiHookAndStackOracles(ctx)
    -- Invalid debug.info option character and negative level must throw a C error; out-of-bounds positive level returns nil
    requireTrue(ctx, not pcall0(dInfo, 1, "z"))
    requireTrue(ctx, not pcall0(dInfo, -1, "s"))
    requireTrue(ctx, dInfo(99999, "s") == nil)

    local cTargets = {
        { pcall0, "pcall" },
        { xpcall0, "xpcall" },
        { getmetatable0, "getmetatable" },
        { setmetatable0, "setmetatable" },
        { rawget0, "rawget" },
        { rawset0, "rawset" },
        { rawequal0, "rawequal" },
        { tostring0, "tostring" },
        { tonumber0, "tonumber" },
        { type0, "type" },
        { typeof0, "typeof" },
        { select0, "select" },
        { getfenv0, "getfenv" },
        { setfenv0, "setfenv" },
        { dInfo, "info" },
        { dTraceback, "traceback" },
        { sGsub, "gsub" },
        { sSub, "sub" },
        { sMatch, "match" },
        { tSort, "sort" },
        { tFreeze, "freeze" },
        { cCreate, "create" },
        { cResume, "resume" },
        { cYield, "yield" },
        { cWrap, "wrap" },
        { cStatus, "status" },
        { cClose, "close" },
        { task0.spawn, "spawn" },
        { task0.defer, "defer" },
        { task0.delay, "delay" },
        { task0.wait, "wait" },
        { task0.cancel, "cancel" },
        { Instance0.new, "new" },
        { UDim20.new, "new" },
        { Random0.new, "new" },
        { game0.GetService, "GetService" },
    }
    for i = 1, #cTargets do
        verifyCClosureMetadata(ctx, cTargets[i][1], cTargets[i][2])
    end

    -- Live Call-Stack Level Introspection (queries numeric level 2 & 3 while C function is on stack)
    local verifiedCallbacks = 0

    -- 1) string.gsub live C-frame stack check (compatible with both raw Luau and VM-virtualized callers)
    local function probeGsubStack()
        sGsub("x", ".", function()
            local s, l, n, a, v, f = dInfo(2, "slnaf")
            local callerS, callerL, _, _, _, callerF = dInfo(3, "slnaf")
            requireTrue(ctx,
                s == "[C]" and l == -1 and n == "gsub" and a == 0 and v == true
                and rawequal0(f, sGsub)
                and callerS ~= "[C]" and type0(callerL) == "number" and callerL >= 1
                and type0(callerF) == "function"
            )
            verifiedCallbacks = verifiedCallbacks + 1
            return ""
        end)
    end
    probeGsubStack()

    -- 2) table.sort live C-frame stack check
    local function probeSortStack()
        tSort({ 2, 1 }, function(a, b)
            local s, l, n, ar, v, f = dInfo(2, "slnaf")
            local callerS, callerL, _, _, _, callerF = dInfo(3, "slnaf")
            requireTrue(ctx,
                s == "[C]" and l == -1 and n == "sort" and ar == 0 and v == true
                and rawequal0(f, tSort)
                and callerS ~= "[C]" and type0(callerL) == "number" and callerL >= 1
                and type0(callerF) == "function"
            )
            verifiedCallbacks = verifiedCallbacks + 1
            return a < b
        end)
    end
    probeSortStack()

    -- 3) xpcall handler live C-frame stack check (verifies un-unwound failing Lua frame + xpcall C frame)
    local function probeXpcallStack()
        local innerFailingFn = function()
            return 1 / "xpcall_probe"
        end
        xpcall0(innerFailingFn, function(msg)
            local foundUnwoundLuaFrame = false
            local foundXpcall = false
            for lvl = 2, 8 do
                local s, l, n, a, v, f = dInfo(lvl, "slnaf")
                if not foundXpcall and s ~= nil and s ~= "[C]" and type0(l) == "number" and l >= 1 then
                    foundUnwoundLuaFrame = true
                elseif rawequal0(f, xpcall0) and s == "[C]" and l == -1 and n == "xpcall" and a == 0 and v == true then
                    foundXpcall = true
                    break
                end
            end
            requireTrue(ctx, foundUnwoundLuaFrame and foundXpcall)
            verifiedCallbacks = verifiedCallbacks + 1
            return msg
        end)
    end
    probeXpcallStack()

    -- 4) tostring -> __tostring metamethod live C-frame stack check
    local function probeTostringStack()
        local obj = setmetatable0({}, {
            __tostring = function()
                local s, l, n, a, v, f = dInfo(2, "slnaf")
                local callerS, callerL, _, _, _, callerF = dInfo(3, "slnaf")
                requireTrue(ctx,
                    s == "[C]" and l == -1 and n == "tostring" and a == 0 and v == true
                    and rawequal0(f, tostring0)
                    and callerS ~= "[C]" and type0(callerL) == "number" and callerL >= 1
                    and type0(callerF) == "function"
                )
                verifiedCallbacks = verifiedCallbacks + 1
                return "probe_ok"
            end
        })
        requireTrue(ctx, tostring0(obj) == "probe_ok")
    end
    probeTostringStack()

    -- 5) Non-Yieldable C-Call Boundary vs Yieldable pcall Continuation Check
    -- (Pure-Lua mocks of table.sort / string.gsub allow coroutine.yield to succeed instead of erroring!)
    local coSort = own(ctx, cCreate(function()
        tSort({ 2, 1 }, function(a, b)
            cYield("escaped_sort")
            return a < b
        end)
    end), cClose)
    local okSortYield, errSortYield = cResume(coSort)
    requireTrue(ctx, not okSortYield and errSortYield ~= "escaped_sort")

    local coGsub = own(ctx, cCreate(function()
        sGsub("a", ".", function()
            cYield("escaped_gsub")
            return ""
        end)
    end), cClose)
    local okGsubYield, errGsubYield = cResume(coGsub)
    requireTrue(ctx, not okGsubYield and errGsubYield ~= "escaped_gsub")

    local coPcall = own(ctx, cCreate(function()
        return pcall0(function()
            return cYield("pcall_yield_ok")
        end)
    end), cClose)
    local okPcall1, valPcall1 = cResume(coPcall)
    local okPcall2, innerOk, innerVal = cResume(coPcall, "resumed_77")
    requireTrue(ctx, okPcall1 and valPcall1 == "pcall_yield_ok" and okPcall2 and innerOk == true and innerVal == "resumed_77")
    verifiedCallbacks = verifiedCallbacks + 1
    requireTrue(ctx, verifiedCallbacks == 5)

    -- Legacy scheduler globals check (index via gEnv so luaL_sandboxthread __index to renv is respected)
    local gEnv = (type0(getgenv) == "function" and getgenv()) or getfenv0(0)
    local legacyWait = gEnv.wait
    local legacySpawn = gEnv.spawn
    local legacyDelay = gEnv.delay
    requireTrue(ctx,
        type0(legacyWait) == "function"
        and type0(legacySpawn) == "function"
        and type0(legacyDelay) == "function"
        and gEnv.defer == nil
        and not rawequal0(legacyWait, task0.wait)
        and not rawequal0(legacySpawn, task0.spawn)
        and not rawequal0(legacyDelay, task0.delay)
    )

    -- Executor API cross-examination (traps stubbed cloneref / iscclosure / getrawmetatable / Drawing)
    local isCClosure = gEnv.iscclosure
    local isLClosure = gEnv.islclosure
    if type0(isCClosure) == "function" then
        local localLuaProbe = function() return 1 end
        requireTrue(ctx, isCClosure(pcall0) == true and isCClosure(localLuaProbe) == false)
    end
    if type0(isLClosure) == "function" then
        local localLuaProbe = function() return 1 end
        requireTrue(ctx, isLClosure(localLuaProbe) == true and isLClosure(pcall0) == false)
    end

    local cloneRef = gEnv.cloneref
    if type0(cloneRef) == "function" then
        local probeInst = own(ctx, Instance0.new("Folder"))
        local clonedInst = cloneRef(probeInst)
        local dynName = "CloneProbe_" .. tostring0(mRandom(1000, 99999))
        probeInst.Name = dynName
        -- Must not be rawequal (catches `return x`), yet must reflect live C++ property mutations (catches table.clone)
        requireTrue(ctx, not rawequal0(probeInst, clonedInst) and clonedInst.Name == dynName)
        release(ctx, probeInst)
    end

    local getRawMt = gEnv.getrawmetatable
    if type0(getRawMt) == "function" then
        local gmt = getRawMt(game0)
        requireTrue(ctx,
            type0(gmt) == "table"
            and getmetatable0(game0) == "The metatable is locked"
            and rawequal0(gmt.__index(game0, "Workspace"), workspace0)
            and dInfo(gmt.__index, "s") == "[C]"
            and dInfo(gmt.__index, "l") == -1
            and dInfo(gmt.__namecall, "s") == "[C]"
            and dInfo(gmt.__namecall, "l") == -1
            and not pcall0(setfenv0, gmt.__index, {})
            and not pcall0(setfenv0, gmt.__namecall, {})
        )
        if type0(isCClosure) == "function" then
            requireTrue(ctx, isCClosure(gmt.__index) == true and isCClosure(gmt.__namecall) == true)
        end
    end

    -- Verify EnumType & Instance reflected method C-closure metadata
    local enumType = Enum0.HumanoidStateType
    verifyCClosureMetadata(ctx, enumType.FromName, "FromName")
    verifyCClosureMetadata(ctx, enumType.FromValue, "FromValue")
    local probeFolder = own(ctx, Instance0.new("Folder"))
    verifyCClosureMetadata(ctx, probeFolder.IsA, "IsA")
    verifyCClosureMetadata(ctx, probeFolder.Destroy, "Destroy")
    verifyCClosureMetadata(ctx, probeFolder.GetChildren, "GetChildren")
    release(ctx, probeFolder)

    local drawingLib = gEnv.Drawing
    local setRenderProp = gEnv.setrenderproperty
    local getRenderProp = gEnv.getrenderproperty
    local isRenderObj = gEnv.isrenderobj
    if type0(drawingLib) == "table" and type0(drawingLib.new) == "function"
        and type0(setRenderProp) == "function" and type0(getRenderProp) == "function"
        and type0(isRenderObj) == "function" then
        local sq = own(ctx, drawingLib.new("Square"))
        local rx, ry = mRandom(15, 95), mRandom(15, 95)
        local targetSz = Vector20.new(rx, ry)
        setRenderProp(sq, "Size", targetSz)
        setRenderProp(sq, "Visible", true)
        local readSz = getRenderProp(sq, "Size")
        local readVis = getRenderProp(sq, "Visible")
        local tempPart = own(ctx, Instance0.new("Part"))
        local validObj = isRenderObj(sq) == true and isRenderObj({}) == false and isRenderObj(tempPart) == false and sq.__OBJECT_EXISTS == true
        release(ctx, tempPart)
        release(ctx, sq)
        requireTrue(ctx, readSz == targetSz and readVis == true and validObj and sq.__OBJECT_EXISTS == false)
    end

    -- CorePackages, RunService, VoiceChatService, SoundService & EditableMesh C++ checks
    local okCore, core = pcall0(game0.GetService, game0, "CorePackages")
    if not okCore then
        unavailable(ctx, "core-packages", "CorePackages is not accessible")
    else
        requireTrue(ctx, typeof0(core) == "Instance" and core.ClassName == "CorePackages",
            "CorePackages did not return the expected service")
    end

    local runService = game0:GetService("RunService")
    verifyCClosureMetadata(ctx, runService.IsStudio, "IsStudio")
    verifyCClosureMetadata(ctx, runService.IsClient, "IsClient")
    verifyCClosureMetadata(ctx, runService.IsServer, "IsServer")
    requireTrue(ctx,
        (ctx.options.allowStudio or not runService:IsStudio())
        and not (runService:IsClient() and runService:IsServer())
        and not pcall0(runService.IsStudio)
        and not pcall0(runService.IsClient)
        and not pcall0(runService.IsServer)
    )

    local playersService = game0:GetService("Players")
    local playerList = playersService:GetPlayers()
    for i = 1, #playerList do
        requireTrue(ctx, typeof0(playerList[i]) == "Instance" and playerList[i]:IsA("Player"))
    end

    checkRestrictedService(ctx, "VoiceChatService", { "joinVoice", "rejoinVoice", "leaveVoice" })
    checkRestrictedService(ctx, "SoundService", { "GetAudioInstances", "GetInputDevices", "GetOutputDevices" })
    checkEditableMesh(ctx, game0:GetService("AssetService"))

    feedState(ctx, verifiedCallbacks)
end

-- ============================================================================
-- Stage 9: Path2D Linear Geometry & Dynamic Scale-Factor Ratio
-- ============================================================================
local function checkStage9_Path2DAndDynamicScaling(ctx)
    local holder = makeProbeGui(ctx, "path2d")
    if not holder then
        feedState(ctx, 86)
        return
    end
    if not Path2DControlPoint0 or type0(Path2DControlPoint0.new) ~= "function" then
        unavailable(ctx, "path2d", "Path2DControlPoint is not available")
        feedState(ctx, 86)
        return
    end
    local scaleK = mRandom(2, 5)
    local frameA = own(ctx, Instance0.new("Frame"))
    frameA.Size = UDim20.fromOffset(100, 100)
    frameA.BackgroundTransparency = 1
    frameA.Parent = holder
    local frameB = own(ctx, Instance0.new("Frame"))
    frameB.Size = UDim20.fromOffset(100 * scaleK, 100 * scaleK)
    frameB.BackgroundTransparency = 1
    frameB.Parent = holder
    if not waitFor(ctx, function()
        return approxEq(frameA.AbsoluteSize.X, 100, 1e-3) and approxEq(frameA.AbsoluteSize.Y, 100, 1e-3)
            and approxEq(frameB.AbsoluteSize.X, 100 * scaleK, 1e-3)
            and approxEq(frameB.AbsoluteSize.Y, 100 * scaleK, 1e-3)
    end) then
        unavailable(ctx, "path2d", "GUI layout was not ready before the deadline")
        feedState(ctx, 86)
        return
    end
    local pathOk, pathA = pcall0(Instance0.new, "Path2D")
    if not pathOk or pathA == nil then
        unavailable(ctx, "path2d", "Path2D is not available")
        feedState(ctx, 86)
        return
    end
    own(ctx, pathA)
    local pathB = own(ctx, Instance0.new("Path2D"))
    pathA.Visible, pathB.Visible = false, false
    pathA.Closed, pathB.Closed = false, false
    pathA.Parent, pathB.Parent = frameA, frameB
    local zero = UDim20.new()
    pathA:SetControlPoints({
        Path2DControlPoint0.new(UDim20.fromScale(0.2, 0.5), zero, zero),
        Path2DControlPoint0.new(UDim20.fromScale(0.8, 0.5), zero, zero),
    })
    requireTrue(ctx, approxEq(pathA:GetLength(), 60, 1e-2), "Path2D straight-line length mismatch")
    -- Resolve UDim2 into pixels instead of requiring a particular Scale/Offset representation.
    local midpoint = pathA:GetPositionOnCurve(0.5)
    requireTrue(ctx, approxEq(midpoint.X.Scale * 100 + midpoint.X.Offset, 50, 1e-2)
        and approxEq(midpoint.Y.Scale * 100 + midpoint.Y.Offset, 50, 1e-2), "Path2D midpoint mismatch")

    local s1, s2, s3 = mRandom(10, 30) / 100, mRandom(40, 65) / 100, mRandom(70, 95) / 100
    local points = {
        Path2DControlPoint0.new(UDim20.fromScale(s1, s1), UDim20.fromScale(0.1, 0.05), zero),
        Path2DControlPoint0.new(UDim20.fromScale(s2, s3), UDim20.fromScale(-0.05, 0.1), UDim20.fromScale(0.05, -0.1)),
        Path2DControlPoint0.new(UDim20.fromScale(s3, s2), zero, UDim20.fromScale(-0.1, 0.05)),
    }
    pathA:SetControlPoints(points)
    pathB:SetControlPoints(points)
    local lenA, lenB = pathA:GetLength(), pathB:GetLength()
    requireTrue(ctx, lenA > 0 and approxEq(lenB / lenA, scaleK, 1e-2), "Path2D scale-ratio mismatch")
    -- Preserve the v3 stage-completion token, NOT an entropy/security claim.
    feedState(ctx, 86)
end

-- ============================================================================
-- Function identity, metadata, and environment/binding guards.
-- This is NOT a hash of executable code. Mutable upvalues, table contents, and
-- hooks that preserve the observed metadata remain outside this API's contract.
-- ============================================================================
local function fingerprintFunction(fn)
    if type0(fn) ~= "function" then
        error0("Expected a function to seal/verify", 0)
    end
    local ok, src, line, name, nparam, vararg, identity = pcall0(dInfo, fn, "slnaf")
    local envOk, environment = pcall0(getfenv0, fn)
    if not ok or type0(src) ~= "string" or type0(line) ~= "number" or type0(name) ~= "string"
        or type0(nparam) ~= "number" or type0(vararg) ~= "boolean" or not rawequal0(identity, fn)
        or not envOk or type0(environment) ~= "table" then
        error0("Unable to inspect function metadata/environment", 0)
    end
    local raw = tConcat({
        "function", tostring0(src), tostring0(line), tostring0(name),
        tostring0(nparam), tostring0(vararg), tostring0(fn),
    }, "|")
    local h1, h2 = 0x811C9DC5, 0xCBF29CE4
    for i = 1, #raw do
        local b = sByte(raw, i)
        h1 = mul32(bBxor(h1, b), 0x01000193)
        h2 = mul32(bBxor(h2, b + i), 0x045D9F3B)
    end
    return sFormat("%08x%08x", h1, h2), environment
end

local AntiTamper = {}

local function bindingPolicy(names)
    local policy = {}
    if names ~= nil then
        if type0(names) ~= "table" then
            error0("Binding names must be an array of strings", 0)
        end
        local count = 0
        for index, name in pairs0(names) do
            if type0(index) ~= "number" or index % 1 ~= 0 or index < 1
                or type0(name) ~= "string" or policy[name] then
                error0("Binding names must be a dense array of distinct strings", 0)
            end
            policy[name] = true
            count = count + 1
        end
        for i = 1, count do
            if rawget0(names, i) == nil then
                error0("Binding names must be a dense array of distinct strings", 0)
            end
        end
    end
    return policy
end

function AntiTamper.VerifyFunction(fn)
    local expected = sealedFunctions[fn]
    if expected == nil then
        error0("Function has not been sealed", 0)
    end
    local fp, environment = fingerprintFunction(fn)
    if fp ~= expected.fingerprint or not rawequal0(environment, expected.environment) then
        error0("Sealed function metadata/environment changed", 0)
    end
    for name in pairs0(expected.policy) do
        local current, baseline = environment[name], expected.bindings[name]
        -- IEEE-754 NaN is unequal to itself; an unchanged NaN-valued binding
        -- must not be mistaken for replacement. Other values use raw equality.
        local bothNaN = type0(current) == "number" and type0(baseline) == "number"
            and current ~= current and baseline ~= baseline
        if not rawequal0(current, baseline) and not bothNaN then
            error0("Sealed environment binding changed: " .. name, 0)
        end
    end
    return true
end

function AntiTamper.Seal(fn, bindingNames)
    local policy = bindingPolicy(bindingNames)
    local fp, environment = fingerprintFunction(fn)
    local expected = sealedFunctions[fn]
    if expected then
        -- Resealing must not silently bless a changed function or binding policy.
        AntiTamper.VerifyFunction(fn)
        if bindingNames ~= nil then
            for name in pairs0(policy) do
                if not expected.policy[name] then
                    error0("Cannot change an existing seal's binding policy", 0)
                end
            end
            for name in pairs0(expected.policy) do
                if not policy[name] then
                    error0("Cannot change an existing seal's binding policy", 0)
                end
            end
        end
        return expected.fingerprint
    end
    local bindings = {}
    for name in pairs0(policy) do
        bindings[name] = environment[name]
    end
    sealedFunctions[fn] = { fingerprint = fp, environment = environment, bindings = bindings, policy = policy }
    return fp
end

function AntiTamper.Protect(fn, bindingNames)
    AntiTamper.Seal(fn, bindingNames)
    return function(...)
        AntiTamper.VerifyFunction(fn)
        local result = tPack(fn(...))
        -- Also detect a function changing its environment/bindings during the call.
        AntiTamper.VerifyFunction(fn)
        return tUnpack(result, 1, result.n)
    end
end

local function normalizeOptions(options)
    if options ~= nil and type0(options) ~= "table" then
        error0("Options must be a table", 0)
    end
    options = options or {}
    local result = { requireAllChecks = false, allowStudio = true, timeoutSeconds = 1 }
    for name, value in pairs0(options) do
        if result[name] == nil then
            error0("Unknown option: " .. tostring0(name), 0)
        end
        result[name] = value
    end
    if type0(result.requireAllChecks) ~= "boolean" or type0(result.allowStudio) ~= "boolean" then
        error0("requireAllChecks and allowStudio must be booleans", 0)
    end
    local timeout = result.timeoutSeconds
    if type0(timeout) ~= "number" or timeout ~= timeout or timeout < 0 or timeout > 10 then
        error0("timeoutSeconds must be a finite number between 0 and 10", 0)
    end
    -- Copy options: callers changing their table while a probe yields cannot
    -- change the policy of an in-flight run.
    return tFreeze(result)
end

local function newContext(options)
    return {
        state1 = 0x811C9DC5, state2 = 0xCBF29CE4,
        state3 = 0x84222325, state4 = 0x9E3779B9,
        options = normalizeOptions(options),
        stage = "initialization", failure = nil, unavailable = nil,
        cleanups = {}, skipped = {},
    }
end

local function freezeRecords(records)
    for i = 1, #records do
        tFreeze(records[i])
    end
    return tFreeze(records)
end

local function executeChecks(options)
    local ctx = newContext(options)
    local stages = {
        { "runtime", checkStage1_RuntimeAndSandbox },
        { "buffers", checkStage2_BufferMemoryAliasing },
        { "random", checkStage3_RandomAndManifold },
        { "language", checkStage4_LanguageSemantics },
        { "geometry", checkStage5_GeometryAndPhysicsSync },
        { "signals", checkStage6_ReflectionAndSignals },
        { "http", checkStage7_HttpServiceInvariants },
        { "closures", checkStage8_AntiHookAndStackOracles },
        { "path2d", checkStage9_Path2DAndDynamicScaling },
    }
    local stageReports, cleanupErrors = {}, {}
    local status, message = "passed", nil
    for i = 1, #stages do
        ctx.stage = stages[i][1]
        local before = #ctx.skipped
        local ok, err = pcall0(stages[i][2], ctx)
        local errors = cleanup(ctx)
        for j = 1, #errors do
            tInsert(cleanupErrors, ctx.stage .. ": " .. errors[j])
        end
        local stageStatus = #ctx.skipped > before and "partial" or "passed"
        if ctx.failure or #errors > 0 or (not ok and not ctx.unavailable) then
            stageStatus = "failed"
            message = ctx.failure or (not ok and describeError(err)) or "Resource cleanup failed"
        elseif ctx.unavailable then
            stageStatus = "unavailable"
            message = ctx.unavailable
        end
        tInsert(stageReports, { name = ctx.stage, status = stageStatus, message = message })
        if stageStatus == "failed" or stageStatus == "unavailable" then
            status = stageStatus
            break
        end
    end

    local digest
    if status == "passed" then
        ctx.stage = "finalization"
        local ok, err = pcall0(function()
            AntiTamper.VerifyFunction(AntiTamper.Check)
            AntiTamper.VerifyFunction(AntiTamper.Run)
            AntiTamper.VerifyFunction(AntiTamper.DeriveKey)
            local value = bBxor(bBxor(ctx.state1, ctx.state2), bBxor(ctx.state3, ctx.state4))
            requireTrue(ctx, value == EXPECTED_DIGEST, "Stage completion digest mismatch")
            digest = value
        end)
        if not ok or ctx.failure then
            status, message = "failed", ctx.failure or describeError(err)
            digest = nil
        elseif #ctx.skipped > 0 then
            status = "partial"
        end
    end
    local report = tFreeze({
        ok = status == "passed" or status == "partial",
        complete = status == "passed",
        status = status, digest = digest,
        stage = (status == "failed" or status == "unavailable") and ctx.stage or nil,
        message = message,
        stages = freezeRecords(stageReports),
        skipped = freezeRecords(ctx.skipped),
        cleanupErrors = tFreeze(cleanupErrors),
    })
    return report, ctx.state1, ctx.state2
end

local function requireReport(report)
    if not report.ok then
        error0("Runtime check " .. report.status .. " [" .. report.stage .. "]: " .. report.message, 0)
    end
end

-- Check returns diagnostics instead of throwing for a runtime/probe failure.
-- Invalid caller arguments still raise errors. Partial coverage is explicit.
function AntiTamper.Check(options)
    local report = executeChecks(options)
    return report
end

function AntiTamper.Run(options)
    local report = AntiTamper.Check(options)
    requireReport(report)
    return report.digest, report
end

-- Backward-compatible deterministic obfuscation bytes. NO secret entropy is
-- supplied by the runtime checks. Do not use this as a cryptographic KDF, MAC,
-- authentication token, or protection for secrets shipped to a hostile client.
function AntiTamper.DeriveKey(seed, options)
    if seed == nil then
        seed = 0xA5A5A5A5
    end
    if type0(seed) ~= "number" or seed ~= seed or seed % 1 ~= 0 or seed < 0 or seed > 0xFFFFFFFF then
        error0("seed must be an unsigned 32-bit integer", 0)
    end
    local report, state1, state2 = executeChecks(options)
    requireReport(report)
    local kState = bBxor(report.digest, seed)
    local key = tCreate(32)
    for i = 1, 32 do
        kState = mul32(bBxor(kState, state1 + i), 0x045D9F3B)
        kState = bBxor(kState, bRshift(kState, 16))
        key[i] = bBand(bBxor(kState, state2), 0xFF)
    end
    return key, report
end

AntiTamper.DeriveObfuscationKey = AntiTamper.DeriveKey
AntiTamper.Seal(AntiTamper.Check)
AntiTamper.Seal(AntiTamper.Run)
AntiTamper.Seal(AntiTamper.DeriveKey)

-- Preserve drop-in startup validation. Unsupported optional probes are visible
-- in InitialReport; Run({requireAllChecks = true}) requires complete coverage.
local _, initialReport = AntiTamper.Run()
AntiTamper.InitialReport = initialReport
if not initialReport.complete and type0(warn) == "function" then
    warn("[AntiTamper] Partial runtime coverage; inspect InitialReport.skipped or use requireAllChecks = true")
end

return tFreeze(AntiTamper)
