-- Appended to an instrumented TEMPORARY copy by run.py; not a Roblox script.
local tests = {}
local function test(name, fn) table.insert(tests, {name, fn}) end
local function equal(actual, expected)
    assert(actual == expected, "expected " .. tostring(expected) .. ", got " .. tostring(actual))
end
local function rejects(fn, expected)
    local ok, err = pcall(fn)
    assert(not ok, "expected an error")
    if expected then
        assert(string.find(tostring(err), expected, 1, true), tostring(err))
    end
end
local function keyHex(key)
    local out = {}
    for i, byte in ipairs(key) do
        assert(byte >= 0 and byte <= 255 and byte % 1 == 0)
        out[i] = string.format("%02x", byte)
    end
    equal(#key, 32)
    return table.concat(out)
end
local saved = {
    task = task0, clock = clock0, game = game0, instance = Instance0,
    vector = Vector30, cframe = CFrame0, udim = UDim20, point = Path2DControlPoint0,
    typeof = typeof0, metadata = verifyCClosureMetadata, debugInfo = dInfo,
}
local function restore()
    table.clear(testHooks)
    task0, clock0, game0, Instance0 = saved.task, saved.clock, saved.game, saved.instance
    Vector30, CFrame0, UDim20, Path2DControlPoint0 = saved.vector, saved.cframe, saved.udim, saved.point
    typeof0, verifyCClosureMetadata, dInfo = saved.typeof, saved.metadata, saved.debugInfo
end

-- Minimal fixtures for testing probe control flow, NOT engine implementations.
local function fakeHost(mode)
    mode = mode or {}
    local destroyed, objects = {}, {}
    local vectorMt = {}
    local function vec(x, y, z) return setmetatable({X = x, Y = y, Z = z}, vectorMt) end
    vectorMt.__unm = function(v) return vec(-v.X, -v.Y, -v.Z) end
    Vector30 = {new = vec, zero = vec(0, 0, 0)}
    CFrame0 = {new = vec}
    local function udim(xs, xo, ys, yo)
        return {X = {Scale = xs, Offset = xo}, Y = {Scale = ys, Offset = yo}}
    end
    UDim20 = {
        new = function() return udim(0, 0, 0, 0) end,
        fromOffset = function(x, y) return udim(0, x, 0, y) end,
        fromScale = function(x, y) return udim(x, 0, y, 0) end,
    }
    Path2DControlPoint0 = {new = function(position, left, right)
        return {position = position, left = left, right = right}
    end}
    local gui = {}
    game0 = {GetService = function(_, name)
        equal(name, "Players")
        if mode.noPlayer then return {} end
        return {LocalPlayer = {FindFirstChildOfClass = function(_, class)
            equal(class, "PlayerGui")
            return gui
        end}}
    end}
    typeof0 = function(value)
        if type(value) == "table" and value.class then return "Instance" end
        return saved.typeof(value)
    end
    task0 = nil -- Synchronous fixtures; timeout paths don't need wall-clock waits.
    Instance0 = {new = function(class)
        if class == "Path2D" and mode.noPath then error("class unavailable") end
        local obj = {class = class}
        table.insert(objects, obj)
        function obj:Destroy() table.insert(destroyed, self.class) end
        function obj:IsA(name) return name == "WorldRoot" or name == "Model" end
        if class == "WorldModel" then
            function obj:Raycast(origin, direction)
                assert(self and self.class == "WorldModel", "missing receiver")
                assert(type(origin) == "table" and type(direction) == "table", "invalid vectors")
                equal(self.Parent.class, "ViewportFrame")
                equal(self.Parent.Parent.class, "ScreenGui")
                if mode.nilRay or direction.Z > 0 then return nil end
                local part = mode.part
                assert(part and part.Parent == self and part.CanQuery)
                local hitZ = part.CFrame.Z + part.Size.Z / 2
                return {
                    Instance = part, Distance = -hitZ,
                    Position = vec(origin.X, origin.Y, hitZ),
                    Normal = vec(0, 0, mode.badNormal and -1 or 1),
                }
            end
        elseif class == "Frame" then
            setmetatable(obj, {__index = function(self, key)
                if key == "AbsoluteSize" then
                    return mode.noLayout and vec(0, 0, 0) or vec(self.Size.X.Offset, self.Size.Y.Offset, 0)
                end
            end})
        elseif class == "Path2D" then
            function obj:SetControlPoints(points) self.points = points end
            function obj:GetLength()
                equal(self.Closed, false)
                local size = self.Parent.AbsoluteSize
                if #self.points == 2 then return size.X * 0.6 end
                -- The test only needs a positive homogeneous length function.
                return mode.badScale and 72 or size.X * 0.72
            end
            function obj:GetPositionOnCurve(t)
                equal(t, 0.5)
                -- Exercise alternate but equivalent Scale/Offset representation.
                return udim(0, 50, 0, 50)
            end
        end
        return obj
    end}
    return mode, destroyed, objects
end

local function fakeMesh(mode)
    mode = mode or {}
    local positions, count = {}, 0
    local mesh = {destroyed = 0}
    function mesh:Destroy() self.destroyed += 1 end
    function mesh:AddVertex(position)
        if mode.addError then error("vertex allocation failed") end
        count += 1
        positions[count] = position
        return count
    end
    function mesh:GetPosition(id)
        assert(positions[id], "invalid vertex")
        return positions[id]
    end
    if not mode.noMutation then
        function mesh:SetPosition(id, position)
            if not mode.ignoreMutation then positions[id] = position end
        end
    end
    local service = {CreateEditableMesh = function()
        if mode.createError then error("permission denied") end
        if mode.empty then return nil end
        return mesh
    end}
    -- Fixtures are Lua functions, not native engine C closures. Metadata is
    -- covered separately against real Luau natives; never stubbed in production.
    verifyCClosureMetadata = function() end
    return service, mesh
end

test("native buffer/language checks and compatible digest", function()
    local digest, report = AntiTamper.Run()
    equal(digest, 0xEAECA79E)
    equal(report.status, "passed")
    assert(report.complete and #report.stages == 9)
    assert(table.isfrozen(AntiTamper) and table.isfrozen(AntiTamper.InitialReport))
    assert(table.isfrozen(report) and table.isfrozen(report.stages) and table.isfrozen(report.stages[1]))
end)

test("real Luau C-stack metadata and yield-boundary probes", function()
    testHooks.closures = checkNativeStackProbes
    equal(AntiTamper.Check().status, "passed")
end)

test("keys are deterministic, compatible, and seed-sensitive", function()
    local key = AntiTamper.DeriveKey()
    equal(keyHex(key), "97158df9d19f49a6a9618216e4a8ce073276d1a76be479f5b4a280bf30c63bec")
    equal(keyHex(AntiTamper.DeriveObfuscationKey()), keyHex(key))
    assert(keyHex(AntiTamper.DeriveKey(1)) ~= keyHex(AntiTamper.DeriveKey(2)))
end)

test("overlapping Run calls keep independent state", function()
    testHooks.signals = function() coroutine.yield("signals") end
    local first, second = coroutine.create(AntiTamper.Run), coroutine.create(AntiTamper.Run)
    for _, thread in {first, second} do
        local ok, value = coroutine.resume(thread)
        assert(ok); equal(value, "signals")
    end
    for _, thread in {first, second} do
        local ok, digest, report = coroutine.resume(thread)
        assert(ok, digest); equal(digest, 0xEAECA79E); equal(report.status, "passed")
    end
    testHooks.signals = nil
    equal(AntiTamper.Run(), 0xEAECA79E)
end)

test("overlapping DeriveKey calls use their own verified state", function()
    local expectedA = keyHex(AntiTamper.DeriveKey(17))
    local expectedB = keyHex(AntiTamper.DeriveKey(91))
    testHooks.signals = function() coroutine.yield("signals") end
    local first = coroutine.create(function() return AntiTamper.DeriveKey(17) end)
    local second = coroutine.create(function() return AntiTamper.DeriveKey(91) end)
    assert(coroutine.resume(first)); assert(coroutine.resume(second))
    local okA, keyA = coroutine.resume(first)
    local okB, keyB = coroutine.resume(second)
    assert(okA and okB)
    equal(keyHex(keyA), expectedA); equal(keyHex(keyB), expectedB)
end)

test("one failed invocation does not poison another", function()
    local calls = 0
    testHooks.signals = function(ctx)
        calls += 1
        local shouldFail = calls == 1
        coroutine.yield()
        if shouldFail then trap(ctx, "intentional first-call failure") end
    end
    local a, b = coroutine.create(AntiTamper.Check), coroutine.create(AntiTamper.Check)
    assert(coroutine.resume(a)); assert(coroutine.resume(b))
    local okA, reportA = coroutine.resume(a)
    local okB, reportB = coroutine.resume(b)
    assert(okA and okB)
    equal(reportA.status, "failed"); equal(reportB.status, "passed")
end)

test("swallowed assertions still fail their own stage", function()
    local disposed = 0
    testHooks.runtime = function(ctx)
        own(ctx, {}, function() disposed += 1 end)
        pcall(function() trap(ctx, "swallowed failure") end)
    end
    local report = AntiTamper.Check()
    equal(report.status, "failed"); equal(report.stage, "runtime")
    equal(report.message, "swallowed failure"); equal(report.digest, nil); equal(disposed, 1)
end)

test("altered stage tokens cannot produce a key", function()
    testHooks.signals = function(ctx) feedState(ctx, 99) end
    equal(AntiTamper.Check().status, "failed")
    rejects(function() AntiTamper.DeriveKey() end, "digest mismatch")
end)

test("cleanup runs in reverse order after an API exception", function()
    local order = {}
    testHooks.geometry = function(ctx)
        for i = 1, 3 do
            own(ctx, {}, function() table.insert(order, i) end)
        end
        error("unexpected engine exception")
    end
    local report = AntiTamper.Check()
    equal(report.status, "failed"); equal(report.stage, "geometry")
    equal(table.concat(order, ","), "3,2,1")
    assert(string.find(report.message, "unexpected engine exception", 1, true))
end)

test("released resources aren't disposed twice", function()
    local count = 0
    testHooks.geometry = function(ctx)
        local resource = own(ctx, {}, function() count += 1 end)
        release(ctx, resource); release(ctx, resource)
    end
    equal(AntiTamper.Check().status, "passed"); equal(count, 1)
end)

test("cleanup errors don't prevent remaining cleanup or mask primary failure", function()
    local count = 0
    testHooks.geometry = function(ctx)
        own(ctx, {}, function() count += 1 end)
        own(ctx, {}, function() error("dispose failed") end)
        trap(ctx, "primary failure")
    end
    local report = AntiTamper.Check()
    equal(report.message, "primary failure"); equal(count, 1)
    equal(#report.cleanupErrors, 1)
end)

test("strict unavailability disposes allocations made earlier in the stage", function()
    local count = 0
    testHooks.geometry = function(ctx)
        own(ctx, {}, function() count += 1 end)
        unavailable(ctx, "resource", "not ready")
    end
    local report = AntiTamper.Check({requireAllChecks = true})
    equal(report.status, "unavailable"); equal(count, 1)
end)

test("hostile error formatting cannot stop cleanup or escape Check", function()
    local count = 0
    local bad = setmetatable({}, {__tostring = function() error("cannot format") end})
    testHooks.geometry = function(ctx)
        own(ctx, {}, function() count += 1 end)
        own(ctx, {}, function() error(bad) end)
        error(bad)
    end
    local report = AntiTamper.Check()
    equal(report.status, "failed"); equal(report.message, "Unprintable error value")
    equal(count, 1); equal(#report.cleanupErrors, 1)
end)

test("resource unavailability is partial by default, unavailable in strict mode", function()
    testHooks.signals = function(ctx) unavailable(ctx, "probe", "resource budget") end
    local report = AntiTamper.Check()
    assert(report.ok and not report.complete)
    equal(report.status, "partial"); equal(report.skipped[1].reason, "resource budget")
    rejects(function() report.skipped[1].reason = "changed" end)
    local strict = AntiTamper.Check({requireAllChecks = true})
    assert(not strict.ok); equal(strict.status, "unavailable"); equal(strict.digest, nil)
    rejects(function() AntiTamper.Run({requireAllChecks = true}) end, "unavailable")
    rejects(function() AntiTamper.DeriveKey(1, {requireAllChecks = true}) end, "unavailable")
end)

test("options are snapshotted before yielding", function()
    local options = {requireAllChecks = true}
    testHooks.signals = function(ctx)
        coroutine.yield()
        unavailable(ctx, "probe", "budget exhausted")
    end
    local thread = coroutine.create(function() return AntiTamper.Check(options) end)
    assert(coroutine.resume(thread)); options.requireAllChecks = false
    local ok, report = coroutine.resume(thread)
    assert(ok); equal(report.status, "unavailable")
end)

test("bad options and seeds fail before doing work", function()
    local calls = 0
    testHooks.runtime = function() calls += 1 end
    for _, options in {true, {typo = true}, {requireAllChecks = 1}, {allowStudio = 1},
        {timeoutSeconds = -1}, {timeoutSeconds = math.huge}, {timeoutSeconds = 0/0}} do
        rejects(function() AntiTamper.Check(options) end)
    end
    for _, seed in {true, "1", -1, 0.5, 0x100000000, math.huge, 0/0} do
        rejects(function() AntiTamper.DeriveKey(seed) end)
    end
    equal(calls, 0)
    equal(#AntiTamper.DeriveKey(0), 32)
    equal(#AntiTamper.DeriveKey(0xFFFFFFFF), 32)
end)

test("scheduler waits are bounded even when the clock doesn't advance", function()
    local count = 0
    clock0 = function() return 0 end
    task0 = {wait = function() count += 1 end}
    assert(not waitFor(newContext(), function() return false end)); equal(count, 120)
    count = 0
    assert(waitFor(newContext(), function() return count == 3 end)); equal(count, 3)
    count = 0
    assert(not waitFor(newContext({timeoutSeconds = 0}), function() return false end)); equal(count, 0)
end)

test("seals detect environment replacement and refuse resealing it", function()
    local function fn() return allowed end
    setfenv(fn, {allowed = true})
    local guarded = AntiTamper.Protect(fn)
    equal(guarded(), true)
    setfenv(fn, {allowed = false})
    rejects(function() AntiTamper.VerifyFunction(fn) end, "environment changed")
    rejects(function() AntiTamper.Seal(fn) end, "environment changed")
    rejects(guarded, "environment changed")
end)

test("watched environment bindings cannot be silently replaced", function()
    local function fn() return dependency() end
    local env = {dependency = function() return 7 end}
    setfenv(fn, env)
    local guarded = AntiTamper.Protect(fn, {"dependency", "initiallyMissing"})
    equal(guarded(), 7)
    equal(AntiTamper.Seal(fn), AntiTamper.Seal(fn, {"initiallyMissing", "dependency"}))
    env.initiallyMissing = true
    rejects(guarded, "initiallyMissing")
    env.initiallyMissing = nil
    env.dependency = function() return 9 end
    rejects(guarded, "dependency")
    rejects(function() AntiTamper.Seal(fn) end, "dependency")
end)

test("unchanged NaN bindings do not trigger a false detection", function()
    local function fn() return sentinel end
    local env = {sentinel = 0/0}
    setfenv(fn, env)
    local guarded = AntiTamper.Protect(fn, {"sentinel"})
    local result = guarded()
    assert(result ~= result)
    equal(AntiTamper.VerifyFunction(fn), true)
    env.sentinel = 17
    rejects(guarded, "sentinel")
end)

test("binding-list metatables cannot conceal sparse indices", function()
    local function fn() return 1 end
    local sparse = setmetatable({[1] = "x", [3] = "y"}, {
        __index = function() return "fabricated" end,
    })
    rejects(function() AntiTamper.Seal(fn, sparse) end, "dense array")
end)

test("sealing rejects failed or malformed metadata instead of hashing placeholders", function()
    local function fn() end
    dInfo = function() error("metadata failed") end
    rejects(function() AntiTamper.Seal(fn) end, "Unable to inspect")
    dInfo = function(candidate) return nil, -1, "", 0, true, candidate end
    rejects(function() AntiTamper.Seal(fn) end, "Unable to inspect")
end)

test("binding policy is validated and cannot be weakened by resealing", function()
    local function fn() return 1 end
    for _, names in {true, {[2] = "x"}, {"x", "x"}, {1}, {[-1] = "x"}} do
        rejects(function() AntiTamper.Seal(fn, names) end)
    end
    AntiTamper.Seal(fn, {"x"})
    rejects(function() AntiTamper.Seal(fn, {}) end, "binding policy")
    rejects(function() AntiTamper.Seal(fn, {"x", "y"}) end, "binding policy")
    rejects(function() AntiTamper.VerifyFunction(function() end) end, "not been sealed")
end)

test("Protect preserves argument and result nil holes, zero returns, and errors", function()
    local guarded = AntiTamper.Protect(function(...) equal(select("#", ...), 3); return ... end)
    local result = table.pack(guarded(1, nil, 3))
    equal(result.n, 3); equal(result[1], 1); equal(result[2], nil); equal(result[3], 3)
    equal(select("#", AntiTamper.Protect(function() end)()), 0)
    local trailing = table.pack(AntiTamper.Protect(function() return nil, 17, nil end)())
    equal(trailing.n, 3); equal(trailing[1], nil); equal(trailing[2], 17); equal(trailing[3], nil)
    rejects(AntiTamper.Protect(function() error("payload error") end), "payload error")
end)

test("Protect supports yields and detects environment changes during a call", function()
    local fn
    fn = function() coroutine.yield("paused"); return 17, nil, 29 end
    local wrapped = AntiTamper.Protect(fn)
    local thread = coroutine.create(wrapped)
    local ok, value = coroutine.resume(thread); assert(ok); equal(value, "paused")
    local ok2, a, b, c = coroutine.resume(thread); assert(ok2); equal(a, 17); equal(b, nil); equal(c, 29)
    local function mutating() setfenv(mutating, {}); return true end
    rejects(AntiTamper.Protect(mutating), "environment changed")
end)

test("mutable upvalues remain explicitly outside the sealing contract", function()
    local state = {value = 1}
    local guarded = AntiTamper.Protect(function() return state.value end)
    equal(guarded(), 1); state.value = 2; equal(guarded(), 2)
end)

test("EditableMesh nil/permission results are availability, not tamper failures", function()
    fakeHost()
    for _, mode in {{empty = true}, {createError = true}} do
        local service, mesh = fakeMesh(mode)
        testHooks.closures = function(ctx) checkEditableMesh(ctx, service) end
        equal(AntiTamper.Check().status, "partial")
        equal(AntiTamper.Check({requireAllChecks = true}).status, "unavailable")
        equal(mesh.destroyed, 0)
    end
end)

test("EditableMesh checks mutation and always disposes its allocation", function()
    fakeHost()
    for _, mode in {{}, {ignoreMutation = true}, {addError = true}, {noMutation = true}} do
        local service, mesh = fakeMesh(mode)
        testHooks.closures = function(ctx) checkEditableMesh(ctx, service) end
        local expected = next(mode) == nil and "passed" or "failed"
        equal(AntiTamper.Check().status, expected)
        equal(mesh.destroyed, 1)
    end
end)

test("WorldModel requires a positive hit and cleans up its fixture", function()
    for _, mode in {{}, {nilRay = true}, {badNormal = true}} do
        local config, destroyed = fakeHost(mode)
        testHooks.geometry = function(ctx)
            config.part = own(ctx, Instance0.new("Part"))
            checkWorldModelRaycast(ctx, config.part)
        end
        local expected = (mode.nilRay or mode.badNormal) and "failed" or "passed"
        equal(AntiTamper.Check().status, expected)
        equal(#destroyed, 4)
    end
end)

test("UI probes report absent PlayerGui instead of querying StarterGui", function()
    fakeHost({noPlayer = true})
    local ctx = newContext()
    checkRealPathProbe(ctx)
    equal(ctx.skipped[1].check, "path2d"); equal(#cleanup(ctx), 0)
    testHooks.geometry = function(c) checkWorldModelRaycast(c, {}) end
    equal(AntiTamper.Check().status, "partial")
end)

test("Path2D checks live layout, midpoint representation, and scale ratio", function()
    for _, mode in {{}, {badScale = true}, {noLayout = true}, {noPath = true}} do
        local _, destroyed, objects = fakeHost(mode)
        local ctx = newContext()
        local ok, err = pcall(checkRealPathProbe, ctx)
        equal(#cleanup(ctx), 0)
        equal(#destroyed, #objects)
        if mode.badScale then
            assert(not ok and string.find(tostring(err), "scale-ratio", 1, true))
        else
            assert(ok, err)
            equal(#ctx.skipped, (mode.noLayout or mode.noPath) and 1 or 0)
        end
    end
end)

local failed = 0
for _, entry in tests do
    restore()
    local ok, err = pcall(entry[2])
    if ok then
        print("PASS " .. entry[1])
    else
        failed += 1
        print("FAIL " .. entry[1] .. ": " .. tostring(err))
    end
end
restore()
print(string.format("%d/%d tests passed", #tests - failed, #tests))
assert(failed == 0, tostring(failed) .. " regression test(s) failed")
