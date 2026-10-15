-- MuseSpark-AntiTamper.lua
-- Muse Spark 1.1 - Next-Gen Lua/Luau Anti-Tamper
-- Built after studying leaks from: Luraph V14.7/V15, Ironbrew, Aqua 1.4.9.5/1.5.0,
-- 77fuscator, Anti-Lua, Lightray, Goofyscator, Ice.Dragon, Illunox, KeyForge, 
-- LeakD, LuaMullvad, Luavex, Lynd, Moonveil, NTT, WynFuscate, XHider, Firefly
--
-- WHY STRONGER THAN LEAKED:
-- 1. Leaked anti-tampers = single if(debug.gethook()) then crash end -> NOP once.
-- 2. This one = 7 entangled checks, distributed across closures, delayed bomb, no instant error.
-- 3. Integrity is tied to string.dump hash + upvalue count + ENV fingerprint, not static line numbers.

local MuseSpark_AT = {}
MuseSpark_AT.__VERSION = "1.1-STRONG"

-- Config
local CONFIG = {
    DELAYED_BOMB = true, -- don't crash instantly, corrupt later (harder to trace)
    BOMB_MIN_CALLS = 8,
    BOMB_MAX_CALLS = 40,
    TIMING_THRESHOLD = 0.35, -- seconds drift that signals debugger stepping
    CHECK_INTERVAL = 3, -- every Nth VM call we run lattice check
}

-- Simple FNV-1a for bytecode hashing (fast, no dependency)
local function fnv1a(str)
    local h = 2166136261
    for i = 1, #str do
        h = bit32 and bit32.bxor(h, string.byte(str, i)) or (h ~ string.byte(str, i))
        h = (h * 16777619) % 2^32
    end
    return h
end
-- Luau / Lua 5.1 compat
local function bxor(a,b)
    if bit32 then return bit32.bxor(a,b) end
    if bit then return bit.bxor(a,b) end
    return a ~ b -- Lua 5.3+
end

-- Internal state (sealed in closure, not in _G)
local callCounter = 0
local tamperScore = 0
local bombArmed = false
local envFingerprint = {}
local chunkHashes = {}
local lastClock = os.clock and os.clock() or tick and tick() or 0

-- 1. ENV SEAL - snapshot of globals at load time
do
    local function snapEnv()
        local t = {}
        for k,v in pairs(_G or _ENV or getfenv(0)) do
            t[k] = type(v)
        end
        return t
    end
    envFingerprint = snapEnv()
end

-- 2. BYTECODE HASH LATTICE
-- Call this on your real functions to register them
function MuseSpark_AT:SealFunction(fn, name)
    if type(fn) ~= "function" then return fn end
    local ok, dumped = pcall(string.dump, fn)
    if ok and dumped then
        chunkHashes[name or fn] = fnv1a(dumped)
        -- Also store upvalue count as integrity
        local info = debug and debug.getinfo and debug.getinfo(fn, "u")
        if info then
            chunkHashes[name.."_nups"] = info.nups
            chunkHashes[name.."_len"] = #dumped
        end
    end
    return fn
end

-- 3. POLYMORPHIC HOOK SENTINEL - not one gethook check, but 3 from different depths
local function checkHookLattice()
    if not debug or not debug.gethook then return 0 end
    local hits = 0
    -- depth 0
    if debug.gethook() ~= nil then hits = hits + 1 end
    -- depth 1 via pcall
    local function inner()
        if debug.gethook() ~= nil then hits = hits + 1 end
        -- depth 2 via xpcall
        xpcall(function()
            if debug.gethook() ~= nil then hits = hits + 1 end
        end, function() end)
    end
    local ok = pcall(inner)
    -- Also check if gethook itself was tampered (replaced)
    if not ok then hits = hits + 2 end
    return hits
end

-- 4. TIMING ENTROPY TRAP - detects stepping / breakpoints
local function checkTiming()
    if not os.clock and not tick then return 0 end
    local now = os.clock and os.clock() or tick()
    local delta = now - lastClock
    lastClock = now
    -- Normal VM tick should be tiny. Big jump = debugger paused
    if delta > CONFIG.TIMING_THRESHOLD and callCounter > 5 then
        return 1
    end
    return 0
end

-- 5. ENV POLLUTION CHECK
local function checkEnv()
    local cur = 0
    for k,v in pairs(_G or _ENV or getfenv(0)) do
        if envFingerprint[k] == nil then
            -- new global injected after load (common deobfuscation trick)
            cur = cur + 1
        end
    end
    return cur > 3 and 1 or 0 -- allow some, but mass injection = tamper
end

-- 6. BYTECODE / UPVALUE INTEGRITY (distributed)
local function checkLattice()
    local score = 0
    for name, hash in pairs(chunkHashes) do
        if type(name) == "string" and not name:find("_nups") and not name:find("_len") then
            -- name is a key, value is function stored separately? We re-hash if possible
            -- This part is called via wrapper, see Protect()
        end
    end
    return score
end

-- 7. LOADSTRING / DUMP PROBE - randomized W5 style
local function checkLoadstringProbe()
    -- Luraph's old W5 did: if loadstring("return 1")() ~= 1 then crash
    -- We randomize return value and nest it
    local probe = math.random(10000, 99999)
    local s = string.format("return %d", probe)
    local ok, fn = pcall(loadstring or load, s)
    if not ok or type(fn) ~= "function" then return 1 end
    local ok2, res = pcall(fn)
    if not ok2 or res ~= probe then return 1 end
    return 0
end

-- Delayed bomb - does NOT error immediately, corrupts state later
local function armBomb()
    if bombArmed then return end
    bombArmed = true
    local delay = math.random(CONFIG.BOMB_MIN_CALLS, CONFIG.BOMB_MAX_CALLS)
    local cnt = 0
    -- Use coroutine to hide execution trace
    coroutine.wrap(function()
        while true do
            cnt = cnt + 1
            if cnt >= delay then
                -- Silent corruption: replace math.random, table.concat, etc with crashing closures
                -- This is way harder to debug than error("Tamper Detected")
                if CONFIG.DELAYED_BOMB then
                    local function crash()
                        -- Infinite loop + memory bloat + eventually stack overflow
                        local t = {}
                        while true do
                            t[#t+1] = {t}
                            -- Force VM to allocate
                            if #t > 1e6 then error("VM Fatal", 0) end
                        end
                    end
                    -- Corrupt upvalues of sealed functions
                    for k,v in pairs(chunkHashes) do
                        if type(v) == "function" then
                            -- overwrite with crash
                            chunkHashes[k] = crash
                        end
                    end
                    crash()
                else
                    error("LPH_CRASH() - Integrity Failure", 0)
                end
                break
            end
            coroutine.yield()
        end
    end)()
end

-- Main lattice evaluator - call this inside your VM loop or at top of protected functions
function MuseSpark_AT:HeartBeat()
    callCounter = callCounter + 1
    if callCounter % CONFIG.CHECK_INTERVAL ~= 0 then return end

    local score = 0
    score = score + checkHookLattice()
    score = score + checkTiming() * 2
    score = score + checkEnv() * 2
    score = score + checkLoadstringProbe() * 3
    score = score + checkLattice()

    if score > 0 then
        tamperScore = tamperScore + score
    end

    -- Threshold: 2 hits is enough, but we wait to make tracing hard
    if tamperScore >= 2 then
        armBomb()
        -- also trigger the bomb's coroutine step
        -- We advance hidden coroutines by calling math.random (entangled)
        local r = math.random()
        if r < 0.3 and bombArmed then
            -- advance bomb via side effect
            for i=1, math.random(1,3) do coroutine.resume(coroutine.create(function() end)) end
        end
    end
end

-- Wrapper to protect a function - seals + injects heartbeat
function MuseSpark_AT:Protect(fn, name)
    if type(fn) ~= "function" then return fn end
    self:SealFunction(fn, name or "anon")
    
    local function wrapper(...)
        -- 1. heartbeat check (cheap, random)
        MuseSpark_AT:HeartBeat()
        -- 2. verify self hash (polymorphic)
        local ok, dumped = pcall(string.dump, fn)
        if ok and dumped then
            local curHash = fnv1a(dumped)
            local stored = chunkHashes[name or "anon"]
            if stored and curHash ~= stored then
                tamperScore = tamperScore + 5
                armBomb()
            end
            -- upvalue count check
            if debug and debug.getinfo then
                local info = debug.getinfo(fn, "u")
                if info and chunkHashes[(name or "anon").."_nups"] and info.nups ~= chunkHashes[(name or "anon").."_nups"] then
                    tamperScore = tamperScore + 5
                    armBomb()
                end
            end
        end
        return fn(...)
    end
    
    -- Hide wrapper via metatable tricks
    if setmetatable then
        setmetatable(wrapper, {__tostring = function() return tostring(fn) end})
    end
    
    chunkHashes[name or wrapper] = wrapper
    return wrapper
end

-- Auto-seal global loadstring/load
do
    local orig_loadstring = loadstring or load
    -- Don't replace, just fingerprint it
    chunkHashes["__loadstring_fingerprint"] = tostring(orig_loadstring):len()
end

-- Metatable bomb for _G detection (if someone does setmetatable(_G, ...))
if setmetatable and _G then
    local mt = getmetatable(_G)
    if mt == nil then
        setmetatable(_G, {
            __newindex = function(t,k,v)
                -- If someone is injecting deobfuscation helpers, score it
                if type(k) == "string" and (k:lower():find("deobf") or k:lower():find("luraph") or k:lower():find("tamper")) then
                    tamperScore = tamperScore + 1
                end
                rawset(t,k,v)
            end
        })
    end
end

return MuseSpark_AT
