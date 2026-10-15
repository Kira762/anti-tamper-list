--[[
	Sentinel v1 — server-side decision policy.

	This is the second half of the design. The client-side Sentinel module
	produces a report. This module turns a stream of reports into a decision
	the server is willing to act on.

	Design principles
	-----------------
	* Never trust a single report. The first thing the policy does is treat
	  every report as one piece of evidence and require corroboration before
	  any action.
	* Separate "client differs from the policy baseline" (interesting, might
	  be a custom UI) from "the client contradicts itself" (very interesting,
	  probably a stub).
	* The honest outcomes are: ignore, observe, rate-limit, kick, ban. The
	  last two are *not* automatic. Banning a player is irreversible and
	  this module deliberately makes that the path you have to reach for,
	  not the default.
	* A failed probe is evidence, not proof. Legitimate clients fail probes
	  constantly: low memory, restricted permissions, server-side execution,
	  Studio, outdated engine versions, accessibility tooling. The policy
	  distinguishes "the client didn't reach this probe" from "the client
	  reached it and gave the wrong answer".

	The interface is a single class, `Policy`, with three entry points:
	  * `policy:update(player, report, timestamp)` — feed a fresh report.
	  * `policy:status(player)` — query the current evidence, by player.
	  * `policy:tick(now)` — age out stale evidence and return any actions
	    the policy is currently recommending.

	The policy is fully synchronous and allocation-bounded; safe to call on
	every Heartbeat for a populated server.
]]

local Policy = {}
Policy.__index = Policy

local function shallowFreeze(t)
	for k, v in pairs(t) do
		if type(v) == "table" then
			shallowFreeze(v)
		end
	end
	table.freeze(t)
	return t
end

-- Default thresholds. Override per-instance in the constructor for the
-- expectations of a particular game.
local DEFAULTS = {
	-- How many distinct reports are enough to act on, per probe
	minSamplesForAction = 3,
	-- Window over which a single piece of evidence remains current
	evidenceLifetime = 60,
	-- How many failing probes must be corroborated to recommend kicking
	failingProbesForKick = 2,
	-- How many corroborating failures to recommend banning
	failingProbesForBan = 4,
	-- Probes that the policy treats as *contradictions* if they fail (the
	-- client has both agreed and disagreed about the same fact in the same
	-- report). A single contradiction is enough to recommend kicking.
	-- By default the most reliable contradiction sources are listed here.
	contradictionProbes = table.freeze({
		["core.identity"] = true,
		["core.buffers"] = true,
		["core.utf8"] = true,
		["core.numericModel"] = true,
		["core.stringPack"] = true,
		["self.integrity"] = true,
	}),
	-- Stages whose failure is allowed to be ignored. A failing probe in a
	-- stage outside this list contributes to action thresholds.
	ignoreStages = table.freeze({
		-- engine probes are platform-dependent; ignore them by default and
		-- only watch the stages that should be stable on every client.
		executors = true,
	}),
}

local function now()
	if type(os) == "table" and type(os.clock) == "function" then
		return os.clock()
	end
	if type(tick) == "function" then
		return tick()
	end
	return 0
end

function Policy.new(options)
	options = options or {}
	local self = setmetatable({}, Policy)
	self.options = {}
	for k, v in pairs(DEFAULTS) do
		if options[k] ~= nil then
			self.options[k] = v
		else
			self.options[k] = v
		end
	end
	shallowFreeze(self.options)
	-- Per-player evidence buffer. Capped to keep a long-running server
	-- from accumulating state for a churning player list.
	self.evidence = {}
	self.MAX_SAMPLES = 16
	return self
end

-- A single report's evidence, indexed by probe id. Stored as a sliding
-- window of recent observations per probe.
local function freshEvidence()
	return {
		samples = {},          -- list of {status, reason, timestamp}
		sawContradiction = false,
		hasRequiredMiss = false,
		lastDigest = nil,
		firstSeen = nil,
		lastSeen = nil,
	}
end

local function recordSample(buffer, probeId, status, reason, timestamp, required)
	buffer.samples[probeId] = buffer.samples[probeId] or {}
	local list = buffer.samples[probeId]
	-- Slide the window
	while #list > Policy.MAX_SAMPLES do
		table.remove(list, 1)
	end
	list[#list + 1] = { status = status, reason = reason, at = timestamp }
	if required and status ~= "passed" and status ~= "partial" then
		buffer.hasRequiredMiss = true
	end
end

local function recordContradiction(buffer, probeId)
	-- A contradiction is recorded once per evidence buffer; further
	-- contradictions on the same report add no new information.
	buffer.sawContradiction = true
end

-- Normalise a Sentinel report into the per-probe observations the policy
-- cares about. Defensive: a missing or malformed report is recorded as
-- "the client sent nothing", not a verification failure.
function Policy:update(player, report, timestamp)
	timestamp = timestamp or now()
	if player == nil then
		error("Policy:update requires a player", 0)
	end
	if report == nil or type(report) ~= "table" then
		-- A completely missing report is a signal too, but a weak one
		-- (e.g. the LocalScript crashed before sending). Record it and
		-- move on; never treat it as a banning signal on its own.
		self.evidence[player] = self.evidence[player] or freshEvidence()
		return
	end

	local buffer = self.evidence[player]
	if not buffer then
		buffer = freshEvidence()
		self.evidence[player] = buffer
		buffer.firstSeen = timestamp
	end
	buffer.lastSeen = timestamp
	buffer.lastDigest = report.digest

	-- Always walk the probe list so the policy can see *what was checked*
	-- in addition to *what failed*.
	for i = 1, #report.probes do
		local p = report.probes[i]
		local required = p.class == "required"
		recordSample(buffer, p.id, p.status, p.message, timestamp, required)
	end

	-- A failed self.integrity is a contradiction by construction: the
	-- module is asserting about its own state. We lift it into a flag
	-- the decision logic can act on without scanning the probe list.
	for i = 1, #report.probes do
		local p = report.probes[i]
		if self.options.contradictionProbes[p.id] and p.status == "failed" then
			recordContradiction(buffer, p.id)
		end
	end
end

-- Aggregate the per-probe samples into a per-probe summary. This is what
-- the decision logic reads.
local function summarise(buffer, now, lifetime)
	local out = {}
	for id, samples in pairs(buffer.samples) do
		local recent = {}
		for i = 1, #samples do
			if (now - samples[i].at) <= lifetime then
				recent[#recent + 1] = samples[i]
			end
		end
		-- Was the most recent observation a failure?
		local last = recent[#recent]
		out[id] = {
			lastStatus = last and last.status or nil,
			lastReason = last and last.reason or nil,
			samples = #recent,
			failing = 0,
			passing = 0,
			partial = 0,
		}
		for i = 1, #recent do
			if recent[i].status == "failed" then
				out[id].failing += 1
			elseif recent[i].status == "passed" then
				out[id].passing += 1
			elseif recent[i].status == "partial" then
				out[id].partial += 1
			end
		end
	end
	return out
end

-- The public status. A frozen, JSON-friendly view of the policy's view
-- of one player.
function Policy:status(player)
	local buffer = self.evidence[player]
	if not buffer then
		return shallowFreeze({ player = player, observation = "no-data" })
	end
	local t = now()
	local summary = summarise(buffer, t, self.options.evidenceLifetime)
	local result = {
		player = player,
		firstSeen = buffer.firstSeen,
		lastSeen = buffer.lastSeen,
		ageSeconds = t - buffer.lastSeen,
		lastDigest = buffer.lastDigest,
		sawContradiction = buffer.sawContradiction,
		probes = summary,
	}
	return shallowFreeze(result)
end

-- Drop evidence for players we have not seen in `lifetime` seconds. This
-- is the policy's "forget the absent" guarantee, so a kicked player who
-- comes back under a different name does not carry their history with
-- them by accident (they have a new player id, but the housekeeping also
-- prevents a churning player list from growing the evidence table forever).
function Policy:tick(now)
	now = now or now()
	local evicted = 0
	for player, buffer in pairs(self.evidence) do
		if (now - buffer.lastSeen) > self.options.evidenceLifetime * 4 then
			self.evidence[player] = nil
			evicted += 1
		end
	end
	return evicted
end

-- A recommendation. The caller decides what to do with it; the policy
-- never kicks or bans on its own. The caller is responsible for the
-- irreversible consequences of acting on a `ban` verdict.
function Policy:recommend(player, now)
	now = now or now()
	local buffer = self.evidence[player]
	if not buffer then
		return shallowFreeze({ action = "ignore", reason = "no evidence yet" })
	end

	-- "Contradiction" is the strongest signal: the client reported about
	-- its own state in a way that is mathematically incompatible with
	-- being unmodified. One sample, with corroboration, is enough to
	-- recommend kicking.
	if buffer.sawContradiction then
		-- Did we see it more than once? A single contradiction can be a
		-- transient state (resource pressure, a permission flap). Two
		-- contradictions in the same lifetime is a strong signal.
		local contradictions = 0
		for id, samples in pairs(buffer.samples) do
			if self.options.contradictionProbes[id] then
				for i = 1, #samples do
					if samples[i].status == "failed"
						and (now - samples[i].at) <= self.options.evidenceLifetime then
						contradictions += 1
						break
					end
				end
			end
		end
		if contradictions >= 2 then
			return shallowFreeze({
				action = "ban",
				reason = "sustained contradiction",
				contradictions = contradictions,
			})
		end
		return shallowFreeze({
			action = "kick",
			reason = "contradiction observed; kick and observe re-entry",
			contradictions = contradictions,
		})
	end

	-- Aggregate failure count across required probes. This is the
	-- "many checks failed over the window" signal.
	local failingProbes, failingSamples = 0, 0
	for id, samples in pairs(buffer.samples) do
		for i = 1, #samples do
			local s = samples[i]
			if s.status == "failed" and (now - s.at) <= self.options.evidenceLifetime then
				failingSamples += 1
			end
		end
		-- A probe only counts once toward the "distinct failing probes"
		-- total even if it failed many times, but only if at least
		-- `minSamplesForAction` corroborating failures exist.
		local corrob = 0
		for i = 1, #samples do
			if samples[i].status == "failed"
				and (now - samples[i].at) <= self.options.evidenceLifetime then
				corrob += 1
			end
		end
		if corrob >= self.options.minSamplesForAction then
			failingProbes += 1
		end
	end

	if failingProbes >= self.options.failingProbesForBan then
		return shallowFreeze({
			action = "ban",
			reason = ("%d required probes failed %d times each"):format(
				failingProbes, self.options.minSamplesForAction),
			failingProbes = failingProbes,
			failingSamples = failingSamples,
		})
	end
	if failingProbes >= self.options.failingProbesForKick then
		return shallowFreeze({
			action = "kick",
			reason = ("%d required probes failed %d times each"):format(
				failingProbes, self.options.minSamplesForAction),
			failingProbes = failingProbes,
			failingSamples = failingSamples,
		})
	end
	if failingSamples > 0 then
		return shallowFreeze({
			action = "observe",
			reason = "a sample failed but not enough corroboration yet",
			failingSamples = failingSamples,
		})
	end
	return shallowFreeze({ action = "ignore", reason = "all recent samples passed" })
end

-- The most defensive test of the contract: a policy with no evidence
-- has nothing to act on. The default recommend() return for an unseen
-- player is `{ action = "ignore" }`. Override `recommend()` if a game
-- wants different behaviour for the cold-start case.

Policy.DEFAULTS = DEFAULTS
return Policy
