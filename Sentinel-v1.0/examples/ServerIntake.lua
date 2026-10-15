--[[
	Server-side intake. Drop into a ServerScript and the framework will:

	* accept reports from clients
	* feed them to a Policy
	* periodically ask the policy for a recommendation per player
	* execute irreversible actions only on `ban`/`kick`

	The policy module is the only place that decides trust. The
	intake is deliberately dumb.
]]

local Players = game:GetService("Players")
local ServerStorage = game:GetService("ServerStorage")
local ReplicatedStorage = game:GetService("ReplicatedStorage")

local Policy = require(ServerStorage.AntiTamperPolicy)
local Intake = ReplicatedStorage:WaitForChild("IntakeRemote")

local policy = Policy.new({
	-- default thresholds are conservative. tune for your game.
	evidenceLifetime = 60,
	minSamplesForAction = 3,
	failingProbesForKick = 2,
	failingProbesForBan = 4,
})

Intake.OnServerEvent:Connect(function(player, payload)
	-- Validate before trusting any field. A client can send any
	-- table; do not index into it without type checks.
	if type(payload) ~= "table" then return end
	if type(payload.label) ~= "string" or type(payload.report) ~= "table" then return end
	if type(payload.report.status) ~= "string" then return end

	-- Optional: cap label length so a hostile client cannot fill our
	-- logs with a 1MB string.
	if #payload.label > 64 then
		payload.label = payload.label:sub(1, 64)
	end

	policy:update(player, payload.report, os.clock())
end)

-- Re-evaluate on a heartbeat. 5 seconds is the default; tighter for
-- competitive games.
local TICK_SECONDS = 5
task.spawn(function()
	while true do
		task.wait(TICK_SECONDS)
		local now = os.clock()
		for _, player in ipairs(Players:GetPlayers()) do
			local recommendation = policy:recommend(player, now)
			if recommendation.action == "ban" then
				-- The irreversible action. Your game has its own
				-- banning system; this is just the trigger.
				warn(("Sentinel ban: player=%s reason=%s contradictions=%d failingProbes=%d"):format(
					player.Name, recommendation.reason,
					recommendation.contradictions or -1,
					recommendation.failingProbes or -1))
				player:Kick("This account has been flagged for further review.")
			elseif recommendation.action == "kick" then
				warn(("Sentinel kick: player=%s reason=%s"):format(
					player.Name, recommendation.reason))
				player:Kick()
			elseif recommendation.action == "observe" then
				-- Non-intrusive: rate-limit, lower spawn priority,
				-- flag for staff. Do NOT kick or ban on observe.
			end
		end
		policy:tick(now)
	end
end)
