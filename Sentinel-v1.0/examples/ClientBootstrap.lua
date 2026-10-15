--[[
	Client-side bootstrap. Drop into a LocalScript and the framework will:

	* run the Sentinel suite on startup
	* re-run it periodically
	* forward each report to the server

	The report is the only thing that crosses the wire. The server runs
	the policy and decides what to do; the client never decides.
]]

local RunService = game:GetService("RunService")
local ReplicatedStorage = game:GetService("ReplicatedStorage")

local Sentinel = require(ReplicatedStorage.Sentinel)
local Intake = ReplicatedStorage:WaitForChild("IntakeRemote")

-- Re-run budget: how often to re-verify. Five seconds is a reasonable
-- default; tighter for competitive games, looser for casual ones.
local RESEAT_SECONDS = 5

local lastRun = 0
local function runCheckpoint(label)
	lastRun = os.clock()
	local ok, err = pcall(function()
		local _, report = Sentinel.Run()
		-- Send the full report. The server-side policy is what decides
		-- what to do with it; the client should not strip fields.
		Intake:FireServer({
			label = label,
			report = report,
		})
	end)
	if not ok then
		-- A throw from Sentinel.Run is unusual: the only paths that
		-- raise are programmer errors (bad options) and the run itself
		-- failed. Either way, surface the error to logs.
		warn(("Sentinel checkpoint %q threw: %s"):format(label, tostring(err)))
	end
end

-- startup
runCheckpoint("startup")

-- periodic re-check, gated on a wall-clock budget
RunService.Heartbeat:Connect(function()
	if os.clock() - lastRun >= RESEAT_SECONDS then
		runCheckpoint("periodic")
	end
end)

-- one more on respawn, in case the engine reinitialises something
local Players = game:GetService("Players")
local function onRespawn()
	task.wait(1)
	runCheckpoint("respawn")
end
Players.LocalPlayer.CharacterAdded:Connect(onRespawn)
onRespawn()
