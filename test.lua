#! /bin/lua

math.randomseed(os.time())

---@param size integer
---@return string key
local get_key = function(size)
	local out = ""
	for i = 1, size do
		out = out .. string.char(math.random(32, 127))
	end
	return out
end

local size = 4
local key = get_key(8 * 4)

local cmd = string.format("echo 'Hello world' | ./salsax %d '%s'", size, "helloworhelloworhelloworhellowor")
print("executing -> " .. cmd)
os.execute(cmd)
