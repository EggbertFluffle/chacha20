#! /bin/lua

math.randomseed(os.time())

---@param size integer
---@return string key
local get_key = function(size)
	local out = ""
	for i = 1, size do
		local char = math.random(32, 127)
		if char == string.byte("\\") or char == string.byte("'") then
			char = char + 1
		end
		out = out .. string.char(char)
	end
	return out
end

local size = 4
-- local key = get_key(8 * 4)
local key = "helloworldhelloworldhelloworldaa"

-- local cmd = string.format("echo -n 'Hello world' | ./chacha20 '%s' | ./chacha20 '%s'", key, key)
-- local cmd = string.format("echo -n 'Hello world' | ./salsax %d '%s' | ./chacha20 '%s'", size, key, key)
local cmd = string.format("echo -n 'Hello world' | ./salsax %d '%s'", size, key)

os.execute(string.format("echo -n 'Hello world' | ./salsax %d '%s'", size, key))
os.execute(string.format("echo -n 'Hello world' | ./chacha20 '%s'", key))

-- local file = io.popen(cmd)
-- if not file then error("Unable to open e_cmd") end
-- local msg = file:read("*a")
-- print("Decrypted message: " .. msg)
--
-- cmd = string.format("echo -n 'Hello world' | ./chacha20 '%s'", key)
-- file = io.popen(cmd)
-- if not file then error("Unable to open e_cmd") end
-- msg = file:read("*a")
-- print("Decrypted message: " .. msg)
