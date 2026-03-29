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

local backwards_compatable = function ()
	local size = 4
	local key = get_key(8 * 4)

	-- Encrypt with chacha20 and decrypt with salsa4
	-- Encrypt with salsa4 and decrypt with chacha20
	local cmds = {
		string.format("./salsax %d '%s' macbeth.txt enc.txt && ./chacha20 '%s' enc.txt d_macbeth.txt", size, key, key)
		-- string.format("./chacha20 '%s' macbeth.txt enc.txt && ./salsax %d '%s' enc.txt d_macbeth.txt", key, size, key)
	}

	for _, cmd in ipairs(cmds) do
		os.execute(cmd)
	end
end

backwards_compatable()
