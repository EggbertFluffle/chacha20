#! /bin/lua

math.randomseed(os.time())

local key_sizes = { 1, 4, 8, 12, 20, 28, 36, 48, 60, 72, 88, 100, 120, 136, 156 }

---@param size integer
---@return string key
local get_key = function(size)
	local out = ""
	for i = 1, key_sizes[size - 1] * 4 do
		local char = math.random(48, 90)
		out = out .. string.char(char)
	end
	return out:gsub("\\", "a")
end

---@param size integer
---@param key string 
---@param input string
---@param output string
---@return string
local salsax = function (size, key, input, output)
	local prog = io.popen(string.format("./salsax %d '%s' %s %s", size, key, input, output))
	if not prog then error("Unable to open program") end
	local output = prog:read("*a")
	prog:close()
	return output
end

---@param key string 
---@param input string
---@param output string
local chacha20 = function (key, input, output)
	os.execute(string.format("./chacha20 '%s' %s %s", key, input, output))
end

local backwards_compatable = function ()
	local size = 4
	local key = get_key(size)

	local from = "macbeth.txt"
	local enc = "enc.txt"
	local to = "d_macbeth.txt"

	-- Encrypt with chacha20 and decrypt with salsa4
	-- Encrypt with salsa4 and decrypt with chacha20
	local cmds = {
		function()
			salsax(size, key, from, enc)
			chacha20(key, enc, to)
		end,
		function()
			chacha20(key, from, enc)
			salsax(size, key, enc, to)
		end,
	}

	for _, cmd in ipairs(cmds) do
		cmd()

		local file = io.popen("diff macbeth.txt d_macbeth.txt")
		if not file then error("diff failed") end
		local diff = file:read("*a")

		if #diff == 0 then
			print("Backwards compatability [PASSED]")
		else
			print("Backwards compatability [FAILED]")
		end
		os.execute("rm ./d_macbeth.txt ./enc.txt")
	end
end

local other_sizes = function ()
	for i = 2, 16 do
		local key = get_key(i)

		salsax(i, key, "macbeth.txt", "enc.txt")
		salsax(i, key, "enc.txt", "d_macbeth.txt")

		local diff = io.popen("diff macbeth.txt d_macbeth.txt")
		if not diff then error("diff failed") end

		if #diff:read("*a") == 0 then
			print(string.format("SalsaX at n=%d [PASSED]", i))
		else
			print(string.format("SalsaX at n=%d [FAILED]", i))
			os.exit(1)
		end


		os.execute("rm ./d_macbeth.txt ./enc.txt")
		diff:close()
	end
end

local generic = function ()
	local size = 5
	local key = get_key(5)

	local from = "small.txt"
	local enc = "enc.txt"
	local to = "d_small.txt"

	print(salsax(size, key, from, enc))
	print(salsax(size, key, enc, to))

	local diff = io.popen(string.format("diff %s %s", from, to))
	if not diff then error("Unable to diff") end
	print(diff:read("*a"))
end

-- backwards_compatable()
-- other_sizes()
generic()
