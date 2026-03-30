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

---@param str string
---@return string
local to_binary = function (str)
	local write_file = io.open("tmp.txt", "w+")
	if not write_file then error("Unable to write to temp file") end
	write_file:write(str)
	write_file:close()

	local xxd = io.popen(string.format("xxd -b tmp.txt"))
	if not xxd then error("Unable to xxd") end

	local out = ""
	while true do
		---@type string
		local line = xxd:read("*l")
		if not line then break end

		line = line:gsub(".*: ", "")
		line = line:gsub("  .*", "")
		out = out .. line
	end
	out = out:gsub("%s", "")

	os.execute("rm tmp.txt")

	return out
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
		end


		os.execute("rm ./d_macbeth.txt ./enc.txt")
		diff:close()
	end
end

local AVALANCHE_ITERATIONS = 5
---@param size integer
local find_avalanche = function (size)

	local avalanche = 0
	for i = 1, AVALANCHE_ITERATIONS do
		local key = get_key(size)

		local from = "macbeth.txt"
		local enc = "enc.txt"

		salsax(size, key, from, enc)
		local enc_file = io.open(enc, "r")
		if not enc_file then error("Unable to read output") end
		local output_1 = to_binary(enc_file:read("*a"))

		local char_idx = math.random(1, #key - 1)

		key = key:sub(1, char_idx - 1) .. string.char(string.byte(key:sub(char_idx, char_idx)) + 1)  .. key:sub(char_idx + 1)

		salsax(size, key, from, enc)
		enc_file = io.open(enc, "r")
		if not enc_file then error("Unable to read output") end
		local output_2 = to_binary(enc_file:read("*a"))

		local flipped = 0
		for i = 1, #output_1 do
			if output_1:sub(i, i) ~= output_2:sub(i, i) then
				flipped = flipped + 1
			end
		end
		flipped = flipped / #output_1

		print(string.format("result %d %f", i, flipped))
		avalanche = avalanche + flipped
	end

	print(string.format("Avalanche for size %d [%.3f]", size, avalanche / AVALANCHE_ITERATIONS))

	os.execute("rm ./enc.txt")
end

local all_avalanches = function ()
	for i = 2, 16 do
		find_avalanche(i)
	end
end


local NIST_TEST_SIZE = 200000
local nist_test = function (size)
	local exit = os.execute("[ -d ./sts-2.1.2 ]")
	if not exit then
		print("Cannot run NIST test suite because test suite is not present")
		return
	end

	local temp = "temp.txt"
	local nist_input = "./sts-2.1.2/nist_input.txt"

	local write_file = io.open(temp, "w+")
	if not write_file then error("Unable to open write file") end
	write_file:write(string.rep("\000", NIST_TEST_SIZE))
	write_file:close()

	local key = get_key(size)

	-- salsax(size, key, temp, nist_input)
	chacha20(key, temp, nist_input)

	-- local asses = io.popen(string.format("cd ./sts-2.1.2 && echo '0\n./%s\n1\n1\n1\n' | ./assess %d", nist_input, NIST_TEST_SIZE))

	-- os.execute(string.format("rm %s %s", temp, nist_input))
end

-- backwards_compatable()
-- other_sizes()
-- all_avalanches()
nist_test(4)
