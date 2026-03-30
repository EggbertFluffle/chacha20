#! /bin/lua

math.randomseed(os.time())

local key_sizes = { 1, 4, 8, 12, 20, 28, 36, 48, 60, 72, 88, 100, 120, 136, 156 }

---@param size integer
---@return string key
local get_key = function(size)
	local out = ""
	for _ = 1, key_sizes[size - 1] * 4 do
		local char = math.random(48, 90)
		out = out .. string.char(char)
	end
	return out:gsub("\\", "a")
end

local nonce_sizes = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }

---@param size integer
---@return string nonce
local get_nonce = function(size)
	local out = ""
	for _ = 1, nonce_sizes[size - 1] * 4 do
		local char = math.random(48, 90)
		out = out .. string.char(char)
	end
	return out:gsub("\\", "a")
end

---@param size integer
---@param key string 
---@param nonce string
---@param input string
---@param output string
---@return string
local salsax = function (size, key, nonce, input, output)
	local prog = io.popen(string.format("./salsax %d '%s' '%s' %s %s", size, key, nonce, input, output))
	if not prog then error("Unable to open program") end
	local output = prog:read("*a")
	prog:close()
	return output
end

---@param key string 
---@param nonce string
---@param input string
---@param output string
local chacha20 = function (key, nonce, input, output)
	os.execute(string.format("./chacha20 '%s' '%s' %s %s", key, nonce, input, output))
end

---@param str string
---@return string
local to_binary = function (str)
	local tmp = "tmp.txt"

	local write_file = io.open(tmp, "w+")
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

	os.execute(string.format("rm %s", tmp))

	return out
end

local backwards_compatable = function ()
	local size = 4
	local key = get_key(size)
	local nonce = get_nonce(size)

	local from = "macbeth.txt"
	local enc = "enc.txt"
	local to = "d_macbeth.txt"

	-- Encrypt with chacha20 and decrypt with salsa4
	-- Encrypt with salsa4 and decrypt with chacha20
	local cmds = {
		function()
			salsax(size, key, nonce, from, enc)
			chacha20(key, nonce, enc, to)
		end,
		function()
			chacha20(key, nonce, from, enc)
			salsax(size, key, nonce, enc, to)
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
		local nonce = get_nonce(i)

		salsax(i, key, nonce, "macbeth.txt", "enc.txt")
		salsax(i, key, nonce, "enc.txt", "d_macbeth.txt")

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
		local nonce = get_nonce(size)

		local from = "macbeth.txt"
		local enc = "enc.txt"

		salsax(size, key, nonce, from, enc)
		local enc_file = io.open(enc, "r")
		if not enc_file then error("Unable to read output") end
		local output_1 = to_binary(enc_file:read("*a"))

		local char_idx = math.random(1, #key - 1)

		key = key:sub(1, char_idx - 1) .. string.char(string.byte(key:sub(char_idx, char_idx)) + 1)  .. key:sub(char_idx + 1)

		salsax(size, key, nonce, from, enc)
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

		avalanche = avalanche + flipped
	end

	print(string.format("Avalanche for size %d [%.3f]", size, avalanche / AVALANCHE_ITERATIONS))

	os.execute("rm ./enc.txt")
end

local all_avalanches = function ()
	print("----- Starting Avalanche Tests -----")
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

	local write_file = io.open(temp, "w+")
	if not write_file then error("Unable to open write file") end
	write_file:write(string.rep("\000", NIST_TEST_SIZE / 8))
	write_file:close()

	local key = get_key(size)
	local nonce = get_nonce(size)

	-- salsax(size, key, temp, nist_input)
	salsax(size, key, nonce, temp, "./sts-2.1.2/nist_input.txt")

	local asses = io.popen(string.format("cd ./sts-2.1.2 && echo '0\n./nist_input.txt\n1\n0\n 1\n1\n' | ./assess %d", NIST_TEST_SIZE))
	if not asses then error("Unable to execute NIST assessment") end
	local asses_output = asses:read("*a")
	asses:close()

	local results_file = io.open("./sts-2.1.2/experiments/AlgorithmTesting/finalAnalysisReport.txt", "r")
	if not results_file then error("Unable to find NIST results file") end

	---@type string
	local tests_results = results_file:read("*a"):gmatch("%d%/1")

	local passed = 0
	local total = 0
	for test in tests_results do
		total = total + 1
		if test == "1/1" then
			passed = passed + 1
		end
	end

	print(string.format("NIST test for size %d [%d/%d (%.2f%%) PASSED]", size, passed, total, (passed / total) * 100))

	os.execute(string.format("rm %s %s %s", temp, "./sts-2.1.2/nist_input.txt", "./sts-2.1.2/experiments/AlgorithmTesting/finalAnalysisReport.txt"))
	-- os.execute(string.format("rm %s %s", temp, "./sts-2.1.2/nist_input.txt"))
end

local all_nist_tests = function ()
	print("----- Starting NIST sts Randomness Tests -----")
	for i = 2, 16 do
		nist_test(i)
	end
end

-- backwards_compatable()
-- other_sizes()
-- all_avalanches()
all_nist_tests()
-- nist_test(4)
