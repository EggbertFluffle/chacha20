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

---@param file1 string
---@param file2 string
---@return number ratio
local compare_files = function(file1, file2)
    local f1 = io.open(file1, "rb")
    local f2 = io.open(file2, "rb")
	if not f1 then error("Unable to open " .. file1) end
	if not f2 then error("Unable to open " .. file2) end

    local data1 = f1:read("*a")
    local data2 = f2:read("*a")

    f1:close()
    f2:close()

    local flipped = 0
    local len = #data1
    for i = 1, len do
        local diff = data1:byte(i) ~ data2:byte(i)
        while diff > 0 do
            flipped = flipped + (diff & 1)
            diff = diff >> 1
        end
    end

    local total_bits = len * 8
    return flipped / total_bits
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

local AVALANCHE_ITERATIONS = 50
---@param size integer
local find_avalanche = function (size)
	local avalanche = 0

	for i = 1, AVALANCHE_ITERATIONS do
		local key = get_key(size)
		local nonce = get_nonce(size)

		local from = "macbeth.txt"
		local first = "first.txt"
		local second = "second.txt"

		salsax(size, key, nonce, from, first)

		local char_idx = math.random(1, #key - 1)
		key = key:sub(1, char_idx - 1) .. string.char(string.byte(key:sub(char_idx, char_idx)) + 1)  .. key:sub(char_idx + 1)

		salsax(size, key, nonce, from, second)

		avalanche = avalanche + compare_files(first, second)

		os.execute(string.format("rm %s %s", first, second))
	end

	print(string.format("Avalanche for size %d [%.2f %%]", size, (avalanche / AVALANCHE_ITERATIONS) * 100))
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
end

local all_nist_tests = function ()
	print("----- Starting NIST sts Randomness Tests -----")
	for i = 2, 16 do
		nist_test(i)
	end
end

os.execute("make clean")
os.execute("make")
backwards_compatable()
other_sizes()
all_avalanches()
all_nist_tests()
