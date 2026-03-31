# SalsaX

SalsaX is a modification of the Chacha20 stream cipher algorithm. It takes the original Chacha20 design and scales it up to support any grid size between 2 and 16. Chacha20 is typically done on a 4x4 grid, so the motivation to allow grid size to be variable fuels two hypotheses. First, using increased grid sizes naturally adds complexity to the original Chacha20 algorithm. Additionally, variable grid size allows the decision for performance over security, or vice versa, to be lifted to the user.

SalsaX was designed to map as close to the Chacha20 algorithm as possible. This idea is present in all of the facets of that needed to change along with the grid size, which are all detailed below.

## The Algorithm

### Block Allocations

Chacha20 has a grid size of 4, meaning there are 16 total elements, each having 32 bits. Chacha20 partitions in 16 elements to reserved roles, and this needed to scale up along with the grid size. There are two major constraints in doing this, first SalsaX must be backwards compatable with Chacha20, and all the original partitions must still be present. By this, the partitions at $n = 4$ and $n = 2$ are already decided, where $n$ is the size of the grid for any SalsaX variant. As for the other sizes and partitions, the size of the block and nonce were kept relatively small and given predictable patterns for their scaling. The key was more or less arbitrarily decided, with the only restriction being to keep it to "pleasant" even numbers. The constant was then treated as filler for anything the block, nonce, and key did not fill. The below table shows the partitioning of roles for each grid size supported.

| Size | Constant | Key | Count | Nonce |
|---|---|---|---|---|
| **2** | **1** | **1** | **1** | **1** |
| 3 | 2 | 4 | 1 | 2 |
| **4 (ChaCha20)** | **4** | **8** | **1** | **3** |
| 5 | 7 | 12 | 2 | 4 |
| 6 | 9 | 20 | 2 | 5 |
| 7 | 12 | 28 | 3 | 6 |
| 8 | 18 | 36 | 3 | 7 |
| 9 | 21 | 48 | 4 | 8 |
| 10 | 27 | 60 | 4 | 9 |
| 11 | 34 | 72 | 5 | 10 |
| 12 | 40 | 88 | 5 | 11 |
| 13 | 51 | 100 | 6 | 12 |
| 14 | 57 | 120 | 6 | 13 |
| 15 | 68 | 136 | 7 | 14 |
| 16 | 78 | 156 | 7 | 15 |

### Fractional Round

Using the quarter round, Chacha20 is able to contact every bit at least once during every round. This happens over 20 rounds, but how would this scale as the size of the grid increases? First, we need a more general _fractional round_ where $n$ of them must be preformed for, any grid size $n$, to complete a single round. The remaining details of fractional rounds behave nearly identically to Chacha20. Each round will act either on a column or a diagonal and each preforms operations on the elements in their group.

### Operations

Famously, Chacha20 only uses three simple operations for all of it's calculations. SalsaX does the exact same, though possible the hardest part to generalize, is choosing what the operations are applied to. For each column or diagonal, which we call a group, they have $n$ elements, where the $n$ is the grid size. Chacha20 always has 4 elements to choose from, and for demonstrations purposes, we label "A", "B", "C", and "D" consecutively. Then the elements are split into triplets. For Chacha20 this looks like (A, B, D) and (C, D, B). For each triplet, mod 32 addition, an XOR and left shift rotations are applied. To scale this, SalsaX picks triplets from each group by picking every other element in the group to be the first member of a new triplet. Then the second member is always choses as the member that appears after the first. Finnally, the last member of each triplet is chosen to be the element 2 places after the second, wrapping back to the beggning of the group if needed. This scales nicely for even numbers, but not as well for odd, which we will see later.

## Test Results

There is a test set that checks for proper behaviour at each size, backwards compatability with chacha20, the avalanche effect at different sizes, and runs the NIST sta test suite on SalsaX.

### Avalanche

Simple avalanche test has SalsaX output an encryption, then a single bit is modified within the key and the a new outputs is calculated. These two outputs are compared bit by bit to get the avalanche percentage. This is iterated 50 times and the average is reported for each size.

| **Size** | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **% Changed** | 50.01 | 0.67 | 50.01 | 29.91 | 50.00 | 35.72 | 50.00 | 38.93 | 50.00 | 41.10 | 49.99 | 42.24 | 49.99 | 43.15 | 49.99 |

Notice how sizes that are low and odd (3 and 5) produce worse scores.

### NIST sts

For more information visit [https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software](https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software)

| **Size** | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **% Passed** | 97.53% | 0.62% | 98.77% | 1.23% | 98.77% | 22.22% | 95.68% | 44.44% | 97.87% | 50.62% | 98.77% | 38.89% | 97.53% | 62.96% | 97.34% |

## Building

To build `salsax` and the `chacha20` example, simple run `make`

Afterwards, `salsax` and `chacha20` can be run like so.

```bash
salsax <SIZE> <KEY> <INPUT_FILE> <OUTPUT_FILE>

chacha20 <KEY> <INPUT_FILE> <OUTPUT_FILE>
```

## Testing

To run the test suite, you must have Lua installed. Additionally, run the `Makefile` within `./sts-2.1.2/` by using

```bash
cd ./sts-2.1.2/ && make
```

Then simply run the test script with Lua.

```bash
lua ./test.lua
```

Keep in mind that the avalanche tests are slow.
