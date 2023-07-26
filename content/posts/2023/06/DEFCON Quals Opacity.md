---
title: "DEFCON2023 - opacity"
date: "2023-06-01"
author: "TwinkleStar03"
description: "Writeup of the reverse challenge `Opacity` in DEFCON2023 Quals: A DRM-protected circuit emulation."
toc: true
tags: [DEFCON2023 Quals, Reverse Engineering]
categories: [CTF]
---

---

Writeup of the reverse challenge `Opacity` in DEFCON2023 Quals: A DRM-protected circuit emulation.

I found this challenge to be highly intriguing, as it took us a considerable amount of time to unravel its true purpose. 
The implementation of a fundamental gate in this challenge was particularly fascinating, which is why I felt compelled to create a detailed writeup for it.

## DRM Protected Environment (`init_drm`)
The DRM is actually a patched `qemu-aarch64` which will use user provided license as PAC key.

This is how PAC key is set:
- license is a 16-bytes sequence, which will applied to `qemu_base+0x48D390` @ `.rodata`
- `qemu_base+0x22BCCC`([do_prctl_reset_keys](https://github.com/qemu/qemu/blob/master/linux-user/aarch64/target_prctl.h#L106)) is replaced with code that perform `memcpy` from `qemu_base+0x48D390` to `PAC_KEY_B` (`&env->keys.apib`)
- A runtime (`init_drm`) perform patch and `exec` itself to a patched qemu and run circuit emulator (`run_prog`)


## `run_prog` (Circuit Emulator)
### PAC as NAND
Using PAC operation as a way to inhibit the nature of bitwise operation is such a cool idea.

Here's how PAC as NAND is made:

Every gate have two output state (0 or 1):
- Use a random number to represent the state 0 or 1
Building NAND gate:
1. Suppose GateA and GateB both output 1, therefore we have two random that represent 1 here (we called it `gateA_rand_1` and `gateB_rand_1`)
2. Use `gateA_rand_1` as Pointer and `gateB_rand_1` as modifier, thus we'll get `result_pac` which is signed `gateA_rand_1`
3. Check other cases, where GateA and GateB will output (00, 01, 10), AUT should fail in those cases
	- If the check failed, the modifier got incremented (modifier++)
	- Repeat until all check success
4. Save information for NAND
	- Random values for 0 and 1 from both input
	- Modifier increment

Using(Evaluate) NAND Gate:
1. Acquire output state numbers from both input
2. Perform AUT
	- If success, then both output is 1
	- If failed, output might be (00, 01, 10)
3. Left shift the AUT result, leave the high byte there
	- If the AUT success the number will be original value where LSB should be `000000`
	- If the AUT failed the number will be invalidate where LSB leave non-zero number
4. Use the shifted result as output of NAND gate
	- The PAC perform AND operation, and shift perform NOT operation, which result in NAND gate

## Solution

### Figure Out Opcodes
After our team get a consensus about the VM and the circuit, we found out it's actually a CPU run a tiny program on it.
We attempt to guess all the opcode one by one by observing the state of the machine before/after an operation is done.

After we built a opcode table, we can start disassemble target program.

### Bytecode Disassembly
The program makes a checksum based on user-input. We can just brute-force this checksum function to find a valid input and send it to remote server.

```
0: 00000100
1: 11000111 cmp r0, 0x00
2: 00100110 jmp 4
3: 11000100   invalid
4: 00001000 read
5: 00000111 cmp r0, 0x3f
6: 01000110 jz 8
7: 01000100   hlt

8: 00111011 add r3, 0x3f
9: 00001000  read
10: 11000111  cmp r0, 0x00
11: 10111110  jz TLE
12: 00011011  mul r1, 0x3f
13: 10100001  ROT3 r2, 2
14: 11110001  ROT3 r3, 3
15: 00101001  XOR r2, r0
16: 00111001  XOR r3, r0
17: 01010001  ROT3 r1, 1
18: 10100110  jz 20; break
19: 01001010 jmp 9

20: 00001000 read
21: 00000111 cmp r0, 0x3f
22: 11000110 jz 24
23: 10111010   TLE ; jmp 23
24: 01100111 cmp r2, 0xd5
25: 11011110 jz 27
26: 10111010   TLE
27: 10110111 cmp r3, 0x54
28: 11110110 jz 30; FLG
29: 10111010   TLE
30: 01100000 FLG
31: 00000000
```