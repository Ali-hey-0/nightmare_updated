
# csaw18_x86tour_pt1 - Nightmare Beginner Reversing / x86 Intro

**Challenge Type:** Educational x86 assembly reading exercise (no binary, no flag)**File:** stage1.asm**Goal:** Read the code and answer the 5 trivia questions in comments.**Key Concepts Learned:**

- Registers: AH/AL/AX (parts of A register), segment registers (ds/es/fs/gs/ss)
- Instructions: mov, xor (to zero registers), cmp/je/jmp, int 0x10 (BIOS video)
- Stack Pointer (sp), Base Pointer (bp), Source/Destination Index (si/di)
- Bootloader basics: org 7C00h, bits 16, cli

**Answers to Questions:**

- Q1: `xor dh, dh` → sets dh to 0 (XOR self = 0, fast zeroing trick)
- Q2: `mov gs, dx` → sets gs to 0 (dx was zeroed earlier)
- Q3: `mov si, sp` → copies stack pointer (sp=0 at that point) to si
- Q4 & Q5: `mov ah, 0x0e` → prepares AH=0x0E for BIOS teletype print (int 0x10)

**Time:** ~20-30 min reading
**Takeaway:** Great intro to x86 registers, basic instructions, and BIOS interrupts in 16-bit real mode.
