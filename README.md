# 🧠 Nightmare Exploitation Roadmap

This repository is **not a random CTF collection**. It is a **progressive exploit development curriculum** designed to build *real-world binary exploitation capability* — from fundamentals to allocator subversion.

The modules are intentionally diverse and sometimes non-linear. This README provides:

* A **clear mental model** of what each module teaches
* A **layered learning roadmap** (why things exist, not just what exists)
* **Preserved module names** (no renaming — filesystem-safe)
* A strategy for **efficient, non-mechanical progression**

---

## 🎯 Primary Goal of the Repository

> Build the ability to **analyze unknown binaries**, identify **exploit primitives**, and **chain them under real-world mitigations**.

This repo optimizes for:

* Thinking in **primitives**, not tricks
* Understanding **why exploits work**, not memorizing patterns
* Transitioning from *manual exploitation* → *automation & reasoning*

---

## 🧱 Layered Curriculum Overview

Each layer represents a **conceptual upgrade** in exploitation ability.
You do **not** need to solve everything sequentially.

---

## LAYER 0 — Environment, Tooling & Mindset

**Purpose:** Build the execution environment and workflow intuition

```
00-intro
01-intro_assembly
02-intro_tooling
references
next
```

**You gain:**

* Assembly fluency
* Debugging workflow
* Mental readiness for later complexity

---

## LAYER 1 — Reverse Engineering Foundations

**Purpose:** Understand binaries *without source code*

```
03-beginner_re
36-obfuscated_reversing
22-movfuscation
21-dot_net
23-custom_architecture
34-emulated_targets
```

**You gain:**

* CFG reconstruction
* Obfuscation resistance
* Cross-architecture reasoning

---

## LAYER 2 — Stack Exploitation (BOF Core)

**Purpose:** Control instruction pointer and execution flow

```
04-bof_variable
05-bof_callfunction
06-bof_shellcode
07-bof_static
08-bof_dynamic
09-bad_seed
15-partial_overwrite
17-stack_pivot
```

**You gain:**

* RIP control
* Stack layout manipulation
* Entry-level exploit chaining

---

## LAYER 2.5 — Modern Mitigations & Bypasses

**Purpose:** Operate in realistic, defended binaries

```
5.1-mitigation_aslr_pie
6.1-mitigation_nx
7.1-mitigation_canary
7.2-mitigation_relro
```

**You gain:**

* Defense-aware exploitation
* Bypass reasoning
* Constraint-driven payload design

---

## LAYER 3 — Control Without Injection (ROP / ret2*)

**Purpose:** Program using existing code

```
14-ret_2_system
16-srop
18-ret2_csu_dl
19-shellcoding_pt1
20-patching_and_jumping
```

**You gain:**

* ROP chain construction
* Syscall-level control
* Payload minimalism

---

## LAYER 4 — Format Strings & Memory Disclosure

**Purpose:** Leak and write memory deliberately

```
10-fmt_strings
37-fs_exploitation
38-grab_bad
```

**You gain:**

* Arbitrary read/write
* GOT/stack corruption
* Reliable libc leaks

---

## LAYER 5 — Symbolic & Automated Reasoning

**Purpose:** Scale exploitation beyond manual effort

```
11-index
12-z3
13-angr
45-automatic_exploit_generation
```

**You gain:**

* Constraint solving mindset
* State-space exploration
* Exploit automation

---

## LAYER 6 — Heap Fundamentals

**Purpose:** Build allocator mental models

```
24-heap_overflow
25-heap
26-heap_grooming
27-edit_free_chunk
```

**You gain:**

* Chunk lifecycle understanding
* Heap layout control
* Memory corruption primitives

---

## LAYER 7 — Heap Attacks (Bins & Internals)

**Purpose:** Turn heap corruption into control

```
28-fastbin_attack
29-tcache
30-unlink
31-unsortedbin_attack
32-largebin_attack
33-custom_misc_heap
44-more_tcache
```

**You gain:**

* Arbitrary write via allocator abuse
* Reliable heap-based exploitation

---

## LAYER 8 — House of * Techniques (Advanced Heap)

**Purpose:** Subvert glibc design assumptions

```
39-house_of_spirit
40-house_of_lore
41-house_of_force
42-house_of_einherjar
43-house_of_orange
```

**You gain:**

* Allocator subversion
* Expert-level heap exploitation

---

## LAYER 9 — Logic & Integer Exploitation

**Purpose:** Exploitation without memory corruption

```
35-integer_exploitation
```

**You gain:**

* Logic abuse
* Boundary & arithmetic vulnerability exploitation

---

## 🧭 Recommended Progression Strategy

> ❌ Do NOT solve everything linearly

### Efficient Path:

1. Stack → ROP → Format String
2. Then Heap Fundamentals
3. Then Heap Attacks
4. Automation last

Revisit earlier layers as needed.

---

## 🧠 Final Notes

* This repository rewards **depth**, not speed
* Skipping is allowed — misunderstanding is not
* Treat every module as a **primitive generator**, not a puzzle

If you finish this repo with understanding, you are **not a CTF beginner anymore**.

---

Happy breaking binaries 🧨

---

## 📌 How to Use This Repository Effectively

This repository is **not meant to be solved mechanically or sequentially**.

Recommended workflow:

1. **Before each module**

   * Identify the *expected exploit primitive* ("What control do I gain if I succeed?")
   * Identify relevant mitigations

2. **During solving**

   * Avoid copy‑pasting known techniques
   * Derive the exploit from observed constraints

3. **After solving**

   * Write a short internal note:

     * What primitive was achieved
     * Why it worked
     * What assumption was broken

This approach converts exercises into **transferable exploit intuition**.

---

## 🧪 Per‑Layer Expected Primitives Checklist

### Layer 2 — Stack / BOF

* [ ] Instruction Pointer Control
* [ ] Controlled Stack Layout
* [ ] Partial Overwrite Reasoning
* [ ] Stack Pivoting

### Layer 3 — ROP / ret2*

* [ ] Libc Leak Acquisition
* [ ] ROP Chain Construction
* [ ] Syscall Invocation
* [ ] Minimal Gadget Usage

### Layer 4 — Format Strings

* [ ] Arbitrary Read
* [ ] Arbitrary Write
* [ ] GOT / Stack Targeting

### Layer 6–8 — Heap

* [ ] Heap Layout Control
* [ ] Allocator Metadata Corruption
* [ ] Bin‑based Exploitation
* [ ] Arbitrary Write via Heap

### Layer 5 — Automation

* [ ] Constraint Modeling
* [ ] Path Exploration
* [ ] Auto‑Exploit Generation

---

## 🧠 Syllabus‑Style View (Exploit Development Track)

**Phase 1 — Foundations**

* Assembly, tooling, reverse engineering

**Phase 2 — Control Flow Exploitation**

* Stack overflows, mitigations, ROP

**Phase 3 — Memory Disclosure & Writes**

* Format strings, leaks, controlled corruption

**Phase 4 — Heap Exploitation**

* Allocator internals, bin attacks, House of *

**Phase 5 — Automation & Reasoning**

* Symbolic execution, exploit generation

---

## 🎓 Resume & CTF Positioning Notes

If you complete this repository *with understanding*, you can legitimately claim:

* Binary Exploitation (Stack & Heap)
* ROP & Mitigation Bypasses
* glibc Allocator Internals
* Format String Exploitation
* Symbolic Execution (angr / Z3)

Suggested resume phrasing:

> *Completed a full exploit‑development curriculum covering stack, heap, mitigations, and automated exploitation using real‑world primitives.*

---

## ⚠️ Important Disclaimer

This repository is:

* ❌ NOT beginner‑friendly
* ❌ NOT walkthrough‑based
* ❌ NOT designed for speed‑running

It is designed for **deep capability building**.

If you rush it, you waste it.

---

## 🧩 Exploit Notes Template (Highly Recommended)

For each solved module, create a personal note file (not necessarily committed):

```
MODULE NAME:
Binary / Architecture:
Mitigations Enabled:

Bug Class:
Trigger Condition:

Primitive Gained:
(e.g. RIP control, arbitrary read, arbitrary write)

Key Insight:
(What assumption failed?)

Exploit Strategy:
- Leak source
- Control strategy
- Final payload logic

Failure Modes:
- What almost worked but didn’t
- What would break this exploit

Generalization:
- Where else does this pattern apply?
```

This converts each challenge into **reusable intuition**, not a one-off solve.

---

## 🧠 Exploit Primitives Reference (Mental Compression)

Think in terms of **outputs**, not vulnerabilities:

* Info Leak → ASLR defeat
* Partial Write → Controlled redirection
* Arbitrary Write → Code execution
* Heap Layout Control → Metadata corruption
* Syscall Control → Sandbox escape

If you cannot name the primitive you gained, you did not really solve the challenge.

---

## 🔀 CTF vs Real-World Exploitation Mapping

**CTF-Oriented Skills**

* Fast pattern recognition
* Gadget hunting
* Creative chaining

**Real-World Skills**

* Mitigation-aware design
* Reliability under constraints
* Minimal and stable payloads

This repository sits deliberately **between** the two.

---

## 🧠 When to Skip a Module

Skipping is valid if:

* You already understand the primitive
* The technique is deprecated for your target environment

Revisit later with stronger context.

---

## 🏁 Final Advice

Do not aim to *finish* this repository.
Aim to **internalize it**.

If you reach the point where you can:

* Look at a binary
* Predict exploitable primitives
* Choose the cheapest path to control

Then this repo has done its job.

If you understand it, you outgrow most CTFs.

---
