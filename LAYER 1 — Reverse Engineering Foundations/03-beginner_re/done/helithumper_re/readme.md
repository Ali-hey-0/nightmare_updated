
### My Solution / Write-up

**Challenge:** helithumper_re**Tools:** radare2, strings**Solution:**

- Input must start with exactly "flag" (first 4 bytes: 0x66 0x6c 0x61 0x67)
- Rest of string ignored
  **Command:**

```bash
echo "flag" | ./rev
# or "flaganything"
```
