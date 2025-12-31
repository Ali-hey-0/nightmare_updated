
# helithumper_re - Nightmare Beginner Reversing

## Challenge Description

- باینری ELF 64-bit
- پیام خوش‌آمدگویی: "Welcome to the Salty Spitoon™, How tough are ya?"
- ورودی می‌گیره و اگر درست باشه می‌گه "Right this way..."، وگرنه "Yeah right. Back to Weenie Hut Jr™ with ya"

## Tools

- strings (برای چک اولیه)
- radare2 / Ghidra (برای decompile)
- echo / terminal input

## Solution Steps

1. باینری واقعی داخل فولدر `rev/rev` قرار داره.
2. تابع `validate` چک می‌کنه که ۴ کاراکتر اول ورودی دقیقاً `'f','l','a','g'` (در هگز: 0x66, 0x6c, 0x61, 0x67) باشه.
3. اگر طول ورودی >= ۴ و ۴ کاراکتر اول "flag" باشه → return 1 → پیام قبول می‌ده.

## Exploit / Input

```bash
echo "flag" | ./rev
# یا هر چیزی که با "flag" شروع بشه
```
