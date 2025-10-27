# Usage: python patch_antidebug_babbleloader.py input.exe
# Patches both anti-debug block and BabbleLoader gates (Variant A & B)

import sys
import shutil

PATTERN_ANTIDEBUG = bytes.fromhex("9C 66 81 0C 24 00 01 9D C3 CC C3")

# Anchor for BabbleLoader decrypt stub (common across variants)
ANCHOR = bytes.fromhex("48 83 EC 20 65 48 8B 04 25 60 00 00 00")

def patch_block_antidebug(b: bytes) -> bytes:
    # Replace everything with NOP except keep RET (0xC3)
    return bytes(x if x == 0xC3 else 0x90 for x in b)

def patch_antidebug(buf: bytearray) -> int:
    n = len(PATTERN_ANTIDEBUG)
    count, i = 0, 0
    while True:
        j = buf.find(PATTERN_ANTIDEBUG, i)
        if j < 0:
            break
        buf[j:j+n] = patch_block_antidebug(PATTERN_ANTIDEBUG)
        count += 1
        i = j + n
    return count

def patch_gates(buf: bytearray) -> int:
    count, i = 0, 0
    while True:
        j = buf.find(ANCHOR, i)
        if j < 0:
            break

        # Limit scan to 0x100 bytes after anchor
        window = memoryview(buf)[j:j+0x100]
        wbytes = window.tobytes()

        # Gate A: 75 09
        idx1 = wbytes.find(b"\x75\x09")
        if idx1 != -1:
            buf[j+idx1:j+idx1+2] = b"\x90\x90"
            count += 1

        # Gate B short: 75 5A
        idx2 = wbytes.find(b"\x75\x5A")
        if idx2 != -1:
            buf[j+idx2:j+idx2+2] = b"\x90\x90"
            count += 1

        # Gate B near: 0F 85 xx xx xx xx
        idx3 = wbytes.find(b"\x0F\x85")
        if idx3 != -1 and idx3+6 <= len(window):
            buf[j+idx3:j+idx3+6] = b"\x90" * 6
            count += 1

        i = j + len(ANCHOR)

    return count

def main():
    if len(sys.argv) < 2:
        print("Usage: python patch_antidebug_babbleloader.py input.exe")
        sys.exit(1)

    path = sys.argv[1]
    backup = path + ".bak"

    shutil.copy2(path, backup)
    print(f"[+] Backup created: {backup}")

    with open(path, "rb") as f:
        data = f.read()

    buf = bytearray(data)

    # Patch anti-debug
    count_antidebug = patch_antidebug(buf)

    # Patch gates
    count_gates = patch_gates(buf)

    with open(path, "wb") as f:
        f.write(buf)

    print(f"[+] Patched {count_antidebug} anti-debug block(s)")
    print(f"[+] Patched {count_gates} gate(s) (Variant A/B)")
    print(f"[+] Done: {path}")

if __name__ == "__main__":
    main()
