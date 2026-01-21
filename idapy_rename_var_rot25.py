import ida_bytes
import ida_name
import ida_segment
import ida_kernwin
import ida_nalt

def rot25(s):
    out = []
    for c in s:
        if 'a' <= c <= 'z':
            out.append(chr((ord(c) - ord('a') - 1) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            out.append(chr((ord(c) - ord('A') - 1) % 26 + ord('A')))
        else:
            out.append(c)
    return ''.join(out)

def sanitize_name(name):
    name = ''.join(c if c.isalnum() or c == '_' else '_' for c in name)
    if name and name[0].isdigit():
        name = '_' + name
    return name

def rename_rot25_strings():
    renamed = 0

    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if not seg:
            continue

        ea = seg.start_ea
        while ea < seg.end_ea:
            flags = ida_bytes.get_full_flags(ea)

            if ida_bytes.is_strlit(flags):
                raw = ida_bytes.get_strlit_contents(
                    ea,
                    -1,
                    ida_nalt.STRTYPE_C
                )

                if raw:
                    try:
                        enc = raw.decode("ascii", errors="ignore")
                    except:
                        enc = None

                    if enc and any(c.isalpha() for c in enc):
                        dec = rot25(enc)
                        dec = sanitize_name(dec)

                        new_name = f"str_{dec}"

                        old_name = ida_name.get_name(ea)
                        if old_name.startswith("a") and len(dec) > 3:
                            if ida_name.set_name(
                                ea,
                                new_name,
                                ida_name.SN_AUTO | ida_name.SN_CHECK
                            ):
                                print(f"[+] {hex(ea)} : {enc} -> {new_name}")
                                renamed += 1

                    ea += len(raw)
                else:
                    ea += 1
            else:
                ea += 1

    ida_kernwin.msg(
        f"\n[✓] ROT25 rename complete: {renamed} strings renamed with 'str_' prefix\n"
    )

rename_rot25_strings()
