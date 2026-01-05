import re
import base64
import idautils
import ida_hexrays
import ida_bytes
import idaapi
import ida_nalt

B64_RE = re.compile(r'^[A-Za-z0-9+/=_-]{8,}$')

def decode_b64(s):
    s = s.strip('"')
    if not B64_RE.match(s):
        return None
    try:
        s += "=" * (-len(s) % 4)
        raw = base64.b64decode(s.replace("-", "+").replace("_", "/"))
        if not raw:
            return None
        # printable heuristic
        if sum(32 <= b <= 126 for b in raw) / len(raw) < 0.85:
            return None
        text = raw.decode("utf-8", errors="replace").strip()
        # reject meaningless short decodes like "one"
        if len(text) < 4:
            return None
        return text
    except Exception:
        return None

class Visitor(ida_hexrays.ctree_visitor_t):
    def __init__(self, cfunc):
        super().__init__(ida_hexrays.CV_FAST)
        self.cfunc = cfunc

    def visit_expr(self, e):
        # ONLY attach comments to CALL statements
        # This guarantees valid EA and no orphan comments
        if e.op != ida_hexrays.cot_call:
            return 0

        for a in e.a:
            decoded = None

            # Case 1: inline string literal
            if a.op == ida_hexrays.cot_str:
                decoded = decode_b64(str(a.string))

            # Case 2: object reference to string
            elif a.op == ida_hexrays.cot_obj and a.obj_ea != idaapi.BADADDR:
                bs = ida_bytes.get_strlit_contents(
                    a.obj_ea, -1, ida_nalt.STRTYPE_C
                )
                if bs:
                    decoded = decode_b64(bs.decode("utf-8", errors="replace"))

            if decoded:
                tl = ida_hexrays.treeloc_t()
                tl.ea = e.ea              # anchor to call line
                tl.itp = ida_hexrays.ITP_SEMI
                self.cfunc.set_user_cmt(tl, f"b64: {decoded}")
                break  # one comment per call line

        return 0

def main():
    if not ida_hexrays.init_hexrays_plugin():
        print("[-] Hex-Rays not available")
        return

    for f_ea in idautils.Functions():
        try:
            cfunc = ida_hexrays.decompile(f_ea)
        except Exception:
            continue

        v = Visitor(cfunc)
        v.apply_to(cfunc.body, None)
        cfunc.save_user_cmts()

    print("[+] Done")

main()
