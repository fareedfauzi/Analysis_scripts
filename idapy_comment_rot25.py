import idaapi
import idautils
import idc
import ida_kernwin

def rot25_decode(data):
    if not data: return ""
    decoded = ""
    for char in data:
        if 'a' <= char <= 'z':
            decoded += chr((ord(char) - ord('a') - 1) % 26 + ord('a'))
        elif 'A' <= char <= 'Z':
            decoded += chr((ord(char) - ord('A') - 1) % 26 + ord('A'))
        else:
            decoded += char
    return decoded

def find_string_at_address(ea):
    """ Helper to get string content even if it's not marked as a string literal """
    # Try to get string from IDA's string list first
    s = idc.get_strlit_contents(ea)
    if s:
        return s.decode("utf-8")
    
    # Fallback: manually read bytes until null terminator
    out = ""
    curr = ea
    for _ in range(256): # Max length safety
        b = idc.get_wide_byte(curr)
        if b == 0 or b == 0xFF: break
        out += chr(b)
        curr += 1
    return out if out else None

def rename_and_comment_rot25(func_name):
    resolver_addr = idc.get_name_ea_simple(func_name)
    if resolver_addr == idc.BADADDR:
        print(f"[-] Function {func_name} not found.")
        return

    print(f"[*] Scanning references to {func_name}...")
    count = 0

    for xref in idautils.XrefsTo(resolver_addr):
        call_addr = xref.frm
        
        # Look back up to 10 instructions to find the string reference
        curr_addr = call_addr
        found_string = False
        
        for _ in range(10):
            curr_addr = idc.prev_head(curr_addr)
            if curr_addr == idc.BADADDR: break
            
            # Check every operand in the instruction for a memory reference
            for op_idx in range(2):
                op_type = idc.get_operand_type(curr_addr, op_idx)
                
                # o_mem (Direct address) or o_imm (Immediate value/offset)
                if op_type in [idc.o_mem, idc.o_imm]:
                    possible_ptr = idc.get_operand_value(curr_addr, op_idx)
                    raw_str = find_string_at_address(possible_ptr)
                    
                    # Basic heuristic: if it looks like the encoded strings (Hfu..., Dsf...)
                    if raw_str and (raw_str.startswith("Hfu") or raw_str.startswith("Dsf") or len(raw_str) > 3):
                        decoded_str = rot25_decode(raw_str)
                        
                        # Set repeatable comment at the CALL instruction
                        idc.set_cmt(call_addr, decoded_str, 1)
                        # Also add it to the instruction where the string is loaded
                        idc.set_cmt(curr_addr, f"-> {decoded_str}", 0)
                        
                        print(f"[+] Found at {hex(call_addr)}: {raw_str} -> {decoded_str}")
                        count += 1
                        found_string = True
                        break
            if found_string: break

    print(f"[*] Done. Updated {count} locations.")
    ida_kernwin.request_refresh(ida_kernwin.IWID_ALL)

# Execute
rename_and_comment_rot25("fn_resolveAPI")
