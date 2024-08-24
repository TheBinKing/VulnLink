import idaapi
import idc
import os

class HexRaysCodeXplorer:
    def __init__(self):
        if not idaapi.init_hexrays_plugin():
            raise RuntimeError("Hex-Rays Decompiler is not available.")

    def get_function_pseudocode(self, func_addr, pseudo_code_dir="./"):
        """
        给定函数地址，返回函数伪代码
        explorer = HexRaysCodeXplorer()
        pseudocode = explorer.get_function_pseudocode(func_start)
        """
        try:
            func = idaapi.get_func(func_addr)
            if not func:
                print(f"Function at 0x{func_addr:X} is not valid.")
                return ""

            cfunc = idaapi.decompile(func)
            if not cfunc:
                print(f"Failed to decompile function at 0x{func_addr:X}.")
                return ""
            func_name = idc.get_func_name(func_addr)
            with open(os.path.join(pseudo_code_dir, f"{func_name}.txt"), "w") as file:
                file.write(str(cfunc))
            return str(cfunc)

        except Exception as e:
            print(f"An error occurred: {e}")
            return ""

    def get_pseudocode_line(self, ea):
        """
        给定一个函数指定行得到对应的伪代码（存在异常）
        """
        func = idaapi.get_func(ea)
        if not func:
            raise ValueError(f"Instruction at 0x{ea:X} is not inside a valid function.")

        cfunc = idaapi.decompile(func)
        if not cfunc:
            raise RuntimeError(f"Failed to decompile function containing 0x{ea:X}.")

        body = cfunc.body
        if not body:
            raise RuntimeError(f"No body found for the function at 0x{ea:X}.")

        item = body.find_closest_addr(ea)
        if not item:
            raise ValueError(f"No citem_t found at address 0x{ea:X}.")

        x = idaapi.int_pointer()
        y = idaapi.int_pointer()
        if cfunc.find_item_coords(item, x, y):
            lines = cfunc.get_pseudocode()
            index = int(y.value())
            if 0 <= index < len(lines):
                line_text = lines[index].line
                try:
                    if isinstance(line_text, bytes):
                        line_text = line_text.decode('utf-8')
                    return line_text
                except UnicodeDecodeError as e:
                    raise ValueError(f"Could not decode pseudocode line: {e}")
            else:
                raise ValueError(f"Index out of range when accessing pseudocode lines.")
        else:
            raise ValueError(f"No pseudocode line found for the address 0x{ea:X}.")

    def get_function_asm_code(self, func_addr, asm_code_dir="./"):
        """
        给定一个函数地址，返回函数的汇编代码
        """
        try:
            func = idaapi.get_func(func_addr)
            if not func:
                print(f"Function at 0x{func_addr:X} is not valid.")
                return ""

            func_name = idc.get_func_name(func_addr)
            start_ea = func.start_ea
            end_ea = func.end_ea

            asm_code = []
            ea = start_ea
            while ea < end_ea:
                disasm = idc.generate_disasm_line(ea, 0)
                if disasm:
                    asm_code.append(disasm)
                ea = idc.next_head(ea, end_ea)
            
            asm_code_str = "\n".join(asm_code)
            with open(os.path.join(asm_code_dir, f"{func_name}.asm"), "w") as file:
                file.write(asm_code_str)
            
            return asm_code_str

        except Exception as e:
            print(f"An error occurred: {e}")
            return ""

# Example usage:
# explorer = HexRaysCodeXplorer()
# asm_code = explorer.get_function_asm_code(0x401000)
# print(asm_code)