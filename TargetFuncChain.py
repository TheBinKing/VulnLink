import idaapi
import idc
import idautils
import os
import json
import TargetFuncFinder

def get_dangerous_function_call_chains(json_file_path):
    def analyze_function0(func_name, call_chain=None, depth=0, stop_function_names=None):
        if stop_function_names is None:
            stop_function_names = ['__libc_start_main', '_start', 'start', 'libc_start_main', 'main']

        if call_chain is None:
            call_chain = []

        if any(func_name == chain[0] for chain in call_chain):
            return []

        func_addr = idc.get_name_ea(0, func_name)
        call_chain.append((func_name, func_addr))

        if func_name in stop_function_names or func_addr == idaapi.BADADDR:
            return [call_chain]

        results = []
        for ref in idautils.CodeRefsTo(func_addr, False):
            caller_func = idaapi.get_func(ref)
            if caller_func:
                caller_func_addr = caller_func.start_ea
                caller_func_name = idc.get_func_name(caller_func_addr)

                # 递归地分析调用者
                sub_chain_results = analyze_function0(caller_func_name, list(call_chain), depth + 1, stop_function_names)
                
                # 过滤掉以非代码段结尾的调用链
                for sub_chain in sub_chain_results:
                    last_call = sub_chain[-1]
                    last_seg = idaapi.getseg(last_call[1])
                    if last_seg and last_seg.type == idaapi.SEG_CODE:
                        results.append(sub_chain)

        return results if results else [call_chain] if idaapi.getseg(call_chain[-1][1]).type == idaapi.SEG_CODE else []


    def analyze_dangerous_functions(dangerous_functions):
        all_chains = []
        for func in dangerous_functions:
            if func.endswith("_ptr"):
                func = func[:-4]
            chains = analyze_function0(func)
            all_chains.extend(chains)
        return all_chains

    dangerous_functions, _ = TargetFuncFinder.analyze_dangerous_functions_in_binary(json_file_path)
    call_chain_results=analyze_dangerous_functions(dangerous_functions)
    return call_chain_results



    
if __name__ == "__main__":
    # 示例使用
    # 返回数据格式
    # [
        # [('snprintf', 135211420), ('debug_printbpc', 134596976), ('bfdd_dest_deregister', 134599641), ('bfdd_replay', 134599907)]
        # [('memmove', 135211488), ('main', 134537530)]
    # ]
    current_directory = os.path.dirname(os.path.realpath(__file__))
    json_file_path = os.path.join(current_directory, 'function_content.json')
    call_chains = get_dangerous_function_call_chains(json_file_path)
    for chain in call_chains:
        print(chain)
