import idaapi
import idc
import idautils
import os
import json
import TargetFuncFinder

def get_function_call_chains_before(json_file_path):
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

    dangerous_functions, _ = TargetFuncFinder.analyze_dangerous_functions_in_binary(json_file_path,name="dangerous_functions")
    call_chain_results=analyze_dangerous_functions(dangerous_functions)
    return call_chain_results
def get_function_call_chains(func_name):
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
                sub_chain_results = analyze_function0(caller_func_name, list(call_chain), depth + 1, stop_function_names)
                
                for sub_chain in sub_chain_results:
                    last_call = sub_chain[-1]
                    last_seg = idaapi.getseg(last_call[1])
                    if last_seg and last_seg.type == idaapi.SEG_CODE:
                        results.append(sub_chain)

        return results if results else [call_chain] if idaapi.getseg(call_chain[-1][1]).type == idaapi.SEG_CODE else []

    # If the function name ends with "_ptr", remove it
    if func_name.endswith("_ptr"):
        func_name = func_name[:-4]

    # Analyze and return the call chains for the given function name
    return analyze_function0(func_name)


def connect_chain_before(dataflow_chain_file_path, sink_chain_file_path, output_path):
    def read_file_contents(file_path):
        with open(file_path, 'r') as file:
            return file.readlines()

    def parse_chain(chain):
        return [tuple(func.split('-')) for func in chain.strip().split(' -> ')]

    def check_list_cross(dataflow_chain, sink_chain):
        for i, dataflow_func in enumerate(dataflow_chain):
            for j, sink_func in enumerate(sink_chain):
                if dataflow_func == sink_func:
                    return dataflow_chain[:i + 1] + sink_chain[j + 1:]
        return None

    dataflow_chain_lines = read_file_contents(dataflow_chain_file_path)
    sink_chain_lines = read_file_contents(sink_chain_file_path)

    all_merge_list = []
    for dataflow_chain in dataflow_chain_lines:
        dataflow_chain_list = parse_chain(dataflow_chain)
        for sink_chain in sink_chain_lines:
            sink_chain_list = parse_chain(sink_chain)
            merged_list = check_list_cross(dataflow_chain_list, sink_chain_list)
            if merged_list:
                all_merge_list.append(merged_list)

    with open(output_path, 'w') as file:
        list_write_all = [' -> '.join(['-'.join(item) for item in merged]) + '\n' for merged in all_merge_list]
        file.writelines(set(list_write_all))  # Remove duplicates and write to file
def connect_chains(sink_chains, dangerous_chains):
    """
    连接 'sink_chains' 和 'dangerous_chains' 中的调用链。
    找到两个链条中的共同函数，并将它们连接起来。

    :param sink_chains: 包含调用链的列表，每个链条是 (函数名, 地址) 的元组列表。
    :param dangerous_chains: 另一个包含调用链的列表，格式同 sink_chains。
    :return: 包含连接后调用链的列表。
    """

    def reverse_chain(chain):
        return list(reversed(chain))

    def check_list_cross(sink_chain, dataflow_chain):
        """
        检查并连接两个调用链。如果找到共同的函数，将这两个链条连接起来，
        并在交汇点处添加特殊标记。

        :param sink_chain: 第一个调用链。
        :param dataflow_chain: 第二个调用链。
        :return: 连接后的调用链，如果没有交汇点，则返回 None。
        """
        for i, sink_func in enumerate(sink_chain):
            for j, dataflow_func in enumerate(dataflow_chain):
                if sink_func[0] == dataflow_func[0]:  # 比较函数名
                    # 连接两条链，并在交汇点处标记为1，其他为0
                    joint_chain = [(func[0], func[1], 0) for func in sink_chain[:i]] + \
                                  [(sink_func[0], sink_func[1], 1)] + \
                                  [(func[0], func[1], 0) for func in dataflow_chain[j+1:]]
                    return joint_chain
        return None

    # 将危险调用链逆序，以便更容易地与汇聚链匹配
    reversed_dangerous_chains = [reverse_chain(chain) for chain in dangerous_chains]

    all_merge_list = []
    # 遍历所有汇聚链和逆序后的危险链，寻找共同点并连接
    for sink_chain in sink_chains:
        for dataflow_chain in reversed_dangerous_chains:
            merged_list = check_list_cross(sink_chain, dataflow_chain)
            if merged_list:
                all_merge_list.append(merged_list)

    return all_merge_list


# 示例调用
def main():
    # 假设这里已经通过 get_function_call_chains 获取到了两个调用链列表
    sink_chains=get_function_call_chains("snprintf")
    #print(sink_chains)
    dangerous_chains=get_function_call_chains("memcmp")

    # 连接调用链
    connected_chains = connect_chains(sink_chains, dangerous_chains)

    # 设置输出文件路径
    output_file_path = r'C:\Users\TheBinKing\Desktop\GIT\VulnLink\output\connected_chains.txt'

    # 将结果写入文件
    with open(output_file_path, 'w') as file:
        for chain in connected_chains:
            chain_str = ' -> '.join(['-'.join(map(str, item)) for item in chain])
            file.write(chain_str + "\n")

if __name__ == "__main__":
    main()



    
#if __name__ == "__main__":
    # 示例使用
    # 返回数据格式
    # [
        # [('snprintf', 135211420), ('debug_printbpc', 134596976), ('bfdd_dest_deregister', 134599641), ('bfdd_replay', 134599907)]
        # [('memmove', 135211488), ('main', 134537530)]
    # ]
#    current_directory = os.path.dirname(os.path.realpath(__file__))
#    json_file_path = os.path.join(current_directory, 'function_content.json')
#    call_chains1 = get_function_call_chains(json_file_path)
#    for chain in call_chains1:
#        print(chain)
#    # 示例调用
#    json_file_path = os.path.join(current_directory, 'function_content.json')
#    call_chains1 = get_function_call_chains(json_file_path)
#
##    print(call_chain)
 #   connect_chain("dataflow_chain.txt", "sink_chain.txt", "output.txt")
    
    