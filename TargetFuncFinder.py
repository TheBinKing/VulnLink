import idaapi
import idc
import idautils
import os
import json

def analyze_dangerous_functions_in_binary(json_file_path, name="dangerous_functions"):
    """
    分析二进制文件中危险函数的调用情况。

    :param json_file_path: 指向包含危险函数列表的 JSON 文件的路径。
    :param name: JSON 文件中危险函数列表的键名，默认为 'dangerous_functions',通过这个参数名去获得不同的列表。
    :return: 一个包含危险函数名称的集合和详细调用信息的列表。
    """
    def read_dangerous_functions(file_path, name):
        try:
            with open(file_path, 'r') as file:
                data = json.load(file)
                return data.get(name, [])
        except FileNotFoundError:
            print(f"文件未找到: {file_path}")
            return []
        except json.JSONDecodeError:
            print(f"JSON 解析错误: {file_path}")
            return []
        except Exception as e:
            print(f"读取文件时发生错误: {e}")
            return []

    def is_direct_call(head):
        return idc.print_insn_mnem(head) == "call"

    def find_dangerous_calls(dangerous_functions):
        target_result_record = []
        target_function_names =set()
        for func_ea in idautils.Functions():
            func_name = idc.get_func_name(func_ea)
            for head in idautils.FuncItems(func_ea):
                if is_direct_call(head):
                    called_addr = idc.get_operand_value(head, 0)
                    called_name = idc.get_name(called_addr, idc.ida_name.GN_VISIBLE)
                    if any(danger_func in called_name for danger_func in dangerous_functions):
                        result = {
                            "Binary file name": os.path.basename(idc.get_input_file_path()),
                            "FuncName": called_name,
                            "Calladd": f"0x{head:08x}",
                            "FoundIn": func_name
                        }
                        target_result_record.append(result)
                        target_function_names.add(called_name)
        return target_function_names,target_result_record

    target_functions = read_dangerous_functions(json_file_path,name)
    target_result,target_result_record=find_dangerous_calls(target_functions)
    
    return target_result,target_result_record

if __name__ == "__main__":
    json_file_path = r'C:\Users\TheBinKing\Desktop\GIT\VulnLink\function_content.json'
    target_result,target_result_record = analyze_dangerous_functions_in_binary(json_file_path)
    print(target_result_record)  