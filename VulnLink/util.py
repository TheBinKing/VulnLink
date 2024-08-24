from openai import OpenAI
import json

import idaapi
import idc
import os


openai_client = OpenAI(
    # defaults to os.environ.get("OPENAI_API_KEY")
    api_key="sk-Htdev0KgVYIlmbW6jPeCyd50bl4FLh6rldp0ryjVU5e0U7k3",
    base_url="https://api.chatanywhere.tech/v1"
    # base_url="https://api.chatanywhere.cn/v1"
)


# 请求openai, 并且返回第一个选择
def request_openai(prompt):
    response = openai_client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "user", "content": prompt}
        ]
    )
    try:
        first_choice = response.choices[0]
        content = first_choice.message.content
        print("success request openai: ", content)
    except Exception as e:
        print("fail request openai:", e)
    return content
    
    
# 根据函数名、汇编码、伪代码返回大模型给出的函数签名
def get_function_signature(func_name, assembly_code=None, pseudo_code=None):
    prompt = """You are a senior security engineer. You are proficient in assembly language, disassembly, and software security skills. Now you are required to output the basic information of a function, mainly including the input and output of the function, based on the name of the function, the corresponding assembly code and pseudocode of the function. The thing to note is that you can't just make things up, and be sure to give correct results based on assembly code and pseudocode. You should make sure that your output is given in formatted json and does not contain any additional information,  your output should start with ```json and end with ``` to indicate that it is json. Such as for the functions described below in python code:```pythondef sum(a: int, b: int) -> int:\n\tc=a+b\n\treturn c```, you should output as belows: ```json\n{"input_parameters":[{"name":"a","desc":"dividend"},{"name":"b","desc":"divisor"}],"output_parameters":[{"name":"c","desc":"result"}],"func_desc":"get the result of a divide b, return as c"}```, input is as follows: func_name: """ + func_name + ", assembly_code: " + assembly_code + ", pseudocode: " + pseudo_code
    res = request_openai(prompt)
    res = res[8: -3]
    func_info = json.loads(res)
    print(func_info)
    return func_info



# 根据调用链和链上各个函数节点的签名信息，让大模型输出危险分数和危险说明
def get_call_chain_danger_score(call_chains, func_infos):
    prompt = """You are a senior security engineer and you are proficient in assembly language, disassembly, and software security skills. Now let's give you a chain of function calls and give you some basic information about each function node in the chain, including the input and output, and a description of the basic function function. The basic information of each function is given in the form: ```{"input_parameters":[{"name":"a","desc":"dividend"},{"name":"b","desc":"divisor"}],"output_parameters":[{"name":"c","desc":"result"}],"func_desc":"get the result of a divide b, return as c"}```.Based on the above information, you should perform taint analysis on the call chain, identify potential dangers, and quantitatively evaluate the danger degree of each dangerous function chain. Please use an integer from 0 to 100, where higher numbers indicate more dangerous and need attention. In addition, you should also give a description of the danger of the call chain. Make sure not to make things up and make sure your output is formatted, your output should start with ```json and end with ``` to indicate that it is json. Your output should look like the following example:```json\n{"score": 98, "desc": "This chain of function calls is risky because the output of b is controlled by the outside world"}```.input is as follows: call_chains: """ + json.dumps(call_chains) + " func_infos: " + json.dumps(func_infos)
    res = request_openai(prompt)
    res = res[8: -3]
    print(res)
    info = json.loads(res)
    print(info)
    return info['score'], info['desc']
    


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



if __name__ == '__main__':
    print(request_openai("Can you read assembly code"))

    
