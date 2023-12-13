# VulnLink

## TargetFuncFinder.py
```
    json_file_path = r'C:\Users\TheBinKing\Desktop\GIT\VulnLink\function_content.json'
    target_result,target_result_record = analyze_dangerous_functions_in_binary(json_file_path)
    print(target_result_record)  
```

核心功能：根据危险函数规则，去搜索二进制中出现的危险函数，可以通过规则的键，去控制寻找的危险函数类，从而后续影响链条属性。


## TargetFuncChain.py
核心功能：
1.根据危险函数的函数名，去构造调用链条（get_function_call_chains）
2.根据两条链（输入污点扩散链以及危险链）构建连接关系（connect_chains）


## todo
-√ 1.初步扫描，存在的危险函数窗口列表（UI）（TargetFuncFinder :  analyze_dangerous_functions_in_binary） √
- 2.点击危险函数，获得所有相关危险函数的调用链（TargetFuncChain：get_function_call_chains）
- 3.点击对应的调用链条，可以显示链条中每个函数节点（和1相同的UI，换成对应函数链条）
- 4-1.可以点击对应的函数链条可以进入对应函数的伪代码窗口，esc键可以返回上一级。
- 4-2.右键点击，菜单栏可以对节点进行相关标注，如果设置为clean则算法会把相关的调用链都去除。

UI：


## other
### vulFi
参考UI设计思路

### Gepetto
参考Chatgpt的设计思路方案，通过GPT进行智能支持。



## 使用说明书
search -> vulnLink 这些和Vulfi类似，得到Vulnlink result 窗口， 右键选择'get all call chains for function', 来到新窗口，Vulnlink call chains results, 这里展示所有调用链，两条调用链用空行分开，注意这只是一个临时窗口，仅用于用户选择进入不同的调用链，左键双击可进入单调用链窗口，右键选择clean this chain, 仅清除当前链，选择clean all chains contains this node, 清除所有包含该函数节点的调用链