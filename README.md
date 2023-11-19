# VulnLink

## TargetFuncFinder.py
```
    json_file_path = r'C:\Users\TheBinKing\Desktop\GIT\VulnLink\function_content.json'
    target_result,target_result_record = analyze_dangerous_functions_in_binary(json_file_path)
    print(target_result_record)  
```

根据危险函数规则，去搜索二进制中出现的危险函数，可以通过规则的键，去控制寻找的危险函数类，从而后续影响链条属性。


## TargetFuncChain.py
根据危险函数的函数名，去构造调用链条