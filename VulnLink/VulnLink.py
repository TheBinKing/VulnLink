from ast import expr_context
from cmath import exp
import collections
from email.policy import default
from uuid import RESERVED_FUTURE
import idaapi
import idc
import ida_ua
import os
import json
import idautils
import ida_kernwin
import ida_name
import ida_hexrays
import ida_funcs
import traceback

from TargetFuncFinder import analyze_dangerous_functions_in_binary
from TargetFuncChain import get_function_call_chains



icon = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00*\x00\x00\x00&\x08\x06\x00\x00\x00\xb2\x01\t \x00\x00\x00\x01sRGB\x00\xae\xce\x1c\xe9\x00\x00\x00\x04gAMA\x00\x00\xb1\x8f\x0b\xfca\x05\x00\x00\x00\tpHYs\x00\x00\x0e\xc3\x00\x00\x0e\xc3\x01\xc7o\xa8d\x00\x00\x02TIDATXG\xcd\x98\xcd.\x03Q\x14\xc7\xef\x10\x14-\xd5\xf8Jj!x\x00+,\xc5\x03\x88\x07\xb0\xb0\xb2\xea\x82\'\xc0\x13\x90\xb0\x15\x8f\x80x\x00+k\x89\xd8\x93\xb0\x94\xb0\x13A\xc6\xf9\xb7skz\xe7\xcc\xf4\xdc\xf9\xec/\xf9\xa5\x9d\x99\xce\xbdg\xce\xdc9\xf7N\x15\xb1@\x1e\x93\xf3\xd8\xe81\xaa\xe4\x91\xf7\xd9\xe4\x9etI\x04\xdc\x0b \xb0=\xf2\x89\xbc\xc0\x0e\r\xb2\x89@\xe1;\xb9C\x16\x05\xfaF\x80:\x9ee\xb2\x83KR\x1f\x84\xc8\xf2:\x99\x17\xe8K\xdfY\xed\x01\x19\xc0\x9fU\xbf\xb8\x80\xc0U\xa5\x08\xda\xbe%\xcd~qg\xdbc\xd3\x04\xe3\xc1<A\x9b\xf6\xf8E\x80h\x13\x01q\xfd\xb1\xd9\xd4\xe0\n\xb8\x93\xfcF6 \x00}D\x05\x081FC\xb3\xa9A#\xdc\xc9~1\x96l\x1f8I\x80Zq\xdb\xfe\xa7.J\x04\xbcEF\x81\x00\xf1\x1bI\x80\x10\xe3U\x0c\x1a\xe6\x1a\t\x13\x0f\x1c7apOr7\xad+\x8d4\xab~\xf10"`tf\x96;\x898\xc7\x1at\xc65\x96\x95\x18\x1a\xb1\xa7q\xae\xbeee\xa2\xf2\x97WV\x91\xcd\xae\xe5\xa8\x1b\x81\xb1\xd6glK\x1dp\x1c\xb7\x9fd\x8ea\x01\x92\x98\xc0\xd4\xeaxn\x0e\x97;\xf6G\xb9:Tj\x9e\xc3\x1c\x13\x15w)\x81\xa9\x15\x9d\xdeL\xd5\xdd\xdd\xf2x\xc7~\xceF\xa5\xea\x9e\xd5f\xc2\x02Mu\xa5\x86+\x0etrM\x81\xbe\xcd-\xb9\x1b\xa5\x91\xc01\xed\xf6\xe8\x98\xfbZ_tO\'\xa6\xb9\xe3\xa8\xb1"h\xb8\x89\xf8 OZ_\x83\x9c\xd7f\xd5\xda\xd0\xb0\xb7\xf5\xcf\xca`I\x1d\x8dO\xaa\x92C\xb9\xe4\xc1\xea]\x844P\xb0O>\xb7\xbe\xb6x\xfc\xfeRw_\x9f\xea\x81>\x1b\xe5\xaa\x1aq\xfe\x9bCp\x8d\xcaD\xfb7/\xbf?\xde\x916W\x9e\x99\x80\xf1\xc4\xdd\xc28ZO\x95\xb6\xc4\x99ZMcM\x95\xb6\xd8.XLQ\xdc\xb3|c\xe8 IV\x93.\xbc\xad\x88;\xb5&Zx\xc4%\xce\x82%\xd7lj0\xce\xb8`\xc2Lu\xaa\xb4%\xea\xad\xd5\xb4\x90lj\xd8\xa9\x95\x11Sea\xd9\xd4\x1c\x92\\p~3/\xee\x12\x90\xa9\xa8r\x95Kq\x97\x82\xf1\xc7\x05\ts+\xee\x12\xc2\xb2Z\xe8\x03\x14\x86\xb9`I\xe5=(+\xfcY\xed\xc9ljtV\x0b-\xeeR\xe2\xfc\x81V\x08\x19dR\xa9?"\x80\x16\n\xa6\x0c\x13@\x00\x00\x00\x00IEND\xaeB`\x82'
icon_id = idaapi.load_custom_icon(data=icon, format="png")

class utils:
    def get_negative_disass(op):
        # Get negative value based on the size of the operand
        if op.dtype == 0x0: # Byte
            return -(((op.value & 0xff) ^ 0xff) + 1)
        elif op.dtype == 0x1: # Word
            return -(((op.value & 0xffff) ^ 0xffff) + 1)
        elif op.dtype == 0x2: # Dword
            return -(((op.value & 0xffffffff) ^ 0xffffffff) + 1)
        elif op.dtype == 0x7: # Qword
            return -((op.value ^ 0xffffffffffffffff) + 1)

    def get_func_name(ea):
        # Get pretty function name
        func_name = utils.get_pretty_func_name(idc.get_func_name(ea))
        if not func_name:
            func_name = utils.get_pretty_func_name(idc.get_name(ea))
        return func_name

    def get_pretty_func_name(name):
        # Demangle function name
        demangled_name = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
        # Return as is if failed to demangle
        if not demangled_name:
            return name
        # Cut arguments
        return demangled_name[:demangled_name.find("(")]

    def prep_func_name(name):
        if name[0] != "." and name[0] != "_":
            # Name does not start with dot or underscore
            return [name,f".{name}",f"_{name}"]
        else:
            return [name[1:],f".{name[1:]}",f"_{name[1:]}"]
        
        
class VulnLink_Single_Function(idaapi.action_handler_t):
    result_window_title = "VulnLink Call Chain Results"
    result_window_columns_names = ["FuncName","FuncAddr", "ChainNo"]
    result_window_columns_sizes = [15,20,8]
    result_window_columns = [ list(column) for column in zip(result_window_columns_names,result_window_columns_sizes)]
    result_window_row = collections.namedtuple("VulnLinkCallChainResultRow",result_window_columns_names)

    def __init__(self,function_ea):
        idaapi.action_handler_t.__init__(self)
        self.function_ea = function_ea

    # Called when the button is clicked
    def activate(self, ctx):
        # Show the form
        function_name = idc.get_func_name(self.function_ea)
        if not function_name:
            function_name = idc.get_name(self.function_ea)
        
        chains = get_function_call_chains(function_name)
        rows = []
        for i, chain in enumerate(chains):
            for func in chain:
                rows.append([func[0], str(func[1]), str(i)])
            rows.append(['', '', ''])
            
        # Construct and show the form
        results_window = VulnLinkCallChainsEmbeddedChooser(self.result_window_title,self.result_window_columns,rows,icon_id, chains)
        results_window.Show()
        hooks.set_chains_chooser(results_window)

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
    
    

class VulnLinkCallChainsEmbeddedChooser(ida_kernwin.Choose):
    titles = ["FuncName","FuncAddr", "Status", "Priority","Comment"]
    result_window_row = collections.namedtuple("VulnLinkCallChainResultRow",titles)
    def __init__(self,title,columns,items,icon, chains, embedded=False):
        ida_kernwin.Choose.__init__(self,title,columns,embedded=embedded,width=100,flags=ida_kernwin.Choose.CH_MULTI + ida_kernwin.Choose.CH_CAN_REFRESH)
        self.items = items
        self.chains = chains
        self.icon = icon

    def GetItems(self):
        return self.items

    def SetItems(self,items):
        if items is None:
            self.items = []
        else:
            self.items = items
        self.Refresh()

    def OnRefresh(self, n):
        rows = []
        for i, chain in enumerate(self.chains):
            for func in chain:
                rows.append([func[0], str(func[1]), str(i)])
            rows.append(['', '', ''])
        self.items = rows

    def OnGetSize(self):
        return len(self.items)

    def OnSelectLine(self,number):
        # By default change to first selected line
        row = VulnLink_Single_Function.result_window_row(*self.items[number[0]])
        chainNo = int(row.ChainNo)
        columns_sizes = [15,20,8, 12, 30]
        columns = [ list(column) for column in zip(self.titles, columns_sizes)]
        rows = []
        for func in self.chains[chainNo]:
            rows.append([func[0], str(func[1]), '', '', ''])
        results_window = VulnLinkCallChainEmbeddedChooser('single call chain', columns, rows,icon_id, self.chains, chainNo)
        results_window.AddCommand("Mark as False Positive", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.AddCommand("Mark as Suspicious", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.AddCommand("Mark as Vulnerable", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.AddCommand("Set Vulnlink Comment", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.AddCommand("clean this chain", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.AddCommand("clean all chains contains this node", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.Show()
        hooks.set_chain_chooser(results_window)
      
        
    def OnGetLine(self,number):
        try:
            return self.items[number]
        except:
            self.Refresh()
            return None
         
        
class VulnLinkCallChainEmbeddedChooser(ida_kernwin.Choose):
    def __init__(self,title,columns,items,icon,chains, chainNo, embedded=False):
        ida_kernwin.Choose.__init__(self,title,columns,embedded=embedded,width=100,flags=ida_kernwin.Choose.CH_MULTI + ida_kernwin.Choose.CH_CAN_REFRESH)
        self.items = items
        self.icon = icon
        self.comment = False
        self.chains = chains
        self.chainNo = chainNo

    def GetItems(self):
        return self.items

    def SetItems(self,items):
        if items is None:
            self.items = []
        else:
            self.items = items
        self.Refresh()

    def OnRefresh(self,n):
        for item in self.items:
            item[0] = utils.get_func_name(int(item[1],16))
        if self.comment:
            if len(n) == 1:
                comment = ida_kernwin.ask_str(self.items[n[0]][4],1,f"Enter the comment: ")
            else:
                comment = ida_kernwin.ask_str("",1,f"Enter the comment: ")
            for i in n:
                self.items[i][4] = comment
            self.comment = False
            #self.save()
            
        return n

    def OnCommand(self,number,cmd_id):
        # Cmd_ids: 0 - FP, 1 - Susp, 2 - Vuln
        if cmd_id < 3:
            if cmd_id == 0:
                status = "False Positive"
            if cmd_id == 1:
                status = "Suspicious"
            if cmd_id == 2:
                status = "Vulnerable"
            # Item at index #3 is status
            self.items[number][4] = status
        if cmd_id == 3:
            # Comment
            self.comment = True
        if cmd_id == 4:
            # Delete selected items
            del self.chains[self.chainNo]
            self.Close()
        if cmd_id == 5:
            self.del_relate_chains(number)
            self.Close()
        self.Refresh()



    def OnGetSize(self):
        return len(self.items)

    def OnSelectLine(self,number):
        # By default change to first selected line
        row = VulnLinkCallChainsEmbeddedChooser.result_window_row(*self.items[number[0]])
        destination = row.FuncAddr
        ida_kernwin.jumpto(int(destination,10))

    def OnGetLineAttr(self, number):
        if self.items[number][2] == "False Positive":
            return (0x9D9D9D,0)
        elif self.items[number][2] == "Suspicious":
            return (0xd0FF,0)
        elif self.items[number][2] == "Vulnerable":
            return (0xFF,0)

    def OnGetLine(self,number):
        try:
            return self.items[number]
        except:
            self.Refresh()
            return None
        
    def del_relate_chains(self, number):
        func_name = self.items[number][0]
        func_addr = int(self.items[number][1])
        deleted = []
        for i, chain in enumerate(self.chains):
            for node in chain:
                if node[0] == func_name and node[1] == func_addr:
                    deleted.append(i)
                    break
        while deleted:
            self.chains.pop(deleted.pop())
               

class VulnLinkScanner:
    def __init__(self, custom_rules_file=None):
        if not custom_rules_file:
            self.rules_file = 'function_content.json'
        else:
            self.rules_file = custom_rules_file

    def start_scan(self):
        ida_kernwin.show_wait_box("VulnLink scan running ... ")
        rules_file_path = os.path.join(os.path.abspath(__file__), "..", self.rules_file)
        ida_kernwin.show_wait_box("rule path :  ",rules_file_path)
        target_result, target_result_record = analyze_dangerous_functions_in_binary(rules_file_path)
        ida_kernwin.hide_wait_box()
        res = []
        for each_result in target_result_record:
            print(each_result)
            result = []
            result.append(each_result['Binary file name'])
            result.append(each_result['FuncName'])
            result.append(each_result['Calladd'])
            result.append(each_result['FoundIn'])
            result.extend(['', '', ''])
            res.append(result)
        return target_result, res

  
class vulnlink_form_t(ida_kernwin.Form):

    def __init__(self,function_name):
        F = ida_kernwin.Form
        F.__init__(
            self,
            r"""STARTITEM {id:rule_name_str}
BUTTON YES* Run
BUTTON CANCEL Cancel
Custom VulnLink rule

{FormChangeCb}
Add custom rule to trace function: {function_name}
Custom rule name:
<#Name of the rule#:{rule_name_str}>
Custom Rule:
<#Rule as desribed in README#:{rule_str}>


""", {
            'function_name': F.StringLabel(function_name),
            'rule_name_str': F.StringInput(),
            'rule_str': F.StringInput(),
            'FormChangeCb': F.FormChangeCb(self.OnFormChange)
        })

    def OnFormChange(self, fid):
        return 1


class vulnlink_main_form_t(ida_kernwin.Form):

    def __init__(self):
        F = ida_kernwin.Form
        F.__init__(
            self,
            r"""STARTITEM {id:rDefault}
BUTTON YES* Run
BUTTON CANCEL Cancel
Custom VulnLink rule

{FormChangeCb}
<##What rule set to use?##Default rules:{rDefault}>
<Custom rules:{rCustom}>
<Import previous results (JSON):{rImport}>{cType}>
<#Select a file to open#Browse to open:{iFileOpen}>

""", {
            'iFileOpen': F.FileInput(open=True),
            'cType': F.RadGroupControl(("rDefault", "rCustom","rImport")),
            'FormChangeCb': F.FormChangeCb(self.OnFormChange)
        })

    def OnFormChange(self, fid):
        if fid == -1 or fid == self.cType.id:
            if self.GetControlValue(self.cType) == 0:
                self.EnableField(self.iFileOpen, False)
            else:
                self.EnableField(self.iFileOpen, True)
        return 1

class VulnLink(idaapi.action_handler_t):
    result_window_title = "VulnLink Results"
    result_window_columns_names = ["BinaryFileName","FuncName","Calladd", "FoundIn","Status", "Priority","Comment"]
    result_window_columns_sizes = [15,20,20,8,8,5,30]
    result_window_columns = [ list(column) for column in zip(result_window_columns_names,result_window_columns_sizes)]
    result_window_row = collections.namedtuple("VulnLinkResultRow",result_window_columns_names)
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    # Called when the button is clicked
    def activate(self, ctx):
        answer = 0
        skip_scan = False
        rows = []
        vulnlink_data = {}
        # Load stored data
        node = idaapi.netnode()
        node.create("vulnlink_data")
        if node.getblob(1,"S"):
            vulnlink_data = json.loads(node.getblob(1,"S"))
        else:
            vulnlink_data = {}
        if vulnlink_data:
            answer = ida_kernwin.ask_buttons("Load Existing","Scan Again","Cancel",1,f"Previous scan results found.")
        else:
            answer = 2
        if vulnlink_data and answer == 1:
            for item in vulnlink_data:
                # mod load previous data
                rows.append([vulnlink_data[item]["BinaryFileName"],vulnlink_data[item]["FuncName"],vulnlink_data[item]["Calladd"],vulnlink_data[item]["FoundIn"],vulnlink_data[item]["status"],vulnlink_data[item]["priority"],vulnlink_data[item]["comment"]])
                
            print("[VulnLink] Loading previous data.")
        elif answer == -1:
            # Cancel
            return
        else:
            # Show the form
            f = vulnlink_main_form_t()
            # Compile (in order to populate the controls)
            f.Compile()
            # Execute the form
            ok = f.Execute()
            # If the form was confirmed
            if ok == 1:
                # choose rules
                if f.cType.value == 0:
                    # Default scan
                    vulnlink_scanner = VulnLinkScanner()
                elif f.cType.value == 1:
                    try:
                        vulnlink_scanner = VulnLinkScanner(f.iFileOpen.value)
                    except:
                        ida_kernwin.warning("Failed to load custom rules!")
                        return
                else:
                    try:
                        with open(os.path.join(f.iFileOpen.value),"r") as import_file:
                            import_data = json.load(import_file)
                        for item in import_data["issues"]:
                            rows.append([item["BinaryFileName"],item["FuncName"],item["Calladd"],item["FoundIn"],item["Status"],item["Priority"],item["Comment"]])
                        skip_scan = True
                    except:
                        ida_kernwin.warning("Failed to load custom data files")
                        return
            else:
                return

            for item in vulnlink_data:
                rows.append([vulnlink_data[item]["BinaryFileName"],vulnlink_data[item]["FuncName"],vulnlink_data[item]["Calladd"],vulnlink_data[item]["FoundIn"],vulnlink_data[item]["status"],vulnlink_data[item]["priority"],vulnlink_data[item]["comment"]])
            # Run the scan
            if not skip_scan:
                print("[VulnLink] Started the scan ...")
                dangerous_funcs, scan_result = vulnlink_scanner.start_scan()
                if scan_result is None:
                    return
                rows.extend(scan_result)
                print("[VulnLink] Scan done!")
            # Save the results
            for item in rows:
                vulnlink_data[f"{item[3]}_{item[0]}"] = {"BinaryFileName":item[0],"FuncName":item[1],"Calladd":item[2],"FoundIn":item[3],"status":item[4],"priority":item[5],"comment":item[6]}
            node.setblob(json.dumps(vulnlink_data).encode("ascii"),1,"S")

        # Construct and show the form
        results_window = VulnLinkEmbeddedChooser(self.result_window_title,self.result_window_columns,rows,icon_id)
        results_window.AddCommand("Mark as False Positive", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.AddCommand("Mark as Suspicious", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.AddCommand("Mark as Vulnerable", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.AddCommand("Set VulnLink Comment", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.AddCommand("Remove Item(s)", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.AddCommand("Export Results", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.Show()
        hooks.set_func_chooser(results_window)

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class vulnlink_export_form_t(ida_kernwin.Form):

    def __init__(self):
        F = ida_kernwin.Form
        F.__init__(
            self,
            r"""STARTITEM {id:rJSON}
BUTTON YES* Save
BUTTON CANCEL Cancel
VulnLink Results Export

{FormChangeCb}
<##Choose format for export##JSON:{rJSON}>
<CSV:{rCSV}>{cType}>
<#Select the output file#Select the output file:{iFileOpen}>

""", {
            'iFileOpen': F.FileInput(save=True),
            'cType': F.RadGroupControl(("rJSON", "rCSV")),
            'FormChangeCb': F.FormChangeCb(self.OnFormChange)
        })

    def OnFormChange(self,fid):
        return 1


class VulnLinkEmbeddedChooser(ida_kernwin.Choose):
    def __init__(self,title,columns,items,icon,embedded=False):
        ida_kernwin.Choose.__init__(self,title,columns,embedded=embedded,width=100,flags=ida_kernwin.Choose.CH_MULTI + ida_kernwin.Choose.CH_CAN_REFRESH)
        self.items = items
        self.icon = icon
        self.delete = False
        self.comment = False
        self.export = False

    def GetItems(self):
        return self.items

    def SetItems(self,items):
        if items is None:
            self.items = []
        else:
            self.items = items
        self.Refresh()

    def OnRefresh(self,n):
        for item in self.items:
            item[2] = utils.get_func_name(int(item[2], 16))
        if self.comment:
            if len(n) == 1:
                comment = ida_kernwin.ask_str(self.items[n[0]][6],1,f"Enter the comment: ")
            else:
                comment = ida_kernwin.ask_str("",1,f"Enter the comment: ")
            for i in n:
                self.items[i][6] = comment
            self.comment = False
            self.save()
        if self.export:
            self.export = False
            self.vulnlink_export()
            
        return n

    def save(self):
        # On close dumps the results
        vulnlink_dict = {}
        for item in self.items:
            vulnlink_dict[f"{item[3]}_{item[0]}"] = {"name":item[0],"function":item[1],"in":item[2],"addr":item[3],"status":item[4],"priority":item[5],"comment":item[6]}
        node = idaapi.netnode()
        node.create("vulnlink_data")
        # Set the blob
        node.setblob(json.dumps(vulnlink_dict).encode("ascii"),1,"S")

    def OnCommand(self,number,cmd_id):
        # Cmd_ids: 0 - FP, 1 - Susp, 2 - Vuln
        if cmd_id < 3:
            if cmd_id == 0:
                status = "False Positive"
            if cmd_id == 1:
                status = "Suspicious"
            if cmd_id == 2:
                status = "Vulnerable"
            # Item at index #3 is status
            self.items[number][4] = status
        if cmd_id == 3:
            # Comment
            self.comment = True
        if cmd_id == 4:
            # Delete selected items
            self.delete = True
        if cmd_id == 5:
            # Export
            self.export = True
            
        self.Refresh()
        # Save the data after every change
        self.save()

    def vulnlink_export(self):
        # Show the form
        f = vulnlink_export_form_t()
        # Compile (in order to populate the controls)
        f.Compile()
        # Execute the form
        ok = f.Execute()
        # If the form was confirmed
        if ok == 1:
            # Get file name
            file_name = f.iFileOpen.value
            if file_name:
                if f.cType.value == 0:
                    # JSON
                    # Pretify 
                    tmp_json = {"issues":[]}
                    for item in self.items:
                        tmp_json["issues"].append({
                            "BinaryFileName": item[0],
                            "FuncName": item[1],
                            "Calladd": item[2],
                            "FoundIn": item[3],
                            "Status": item[4],
                            "Priority": item[5],
                            "Comment": item[6]
                        })
                    with open(file_name,"w") as out_file:
                        json.dump(tmp_json, out_file)
                    ida_kernwin.info(f"Results exported in JSON format to {file_name}")
                else:
                    #CSV
                    csv_string = "IssueName,FunctionName,FoundIn,Address,Status,Priority,Comment\n"
                    for item in self.items:
                        csv_string += f"{item[0]},{item[1]},{item[2]},{item[3]},{item[4]},{item[5]},{item[6]}\n"
                    with open(file_name,"w") as out_file:
                        out_file.write(csv_string)
                    ida_kernwin.info(f"Results exported in comma-separated CSV file to {file_name}")
        

    def OnGetSize(self):
        return len(self.items)

    def OnSelectLine(self,number):
        # By default change to first selected line
        row = VulnLink.result_window_row(*self.items[number[0]])
        destination = row.Calladd
        ida_kernwin.jumpto(int(destination,16))

    def OnGetLineAttr(self, number):
        if self.items[number][4] == "False Positive":
            return (0x9D9D9D,0)
        elif self.items[number][4] == "Suspicious":
            return (0xd0FF,0)
        elif self.items[number][4] == "Vulnerable":
            return (0xFF,0)

    def OnGetLine(self,number):
        try:
            return self.items[number]
        except:
            self.Refresh()
            return None


class vulnlink_fetch_t(idaapi.plugin_t):
    comment = "Vulnerability Finder"
    help = "This script helps to reduce the amount of work required when inspecting potentially dangerous calls to functions such as 'memcpy', 'strcpy', etc."
    wanted_name = "VulnLink"
    wanted_hotkey = ""
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        vulnlink_desc = idaapi.action_desc_t(
            'vulnlink:fetch',   # The action name. This acts like an ID and must be unique
            'VulnLink',  # The action text.
            VulnLink(),   # The action handler.
            '',      # Optional: the action shortcut
            'Make VulnLink fetch the potentially interesting places in binary.',  # Optional: the action tooltip (available in menus/toolbar)
            icon_id)           # Optional: the action icon (shows when in menus/toolbars)
        idaapi.register_action(vulnlink_desc)
        idaapi.attach_action_to_menu("Search", "vulnlink:fetch", idaapi.SETMENU_APP)

    def run(self):
        pass

    def term(self):
        pass



class Hooks(idaapi.UI_Hooks):
    def __init__(self):
        self.chains_chooser = None
        self.chain_chooser = None
        self.func_chooser = None
        idaapi.UI_Hooks.__init__(self)

    def finish_populating_widget_popup(self, form, popup):
        action_text = f"get all call chains for function '{utils.get_func_name(idc.here())}'"
        function_ea = idc.here()
        try:
            # Get selected symbol
            selected_symbol, _ = ida_kernwin.get_highlight(ida_kernwin.get_current_viewer())
            # Check if it is a function name
            for function in idautils.Functions():
                if utils.get_func_name(function) in utils.prep_func_name(selected_symbol):
                    action_text = f"Add '{utils.get_func_name(function)}' function to VulnLink"
                    function_ea = function
        except:
            pass
        action_desc = idaapi.action_desc_t(
        'vulnlink:get_one',   # The action name. This acts like an ID and must be unique
        action_text,  # The action text.
        VulnLink_Single_Function(function_ea),   # The action handler.
        '',      # Optional: the action shortcut
        'Make VulnLink look for all interesting refences of this function.',  # Optional: the action tooltip (available in menus/toolbar)
        icon_id)           # Optional: the action icon (shows when in menus/toolbars)
        idaapi.unregister_action("vulnlink:get_one")
        idaapi.register_action(action_desc)
        if ida_kernwin.get_widget_title(form) == 'VulnLink Results':
            idaapi.attach_action_to_popup(form, popup, "vulnlink:get_one", "")
        

    def current_widget_changed(self, widget, prev_widget):
        title = ida_kernwin.get_widget_title(widget)
        if title and title == 'VulnLink Call Chain Results' and self.chains_chooser:
            self.chains_chooser.Refresh()
        elif title and title == 'single call chain' and self.chain_chooser:
            self.chain_chooser.Refresh()
        elif self.func_chooser:
            self.func_chooser.Refresh()

    def set_func_chooser(self, func_chooser):
        self.func_chooser = func_chooser
        
    def set_chains_chooser(self, chains_chooser):
        self.chains_chooser = chains_chooser
        
    def set_chain_chooser(self, chain_chooser):
        self.chain_chooser = chain_chooser


# Run the hooks
hooks = Hooks()
hooks.hook()


def PLUGIN_ENTRY():
    return vulnlink_fetch_t()
