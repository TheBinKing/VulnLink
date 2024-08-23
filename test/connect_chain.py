def parse_chain(chain_str):
    return [tuple(item.split('-')) for item in chain_str.strip().split(' -> ')]

def read_chains_from_file(file_path):
    with open(file_path, 'r') as file:
        return [parse_chain(line) for line in file]

def main():
    # 读取两个文件中的调用链
    dangerous_chains_file = r''  # 替换为实际文件路径
    sink_chains_file  = r''  # 替换为实际文件路径

    sink_chains = read_chains_from_file(sink_chains_file)
    dangerous_chains = read_chains_from_file(dangerous_chains_file)

    # 连接调用链
    connected_chains = connect_chains(sink_chains, dangerous_chains)

    # 打印或处理连接后的调用链
    for chain in connected_chains:
        print(chain)
def connect_chains(sink_chains, dangerous_chains):
    """
    连接 'sink_chains' 和 'dangerous_chains' 中的调用链。
    找到两个链条中的共同函数，并将它们连接起来。

    :param sink_chains: 包含调用链的列表，每个链条是 (函数名, 地址) 的元组列表。
    :param dangerous_chains: 另一个包含调用链的列表，格式同 sink_chains。
    :return: 包含连接后调用链的列表。
    """

    def reverse_chain(chain):
        """
        将给定的调用链逆序。

        :param chain: 要逆序的调用链。
        :return: 逆序后的调用链。
        """
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






    reversed_dangerous_chains = [reverse_chain(chain) for chain in dangerous_chains]
    all_merge_list = []

    for dataflow_chain in reversed_dangerous_chains:
        for sink_chain in sink_chains:
            merged_list = check_list_cross(dataflow_chain, sink_chain)
            if merged_list:
                all_merge_list.append(merged_list)

    return all_merge_list
if __name__ == "__main__":
    main()
