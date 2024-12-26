from patternClass import Pattern

def merge_bidirectional_patterns(pattern_list):
    """合并表示双向流量的模式"""
    merged_patterns = []
    used_patterns = set()
    used_patterns_obj = []
    
    def _check_reverse_pattern(pattern1, pattern2):
        """检查pattern2是否是pattern1的反向流量"""
        # 跳过不需要双向检查的协议
        if pattern1.layer_2 and pattern1.layer_2.__class__.__name__ in [
            'coap', 'dhcp', 'mdns', 'ssdp']:
            return False
            
        if pattern1.layer_1 and pattern1.layer_1.__class__.__name__ == 'igmp':
            return False
            
        if pattern1.layer_0 and pattern1.layer_0.__class__.__name__ == 'arp':
            return False
            
        # 检查协议层是否匹配
        if ((pattern1.layer_0 is None) != (pattern2.layer_0 is None) or
            (pattern1.layer_1 is None) != (pattern2.layer_1 is None) or
            (pattern1.layer_2 is None) != (pattern2.layer_2 is None)):
            return False
            
        # 检查每层协议的具体属性
        if pattern1.layer_0:
            if pattern1.layer_0.__class__ != pattern2.layer_0.__class__:
                return False
            if pattern1.layer_0.__class__.__name__ in ['ipv4', 'ipv6']:
                if (pattern1.layer_0.src != pattern2.layer_0.dst or 
                    pattern1.layer_0.dst != pattern2.layer_0.src):
                    return False
                    
        if pattern1.layer_1:
            if pattern1.layer_1.__class__ != pattern2.layer_1.__class__:
                return False
            if pattern1.layer_1.__class__.__name__ in ['tcp', 'udp']:
                if (pattern1.layer_1.src_port != pattern2.layer_1.dst_port or 
                    pattern1.layer_1.dst_port != pattern2.layer_1.src_port):
                    return False
                    
        if pattern1.layer_2:
            if pattern1.layer_2.__class__ != pattern2.layer_2.__class__:
                return False
                
        return True

    # 查找并合并双向模式
    for i, pattern1 in enumerate(pattern_list):
        if i in used_patterns:
            continue
            
        found_reverse = False
        for j, pattern2 in enumerate(pattern_list[i+1:], i+1):
            if j in used_patterns:
                continue
                
            if _check_reverse_pattern(pattern1, pattern2):
                # 创建合并后的模式
                merged = Pattern(
                    layer_0=pattern1.layer_0,
                    layer_1=pattern1.layer_1,
                    layer_2=pattern1.layer_2,
                    is_bidirectional=True  # 设置双向标志
                )
                merged_patterns.append(merged)
                used_patterns.add(i)
                used_patterns.add(j)
                used_patterns_obj.append(pattern1)
                used_patterns_obj.append(pattern2)
                found_reverse = True
                break
                
        if not found_reverse and i not in used_patterns:
            # 没有找到反向模式，添加原始模式
            merged_patterns.append(pattern1)
            
    return merged_patterns