# 说明
分析访问日志使用iptables禁止过于频繁的IP，可以用来防DDOS，恶意访问，采集

#帮助
##封禁IP访问80端口
iptables -I INPUT -p tcp --dport 80 -s 192.168.1.101 -j DROP
##查看规则
iptables --list --line-numbers
##删除指定规则
iptables -D INPUT 3
##清空规则
iptalbles -F

#使用
allow.config是白名单IP(一行一个)
bad_str.config是日志当中禁止出现的字符串(一行一个)
deny.log加入黑名单的IP记录
temp.log是临时日志文件
bad_vis_ips.log是超出访问限制的ip（一行一个）
bad_str_ips.log是禁止出现的字符串IP（一行一个）
bad_ips.log是bad_vis_ips.log和bad_str_ips.log的合并去重

