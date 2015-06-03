#!/bin/bash

#第一参数为时间间隔  第二个参数为访问限制

if [ -f /tmp/plus.lock ];then
echo 'run ....' && exit 1
fi
touch /tmp/plus.lock

#访问日志
ACCESS_LOG='/var/www/log/redis_access.log'
if [ ! -f ${ACCESS_LOG} ];then
echo ${ACCESS_LOG}' not find!'
exit 1
fi
#白名单一行一个
SAFE_LOG='./allow.config'
if [ ! -f ${SAFE_LOG} ];then
touch ${SAFE_LOG}
fi
SAFE_IP_ARRAY=$(awk '{print $0}' ${SAFE_LOG})
#恶意字符串
DENY_STR_FILE='./bad_str.config'
if [ ! -f ${DENY_STR_FILE} ];then
touch ${DENY_STR_FILE}
fi
BAD_STR_ARRAY=$(awk '{print $0}' ${DENY_STR_FILE})
#记录黑名单IP
BAD_IPS='./deny.log'
if [ ! -f ${BAD_IPS} ];then
touch ${BAD_IPS}
fi
#导入英文(转换日期)
export LANG=en_US
#开始
TEMP_LOG='./temp.log'
if [ -f ${TEMP_LOG} ];then
rm -f ${TEMP_LOG}
fi

#获取日志文件（取出前几分钟内日志文件）
for((i=0;i<${1};i++));do
    grep `date +'%d/%b/%Y:%H:%M' --date="-$i minute"` ${ACCESS_LOG}  >> ${TEMP_LOG}
done
#超出限定的前5个访问存放统计表
TEMP_BAD_VISETER=./bad_vis_ips.log
cat ${TEMP_LOG} |awk -vnvar="$2" '{a[$1]++}END{for (j in a) if(a[j]>nvar) print j}'|sort -rnk1|head -5> ${TEMP_BAD_VISETER}

#访问恶意字符串直接拉黑（每个字符串最多处理2个）
TEMP_BAD_STR_IPS=./bad_str_ips.log
if [ ! -f ${TEMP_BAD_STR_IPS} ];then
touch ${TEMP_BAD_STR_IPS}
fi
for a in ${BAD_STR_ARRAY[*]}
do
    awk '/game_server_web/{print $1}' ${TEMP_LOG} |uniq -c | head -2 >> ${TEMP_BAD_STR_IPS}
  
done
#合并访问超出以及恶意访问的IP然后去重
cat ${TEMP_BAD_VISETER} > ./bad_ips.log
cat ${TEMP_BAD_STR_IPS} >> ./bad_ips.log
awk '{print $1}' ./bad_ips.log |uniq >./bad_ip.log

#处理本次拉黑的IP（去除在白名单的，去除不在黑名单的）
CURRENT_IPS=$(awk '{print $0}' ./bad_ip.log)
for a in ${CURRENT_IPS[*]}
do
    #是否白名单
    IS_SAFE=`cat ${SAFE_LOG}|grep $a`
    if [ ! -z "${IS_SAFE}" ];then
    #如果新加入的从防火墙移除
    NUM=`iptables -L --line-number |grep 10.1.2.101|awk '{print $1}'`
    if [ ! -z "${NUM}"];then
    iptables -D INPUT ${NUM}
    fi
    continue
    fi
    #是否已拉黑
    IS_BAD=`cat ${BAD_IPS}|grep $a`
    if [ ! -z "${IS_BAD}" ];then
    continue
    fi
    #防止重复加入黑名单,检查是否在防火墙
    IS_EXIST=`iptables -nL |grep $a`
    if [ -z "${IS_EXIST}" ];then
    #防止防火墙规则大于2000个
    COUNT=awk '{print NR}' ${BAD_IPS} 
        if [ -z "${COUNT}" || ${COUNT} -lt 2000 ];then
        echo ${a} >> ${BAD_IPS}
        `iptables -I INPUT -p tcp --dport 80 -s ${a} -j DROP`
        fi
    fi  
done

rm -f /tmp/plus.lock
exit

