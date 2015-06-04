#!/bin/bash

#第一参数为时间间隔  第二个参数为访问限制

#脚本路径
FILE_PATH=/home/joyous/joyous/scripts/github/web-server-plus
LOG_FILE=${FILE_PATH}/plus.log

if [ ! -f ${LOG_FILE} ];then
touch -f ${LOG_FILE}
fi

if [ -f /tmp/plus.lock ];then
echo 'run ....'>>${LOG_FILE} && exit 1
fi
touch /tmp/plus.lock

#访问日志
ACCESS_LOG='/var/www/log/redis_access.log'
if [ ! -f ${ACCESS_LOG} ];then
echo ${ACCESS_LOG}' not find!'>>${LOG_FILE}
exit 1
fi
#白名单一行一个
SAFE_LOG=${FILE_PATH}/allow.config
if [ ! -f ${SAFE_LOG} ];then
touch -f ${SAFE_LOG}
fi
SAFE_IP_ARRAY=$(awk '{print $0}' ${SAFE_LOG})
#恶意字符串
DENY_STR_FILE=${FILE_PATH}/bad_str.config
if [ ! -f ${DENY_STR_FILE} ];then
touch -f ${DENY_STR_FILE}
fi
BAD_STR_ARRAY=$(awk '{print $0}' ${DENY_STR_FILE})
#记录黑名单IP
BAD_IPS=${FILE_PATH}/deny.log
if [ ! -f ${BAD_IPS} ];then
touch -f ${BAD_IPS}
fi
#导入英文(转换日期)
export LANG=en_US
#开始
echo 'begin>>>>>>'>>${LOG_FILE}
TEMP_LOG=${FILE_PATH}/temp.log
if [ ! -f ${TEMP_LOG} ];then
touch -f ${TEMP_LOG}
fi
echo ''> ${TEMP_LOG}
#获取日志文件（取出前几分钟内日志文件）
for((i=0;i<${1};i++));do
    grep `date +'%d/%b/%Y:%H:%M' --date="-$i minute"` ${ACCESS_LOG}  >> ${TEMP_LOG}
done
#超出限定的前5个访问存放统计表
TEMP_BAD_VISETER=${FILE_PATH}/bad_vis_ips.log
cat ${TEMP_LOG} |awk -vnvar="$2" '{a[$1]++}END{for (j in a) if(a[j]>nvar) print a[j]"\t"j}'|sort -rnk1|head -5> ${TEMP_BAD_VISETER}

echo 'bad_vister.'>>${LOG_FILE}
cat ${TEMP_BAD_VISETER}>>${LOGF_FILE}


#访问恶意字符串直接拉黑（每个字符串最多处理2个）
TEMP_BAD_STR_IPS=${FILE_PATH}/bad_str_ips.log
if [ ! -f ${TEMP_BAD_STR_IPS} ];then
touch ${TEMP_BAD_STR_IPS}
fi
for str in ${BAD_STR_ARRAY[*]}
do
    cat ${TEMP_LOG}|grep ${str} | awk '{print $1}'  |uniq -c | head -2 >> ${TEMP_BAD_STR_IPS}
done

echo 'bad_str_vister.'>>${LOG_FILE}
cat ${TEMP_BAD_STR_IPS}>>${LOG_FILE}

#合并访问超出以及恶意访问的IP然后去重
cat ${TEMP_BAD_VISETER} |awk '{print $2}' > ${FILE_PATH}/bad_ips.log
cat ${TEMP_BAD_STR_IPS} |awk '{print $2}' >> ${FILE_PATH}/bad_ips.log
awk '{print $1}' ${FILE_PATH}/bad_ips.log |uniq >${FILE_PATH}/bad_ip.log
echo 'megre bad IP.'>>${LOG_FILE}
cat ${FILE_PATH}/bad_ip.log>>${LOG_FILE}
echo 'begin add iptables.'>>${LOG_FILE}
#处理本次拉黑的IP（去除在白名单的，去除不在黑名单的）
CURRENT_IPS=$(awk '{print $0}' ${FILE_PATH}/bad_ip.log)
for a in ${CURRENT_IPS[*]}
do
    #是否白名单
    IS_SAFE=`cat ${SAFE_LOG}|grep $a`
    if [ ! -z "${IS_SAFE}" ];then
    echo ${a} 'is safe ip.'>>${LOG_FILE}
    NUM=`iptables -L --line-number |grep ${a}|awk '{print $1}'`
    if [ ! -z "${NUM}"];then
    iptables -D INPUT ${NUM}
    echo ${a} 'is delete from iptables .'>>${LOG_FILE}
    fi
    continue
    fi
    
    IS_BAD=`cat ${BAD_IPS}|grep $a`
    #存在黑名单
    if [ ! -z "${IS_BAD}" ];then
         NUM=`iptables -L --line-number |grep ${a}|awk '{print $1}'`
         #存在防火墙
         if [ ! -z "${NUM}"];then
             echo ${a}' is exist bad.'>>${LOG_FILE}
             continue   
         fi
    fi
    #防止重复加入黑名单,检查是否在防火墙
    IS_EXIST=`iptables -nL |grep $a`
    if [ -z "${IS_EXIST}" ];then
    #防止防火墙规则大于2000个
    COUNT=`awk '{print NR}' ${BAD_IPS}` 
        if [ -z "${COUNT}" ] || [ ${COUNT} -lt 2000 ];then
         echo ${a}' add iptables.'>>${LOG_FILE}
         SUCCESS=`/sbin/iptables -I INPUT -p tcp --dport 80 -s ${a} -j DROP`
        fi
    fi  
done
#删除生成文件
echo 'delete temp file.'>>${LOG_FILE}
rm -f ${FILE_PATH}/bad_ips.log
rm -f ${FILE_PATH}/bad_ip.log
rm -f ${FILE_PATH}/bad_str_ips.log
rm -f ${FILE_PATH}/bad_vis_ips.log
rm -f ${FILE_PATH}/temp.log
echo "<<<<<<end">>${LOG_FILE}
rm -f /tmp/plus.lock
exit
