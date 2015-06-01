#!/bin/sh

#第一参数为时间间隔  第二个参数为访问限制,第三个最多处理IP数量

#封禁IP访问80
#iptables -I INPUT -p tcp --dport 80 -s 10.1.2.101 -j DROP

#运行日志
RUN_LOG=./debug.log
#访问日志
ACCESS_LOG=/var/www/log/redis_access.log
#分析日志文件
TEMP_LOG=./temp.log
#临时存放IP
TEMP_IP=./ips.log
#最多处理IP数量
TOTAL_IP=5
SAFE_LOG='./save_ips.log'
#白名单（一行一个）
SAFE_IP=$(awk '{print $0}' ${SAFE_LOG})
#指定限制文件
BAD_STR='http://fisiolaborbsb.com.br'
#黑名单IP记录文件
BAN_IP=./balckip.log
#导入英文
export LANG=en_US
#建立运行文件
if [ -f ${RUN_LOG} ];then
touch -f ${RUN_LOG}
fi
if [ -f ${TEMP_LOG} ];then
touch -f ${TEMP_LOG}
fi

if [ -f ${TEMP_IP} ];then
touch -f ${TEMP_IP}
fi
if [ -f ${BAN_IP} ];then
touch -f ${BAN_IP}
fi

#开始
echo `date` >> ${RUN_LOG}
[ -f ${ACCESS_LOG} ] || { echo "Can not read ${ACCESS_LOG}" >> ${RUN_LOG}; exit 1;}
echo "" > ${TEMP_LOG}
#获取日志文件
for((i=0;i<${1};i++));do
    grep `date +'%d/%b/%Y:%H:%M' --date="-$i minute"` ${ACCESS_LOG} |egrep -vi 'spider|Google|crawl|Yahoo' >> ${TEMP_LOG}
done

#访问恶意字符串直接拉黑
grep ${BAD_STR} ${TEMP_LOG}| awk -F " " '{print $1}' >${TEMP_IP}
#获取IP
cat ${TEMP_LOG} |awk -vnvar=${2} '{a[$1]++}END{for (j in a) if(a[j]>nvar) print j}'|sort -rnk1 >> ${TEMP_IP}



i=0
let MAXIP=${TOTAL_IP}-1
while read line
do
	ALL_IP[$i]=`echo ${line}|cut -d" " -f1`
	if [ "$i" -eq "$TOTAL_IP" ]; then 
		break;
	fi
	i=$(($i+1))
done < ${TEMP_IP}


LENGTH=${#ALL_IP[*]}
#检查是否有IP
if [ ${LENGTH} = 0 ]; then
	echo "None IP " >> ${RUN_LOG};
	exit 1;
fi

for i in ${ALL_IP[*]}
do
	for j in ${SAFE_IP} ;do 
	    #如果在白名单则直接跳过
		if [ "$j" = "$i" ]; then
		continue 2;
		fi
	done
	IS_BAD=`grep $i ${BAN_IP}`
	if [ -z ${IS_BAD} ];then
	echo $i >> ${BAN_IP}
	iptables -I INPUT -p tcp --dport 80 -s ${i} -j DROP
	fi
done
rm -f ${TEMP_LOG}
rm -f ${TEMP_IP}



