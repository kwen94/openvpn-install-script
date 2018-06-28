#!/bin/bash
#Description: install openvpn client
#Version: v1.0 v2.0
#Date: 2017-08-30 2018-05-26
#Author: kongxiangwen
#Email: 981651697@qq.com


args=$#
Client_Output_Path=$1
script_dir=$(cd `dirname $0`;pwd)
source /etc/init.d/functions

check(){ #格式化输出结果
    if [ $? -ne 0 ];then
        action "$1" /bin/false
        exit
    else
        action "$1" /bin/true
    fi
}


check_client_path(){  #客户端输出路径检测
	if [ $args -ne 1 ];then		#参数个数检测
		echo "Usage: Script.sh Client_Output_Path"
		exit 1
	fi

	if ! [ -d "$Client_Output_Path" ];then
		echo "${Client_Output_Path}目录不存在"
		echo "Usage: Script.sh Client_Output_Path"
		exit 1
	fi
}


check_cert_name(){ #客户端证书名检测
	read -p '输入客户端证书名(需唯一): ' CERT_NAME
	KEY_CN=`cat ${script_dir}/easy-rsa/2.0/vars | grep -o 'KEY_CN=.*$'|sed 's/KEY_CN=//'`
	KEY_SERVER_NAME=`cat ${script_dir}/easy-rsa/2.0/vars | grep -o 'KEY_SERVER_NAME=.*'|sed 's/KEY_SERVER_NAME=//'`
	KEY_CLIENT_NAME=`cat ${script_dir}/easy-rsa/2.0/vars | grep -o 'KEY_CLIENT_NAME=.*'|sed 's/KEY_CLIENT_NAME=//'`
	while true;do
		if [ -z "${CERT_NAME}" ];then
			read -p "输入为空 ，请重新输入: " CERT_NAME
		elif echo " ${KEY_CN} ${KEY_SERVER_NAME} ${KEY_CLIENT_NAME} " | grep -q " ${CERT_NAME} ";then
			read -p "证书名已存在，请重新输入: " CERT_NAME
		else
			sed -i 's/.*KEY_CLIENT_NAME.*/& '"${CERT_NAME}"'/' ${script_dir}/easy-rsa/2.0/vars
			break
		fi
	done
}

client_passwd(){
	read -p '输入客户端证书密码(可为空): ' KEY_CLIENT_PASSWD
}

create_certificate(){ #创建客户端证书
	cd ${script_dir}/easy-rsa/2.0/
	source ./vars &> /dev/null
	/usr/bin/expect << EOF
log_user 0
set timeout 5
spawn ./build-key $1
expect "Country Name" {send "\r"}
expect "State or Province Name" {send "\r"}
expect "Locality Name" {send "\r"}
expect "Organization Name" {send "\r"}
expect "Organizational Unit Name" {send "\r"}
expect "Common Name" {send "\r"}
expect "Name" {send "\r"}
expect "Email Address" {send "\r"}
expect "password" {send "${KEY_CLIENT_PASSWD}\r"}
expect "company name" {send "\r"}
expect "y/n" {send "y\r"}
expect "y/n" {send "y\r"}
expect "timeout" { puts "error"; exit 1 }
EOF
check "客户端证书生成"
}

create_client_config(){ #创建客户端config目录及文件
	cd ${Client_Output_Path}
	mkdir  openvpn_client_${CERT_NAME}
	cd openvpn_client_${CERT_NAME}
	cp -r ${script_dir}/* ./
	rm -rf  config/*
	config_path="`pwd`/config"
	client_path=`pwd`
	cd easy-rsa/2.0/keys/
	cp ca.crt ${CERT_NAME}.crt ${CERT_NAME}.key ta.key $config_path
}

create_client_conf(){ #创建客户端client.conf文件
	IP=`grep -oP "(?<=Openvpn_Client_Remote_IP=).*" ${script_dir}/easy-rsa/2.0/vars`
	cat << EOF >> ${config_path}/client.conf
client         #指定当前VPN是客户端
dev tun        #必须与服务器端的保持一致
proto udp      #必须与服务器端的保持一致
remote $IP 1194      #指定连接的远程服务器的实际IP地址和端口号
resolv-retry infinite    #断线自动重新连接，在网络不稳定的情况下(例如：笔记本电脑无线网络)非常有用。
nobind         #不绑定特定的本地端口号
persist-key
persist-tun
ca ca.crt      #指定CA证书的文件路径
cert ${CERT_NAME}.crt       #指定当前客户端的证书文件路径
key ${CERT_NAME}.key    #指定当前客户端的私钥文件路径
ns-cert-type server      #指定采用服务器校验方式
tls-auth ta.key 1     #如果服务器设置了防御DoS等攻击的ta.key，则必须每个客户端开启；如果未设置，则注释掉这一行；
comp-lzo              #与服务器保持一致
verb 3                #指定日志文件的记录详细级别，可选0-9，等级越高日志内容越详细
EOF
	echo
	echo -e "client.conf listen \033[32mremote $IP\033[0m"
	echo
	if grep -q "auth-user-pass-verify" ${script_dir}/config/server.conf;then
		echo "auth-user-pass #客户端开启密码认证" >> ${config_path}/client.conf
	fi
}
end(){ #无用文件清理
	cd $config_path
	cd ..
	rm -rf easy-rsa
	rm -rf openvpn_create_client_certificate.sh
	rm -rf $client_path/checkpsw.sh
	rm -rf  $client_path/psw-file
	rm -rf $client_path/openvpn-password.log
	cd $client_path
	mv $config_path/client.conf $config_path/client.ovpn
	tar -zcf $CERT_NAME-windows-config.tar.gz config
	mv $config_path/client.ovpn $config_path/client.conf
	check "客户端文件创建于$client_path/"
	echo
	echo "linux启动方法：cd $config_path ; $client_path/sbin/openvpn server.conf &"
	echo
	echo windows请将$client_path/$CERT_NAME-windows-config.tar.gz解压，将其中config目录覆盖openvpn安装目录的config目录
}

input(){
	check_client_path
	check_cert_name $CERT_NAME
	client_passwd
	create_certificate $CERT_NAME	
	create_client_config
	create_client_conf
	end
}
input
