#!/bin/bash
# 修改
# sed -i 's/\r//g' kf-x.sh
# 

rpm -qa |grep dialog &>/dev/null || yum -y install dialog &>/dev/null
#获取脚本所在目录
shell_dir=`pwd`

function server_initial {
    if [ `echo $UID` -eq 0 ];then
        echo "You are root. go on .."
    else
        echo "You are not root. go back.."
        exit 1
    fi

    id webapp
    if [ $e -ne 0 ];then
        useradd webapp
        echo "Fyhz1234.asd" | passwd --stdin webapp
        if [ $? -eq 0 ];then
            echo "User webapp create successful"
        else
            echo "User webapp create failure"
        fi
    else
        echo "User webapp already exists. go on.."
    fi

    #记录历史命令到日志文件
	cat $shell_dir/bashrc >> /etc/bashrc
	source /etc/bashrc

    #定义系统运行级别
	RUNLEVEL=`runlevel | awk '{print $2}'`
	if [ $RUNLEVEL -ne 3 ];then
		systemctl set-default multi-user.target
	fi

    #安装基础工具包
    yum -y install vim-enhanced bash-completion lsof curl wget net-snmp sysstat lrzsz zip unzip tree net-tools bind-utils nethogs iftop ethstatus nmap tcpdump ntpdate shtool extundelete rkhunter psmisc yum-utils dstat denyhosts crudini mailx 

    #修改主机名
    until [ "$action" == "0"  ] 
    do
	dialog --title "HOSTNAME" --inputbox "设置服务器主机名" 10 30 2>$temp_out
        HOSTNAME=`cat $temp_out`
        dialog --title "HOSTNAME" --yesno "Are you sure?" 0 0
        action=$?
    done
    dialog --title "HOSTNAME" --infobox "`echo "Setting Hostname Waiting: $HOSTNAME"`" 5 60
    hostname $HOSTNAME && echo "$HOSTNAME" >> /etc/hostname

    #定义解析DNS服务器
    for DNS in 114.114.114.114 8.8.8.8
    do
        ping -c1 -W1 $DNS &> /dev/null
        if [ $? -eq 0 ];then
            echo  "nameserver $DNS" >> /etc/resolv.conf
        else
            echo "DNS server can not to use or your network has a proplem."
            exit 1
        fi
    done

    #时间同步服务器
    timedatectl set-timezone $(timedatectl list-timezones |grep Shanghai)
    ping -c1 -W1 ntp1.aliyun.com
    if [ $? -eq 0 ];then
        ntpdate ntp1.aliyun.com
        echo "*/5 * * * * /usr/sbin/ntpdate ntp1.aliyun.com &>/dev/null" >> /etc/crontab
        hwclock --systohc
    fi

    #关闭防火墙
    systemctl status firewalld.service |grep running |grep -v grep
    if [ $? -eq 0 ];then
        systemctl stop firewalld.service &> /dev/null  
        systemctl disable firewalld.service &> /dev/null
    else
        echo "The firewalld is unactive. nothing to do. next..."
    fi

    #关闭SElinxu
    setenforce 0 
	sed -ri '/SELINUX=enforcing/c\SELINUX=disabled' /etc/selinux/config

    #开启密钥登陆
    # sed -i 's/#RSAAuthentication yes/RSAAuthentication yes/g' /etc/ssh/sshd_config
    # sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/g' /etc/ssh/sshd_config
    # sed -i 's/#AuthorizedKeysFile/AuthorizedKeysFile/g' /etc/ssh/sshd_config

    #禁止密码登陆
    # sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config

    #修改ssh登录端口
    sed -i '/^#Port 22/c\Port 58422' /etc/ssh/sshd_config
    sed -i '/^#UseDNS yes/c\UseDNS no' /etc/ssh/sshd_config
    systemctl restart sshd.service

#优化系统内核参数
sysctl -a >kernel_back
cat >> /etc/sysctl.conf << EOF 
##应对DDOS攻击,TCP连接建立设置
net.ipv4.tcp_syncookies = 1         #防范SYN Flood攻击
net.ipv4.tcp_synack_retries = 2     #控制内核向某个socket的ack,syn段（三次握手的第二次握手）重新发送响应的次数，降低此值可以尽早检测到来自远程主机的连接失败尝试
net.ipv4.tcp_syn_retries = 2 
net.ipv4.tcp_retries2 = 5       #控制内核向已建立连接的远程主机重新发送数据的次数，降低此值，可以尽早的检测连接失效
net.ipv4.tcp_max_syn_backlog = 30000        #限定SYN队列的长度
##应对timewait过高,TCP连接断开设置
net.ipv4.tcp_max_tw_buckets = 6000    #表示系统同时保持TIME-WAIT状态的socket连接的最大数量，超过则清除TIME-WAIT状态socket连接，并打印警告信息，默认32768
net.ipv4.tcp_tw_recycle = 1         #开启tcp连接中TIME-WAIT状态的socket的快速回收,默认0(关闭)
net.ipv4.tcp_tw_reuse = 1           #开启重用 允许将状态为TIME-WAIT的sockets 重新用于新的tcp连接，默认为0(关闭)
net.ipv4.tcp_fin_timeout = 6        #如果socket连接由本端关闭，则保持在FIN-WAIT-2状态的时间
net.ipv4.tcp_timestamps = 0 
net.ipv4.ip_local_port_range = 20000 60999  #用于向外连接的端口范围，默认 32768 61000
###TCP keepalived 连接保鲜设置
net.ipv4.tcp_keepalive_time = 30   #当keepalive起作用的时候，tcp发送keepalive消息的频度，默认2小时
net.ipv4.tcp_keepalive_intvl = 3   #内核向远程主机发送的保活探测的时间间隔
net.ipv4.tcp_keepalive_probes = 2  #内核发送保活探测的最大次数，如果探测次数大于这个数，则断定远程主机不可达，则关闭该连接并释放本地资源
###其他TCP相关调节
net.core.somaxconn = 262144
net.core.netdev_max_backlog = 262144  #表示在每个网络接口接收数据包的速率比内核处理这些包的速率快时，允许送到队列的数据包的最大数目
net.ipv4.tcp_max_orphans = 3276800
net.ipv4.tcp_sack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv4.neigh.default.gc_stale_time = 120
net.ipv4.conf.default.arp_announce = 2
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.lo.arp_announce = 2
net.ipv4.ip_forward = 0     #表示开启路由功能，0是关闭，1是开启
net.ipv4.conf.all.forwarding = 0
net.ipv4.conf.all.send_redirects = 0  #禁止转发重定向报文
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.rp_filter = 1  #打开反向路径过滤功能，防止ip地址欺骗
net.ipv4.conf.default.rp_filter = 1
#关闭如下参数可以防止黑客对服务器IP地址的攻击
#net.ipv4.conf.eth0.accept_source_route = 0
net.ipv4.conf.lo.accept_source_route = 0
net.ipv4.conf.all.accept_source_route = 0  #禁止包含源路由的ip包
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0     #禁止接收路由重定向报文，防止路由表被恶意更改
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0     #只接受来自网关的“重定向”icmp报文
net.ipv4.conf.default.secure_redirects = 0
#net.ipv4.route.max_size = 5242880      #路由缓存最大值
net.ipv4.icmp_echo_ignore_broadcasts = 1   #配置服务器拒绝接受广播风暴或者smurf 攻击attacks
net.ipv4.icmp_echo_ignore_all = 1          #防止PING,忽略所有icmp包
net.ipv4.icmp_ignore_bogus_error_responses = 1 #有些路由器针对广播祯发送无效的回应，每个都产生警告并在内核产生日志。这些回应可以被忽略

net.ipv4.tcp_max_orphans = 65536    #系统所能处理不属于任何进程的TCP sockets最大数量。假如超过这个数量﹐那么不属于任何进程的连接会被立即reset，并同时显示警告信息.
net.bridge.bridge-nf-call-ip6tables = 0
net.bridge.bridge-nf-call-iptables = 0
net.bridge.bridge-nf-call-arptables = 0
net.unix.max_dgram_qlen = 100           #进程间通信发送数据, 默认10
###内核相关参数设置###
kernel.sysrq = 1
kernel.core_uses_pid = 1
kernel.msgmnb = 65536
kernel.msgmax = 65536
kernel.shmmax = 68719476736
kernel.shmall = 4294967296
###内存资源使用相关设定
net.core.wmem_default = 8388608           #设置发送缓存区预留内存默认大小8M 默认值 16k
net.core.rmem_default = 8388608           #设置接受缓存区预留内存默认大小8M 默认值 16k
net.core.wmem_max = 16777216              #设置发送缓存区预留内存最大值16M 默认值 128k
net.core.rmem_max = 16777216              #设置接受缓存区预留内存最大值16M 默认值 128k
net.ipv4.tcp_rmem = 4096 65536 16777216   #调整tcp发送缓存 最小值 初始值 最大值 第三个值必须小于或等于wmem_max和rmem_max
net.ipv4.tcp_wmem = 4096 65536 16777216   #调整tcp接收缓存 最小值 初始值 最大值 第三个值必须小于或等于wmem_max和rmem_max
net.ipv4.tcp_mem = 8388608 8388608 16777216
net.ipv4.ipfrag_low_thresh = 3145728     #设置用于重新组合IP碎片的最小内存3M
net.ipv4.ipfrag_high_thresh = 4194304    #设置用于重新组合IP碎片的最大内存4M
EOF
sysctl -p

    ##################################### 安装zabbix-agent ########################################
    # ZABBIX_FILE=zabbix-3.2.1.tar.gz
    # if [ ! -f ./${ZABBIX_FILE}] ;then
    #     echo -e "\033[32m No zabbix package.Please download first..\033[0m"
    #     exit 1
    # fi
    # yum -y install gcc gcc-c++ pcre pcre-devel openssl openssl-devel
    # groupadd -r zabbix
    # useradd -r -g zabbix -s /sbin/nologin -M zabbix
    # tar -zxvf $ZABBIX_FILE && cd ${ZABBIX_FILE%.tar.gz}
    # ./configure --prefix=/usr/local/zabbix --enable-agent && make install
    
    # sed -ri '/^# PidFile=/c\PidFile=/tmp/zabbix_agentd.pid' /usr/local/zabbix/etc/zabbix_agentd.conf
    # sed -ri '/^# EnableRemoteCommands=0/c\EnableRemoteCommands=1' /usr/local/zabbix/etc/zabbix_agentd.conf
    # sed -ri '/^Server=127.0.0.1/c\Server=10.10.0.70' /usr/local/zabbix/etc/zabbix_agentd.conf
    # sed -ri '/^ServerActive=127.0.0.1/c\ServerActive=10.10.0.70' /usr/local/zabbix/etc/zabbix_agentd.conf
    # sed -ri "/^Hostname=Zabbix server/c\Hostname=`echo $HOSTNAME`" /usr/local/zabbix/etc/zabbix_agentd.conf
    # sed -ri '/^# UnsafeUserParameters=0/c\UnsafeUserParameters=1' /usr/local/zabbix/etc/zabbix_agentd.conf
    # cp ./misc/init.d/fedora/core/zabbix_agentd /etc/init.d/ && chkconfig zabbix_agentd on
    # sed -ri '/BASEDIR=\/usr\/local/c\BASEDIR=\/usr\/local\/zabbix' /etc/init.d/zabbix_agentd
    # /etc/init.d/zabbix_agentd start
    # zabbix_status=`pidof zabbix_agentd |wc -l`
    # if [ "$zabbix_status" = "1" ];then
    #     echo -e "\033[32mZabbix_agentd is running.\033[0m"
    #     sleep 3
    #     cd $shell_dir
    # else
    #     echo ""
    #     exit 1
    # fi

#安装saltstack-minion
cat > /etc/yum.repos.d/saltstack.repo << 'EOF'
[saltstack-repo]
name=SaltStack repo for Red Hat Enterprise Linux $releasever
baseurl=https://repo.saltstack.com/yum/redhat/$releasever/$basearch/latest
enabled=1
gpgcheck=1
gpgkey=https://repo.saltstack.com/yum/redhat/$releasever/$basearch/latest/SALTSTACK-GPG-KEY.pub
        https://repo.saltstack.com/yum/redhat/$releasever/$basearch/latest/base/RPM-GPG-KEY-CentOS-7
EOF

   #yum -y install epel-release
    yum -y install salt-minion

    sed -ri '/^#master:/c\master: salt-master' /etc/salt/minion
    sed -ri "/^#id:/c\id: `echo ${HOSTNAME%.novalocal} |sed 's/-/_/g'`" /etc/salt/minion
    echo "#salt-master ip address" >> /etc/hosts
    echo "10.30.1.246 salt-master" >> /etc/hosts

	systemctl enable salt-minion.service
    systemctl start salt-minion.service
    salt_status=`systemctl status salt-minion.service |grep -w Active |awk '{print $3}'`
    if [ $salt_status == '(running)' ];then
        dialog --title "Salt-minion Pro Info" --msgbox "`systemctl status salt-minion.service`" 10 90
    else
        echo "salt-minion.service is not running. please check salt-minion configure file or /etc/hosts"
        exit 1
    fi

}


#部署mariadb，可以提前准备好mariadbtar.tar.gz包,省略下载这步加个简单的判断
function mariadb_install {
	local MARIADB_URL=http://ftp.hosteurope.de/mirror/archive.mariadb.org//mariadb-10.1.34/source/mariadb-10.1.34.tar.gz
	local MARIADB_FILE=mariadb-10.1.34.tar.gz
	local MARIADB_SRC=`echo $MARIADB_FILE |sed 's/\.tar\.gz//g'`
	local SERVERID=$(ifconfig |awk 'NR==2{print $2}' |awk -F "." '{print $NF}') 

    #安装mariadb依赖包
    yum -y install cmake gcc gcc-c++ readline-devel bison bison-devel ncurses ncurses-devel zlib-devel openssl openssl-devel libaio-devel libcurl-devel libarchive-devel l libevent-devel
	cd $shell_dir
	if [ ! -f ./${MARIADB_FILE} ];then
		wget $MARIADB_URL
	fi
	groupadd -r -g 3306 mysql
	useradd -r -u 3306 -M mysql -g mysql -s /sbin/nologin
	ls /data/mysql || mkdir -p /data/mysql && tar -zxvf ${MARIADB_FILE} -C /data
	cd /data/${MARIADB_SRC} && cmake . -DCMAKE_INSTALL_PREFIX=/data/mysql -DMYSQL_DATADIR=/data/mysql/data -DWITHOUT_TOKUDB=1 -DWITH_INNOBASE_STORAGE_ENGINE=1 -DMYSQL_UNIX_ADDR=/tmp/mysql.sock -DDEFAULT_CHARSET=utf8 -DDEFAULT_COLLATION=utf8_general_ci && make && make install
	#编译失败的话执行 rm -f CMakeCache.txt /etc/my.cnf && make clean 重新编译
	if [ $? -ne 0 ];then
		echo "Run configure or make faiure."
	exit 1
	fi
	ls /data/mysql/logs || mkdir -p /data/mysql/logs
	chown -R mysql.mysql /data/mysql
	cp /data/mysql/support-files/mysql.server /etc/rc.d/init.d/mysqld
	ln -sf /data/mysql/bin/mysql* /usr/sbin/

	cat <<-EOF > /etc/my.cnf
	[client]
	port = 3306
	socket = /tmp/mysql.sock
	default-character-set = utf8mb4
	 
	[mysqld]
	port = 3306
	socket = /tmp/mysql.sock

	open-files-limit = 65535
	log-error = /data/mysql/logs/mysql.err
	pid-file  = /data/mysql/logs/mysql.pid
	 
	basedir = /data/mysql
	datadir = /data/mysql/data

	user = mysql
	#bind-address = 0.0.0.0

	server-id = $SERVERID		       #server-id的参数不能和其他节点一样，务必记住

	#binlog-do-db = db1                    #指定需要记录binlog的数据库,默认所有库，不建议master开启，过滤压力全在master上
	#replicate-do-db=account_sys           #要同步的数据库，默认所有库
	#binlog-ignore-db = mysql              #忽略同步的数据库
	#log_slave_updates                     #把从库的写操作记录到binlog中
	#expire_logs_days  = 365               #日志文件过期天数，默认是 0，表示不过期 
	#auto_increment_increment= 2	       #设定为主服务器的数量，防止auto_increment字段重复 
	#auto_increment_offset  = 2            #自增长字段的初始值，在多台master环境下，不会出现自增长ID重复


	character-set-client-handshake = FALSE
	character-set-server = utf8mb4
	collation-server = utf8mb4_unicode_ci
	init_connect = 'set names utf8mb4'

	lower_case_table_names = 1
	slow-query-log = on
	slow-query-log-file = /data/mysql/logs/mysql.bogon-slow.log
	long_query_time = 0.5
	sql_mode=NO_ENGINE_SUBSTITUTION,STRICT_TRANS_TABLES

	log_bin = mysql-bin
	binlog_format = mixed
	expire_logs_days = 30
	max_binlog_size = 1G
	log_bin                = /data/mysql/logs/mysql-bin
	log_bin_index          = /data/mysql/logs/mysql-bin.index
	 
	skip-name-resolve
	#skip-networking
	back_log = 300
	 
	max_connections = 1000
	max_connect_errors = 6000
	open_files_limit = 65535
	table_open_cache = 256
	max_allowed_packet = 4M
	binlog_cache_size = 1M
	max_heap_table_size = 8M
	tmp_table_size = 32M
	 
	read_buffer_size = 2M
	read_rnd_buffer_size = 8M
	sort_buffer_size = 8M
	join_buffer_size = 8M
	key_buffer_size = 16M
	 
	thread_cache_size = 16
	 
	query_cache_type = 1
	query_cache_size = 16M
	query_cache_limit = 2M
	 
	ft_min_word_len = 4
	 
	performance_schema = 0
	 
	skip-external-locking
	 
	default_storage_engine = InnoDB
	#default-storage-engine = MyISAM
	innodb_file_per_table = 1
	innodb_open_files = 500
	innodb_buffer_pool_size = 128M
	innodb_write_io_threads = 4
	innodb_read_io_threads = 4
	innodb_thread_concurrency = 0
	innodb_purge_threads = 1
	innodb_flush_log_at_trx_commit = 2
	innodb_log_buffer_size = 2M
	innodb_log_file_size = 32M
	innodb_log_files_in_group = 3
	innodb_max_dirty_pages_pct = 90
	innodb_lock_wait_timeout = 120
	 
	bulk_insert_buffer_size = 8M
	myisam_sort_buffer_size = 16M
	myisam_max_sort_file_size = 10G
	myisam_repair_threads = 1
	 
	interactive_timeout = 288000
	wait_timeout = 288000
	 
	[mysqldump]
	quick
	max_allowed_packet = 16M
	 
	[myisamchk]
	key_buffer_size = 16M
	sort_buffer_size = 8M
	read_buffer = 4M
	write_buffer = 4M


	[mysql]
	pager = more
	no-auto-rehash
	prompt = '[\u@\h] (\d) \R:\m> '
	default-character-set = utf8mb4
	EOF

	/data/mysql/scripts/mysql_install_db --user=mysql --basedir=/data/mysql --datadir=/data/mysql/data
	sleep 30
	wait
	/etc/init.d/mysqld start
	mysql_status=$(service mysqld status |awk '{print $3}')
	if [ "$mysql_status" == "running" ];then
	echo "Mysql server start success. go on ..."
	chkconfig --add mysqld
	chkconfig mysqld on
	else
	exit 1
	fi
	#根据需求创建指定数据库
	mysqladmin -uroot password 'sme123456'
	dialog --inputbox "输入要创建的数据库" 10 20 2>$temp_out
	NEW_DATABASE=$(cat $temp_out)
	dialog --inputbox "输入要创建的用户名" 10 20 2>$temp_out
	SQL_USER=$(cat $temp_out)
	dialog --inputbox "请输入新用户的密码" 10 20 2>$temp_out
	SQL_PASS=$(cat $temp_out)
	MYSQL=$(which mysql)
	$MYSQL -uroot -psme123456 <<-EOF
	CREATE DATABASE IF NOT EXISTS $NEW_DATABASE DEFAULT CHARSET utf8 COLLATE utf8_general_ci;

	grant all privileges on $NEW_DATABASE.* to "$SQL_USER"@"localhost" identified by "$SQL_PASS";

	grant all privileges on $NEW_DATABASE.* to "$SQL_USER"@"$HOSTNAME" identified by "$SQL_PASS";

	grant all privileges on $NEW_DATABASE.* to "$SQL_USER"@"%" identified by "$SQL_PASS";
	
	grant all privileges on *.* to root@"%";
	
	grant all privileges on *.* to root@"localhost";

	use mysql;

	select host,user,password from user;

	delete from user where user=' ';

	delete from user where password=' ';

	flush privileges;
	EOF
	if [ $? -eq 0 ];then
	dialog --title "Mariad DB Server Process Info" --msgbox "`ps aux |grep mysql |grep -v kaifu |grep -v grep`" 10 90
	fi
}

function mysql_install {
	rpm -qa |grep -e wget -e yum-utils || yum -y install wget yum-utils
	local MYSQL_REPO_URL=https://repo.mysql.com//mysql80-community-release-el7-3.noarch.rpm
	local MYSQL_REPO__FILE=mysql80-community-release-el7-3.noarch.rpm
	local SERVERID=$(ifconfig |awk 'NR==2{print $2}' |awk -F "." '{print $NF}')
	cd $shell_dir
	if [ ! -f ./${MYSQL_REPO_FILE} ];then
		wget $MYSQL_REPO_URL
	fi
	rpm -Uvh mysql80-community-release-el7-3.noarch.rpm
	yum-config-manager --disable mysql80-community
	yum-config-manager --enable mysql57-community   
	yum -y install mysql-community-server
	ls -d /var/log/mysql &>/dev/null || mkdir -p /var/log/mysql
	chown -R mysql:mysql /var/log/mysql
	systemctl start mysqld.service
	systemctl enable mysqld.service

	sleep 10
	wait

	mysql_status=$(service mysqld status |awk '/Active/{print $3}')
	if [ "$mysql_status" == "(running)" ];then
		random_pass=`grep 'temporary password' /var/log/mysqld.log |awk '{print $NF}'`	
		mysqladmin -u root -p"$random_pass" password '(Sme_123456)' &>/dev/null
	else
		exit 1
	fi
    #修改配置文件 my.cnf
	cp /etc/my.cnf /etc/my.cnf_bak
	cat <<-EOF >/etc/my.cnf
	[client]
	port	= 3306
	socket	= /var/lib/mysql/mysql.sock
	default-character-set = utf8mb4

	[mysql]
	prompt="\u@MySQL_57 \R:\m:\s [\d]> "
	no-auto-rehash
	default-character-set = utf8mb4

	[mysqld]
	user	= mysql
	port	= 3306
	datadir	= /var/lib/mysql
	socket	= /var/lib/mysql/mysql.sock
	pid-file = /var/run/mysqld/mysqld.pid

	character-set-server = utf8mb4
	skip_name_resolve = 1
	open_files_limit = 65535
	back_log = 1024
	max_connections = 2000
	max_connect_errors = 1000000

	table_open_cache = 2048
	table_definition_cache = 2048
	table_open_cache_instances = 64
	lower_case_table_names = 1
	sql_mode=STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION

	thread_stack = 512K
	external-locking = FALSE
	max_allowed_packet = 32M
	sort_buffer_size = 16M
	join_buffer_size = 16M
	thread_cache_size = 3000
	#interactive_timeout = 600
	#wait_timeout = 600

	tmp_table_size = 96M
	max_heap_table_size = 96M

	slow_query_log = 1
	slow_query_log_file = /var/log/mysql/slow.log
	log-error = /var/log/mysql/error.log
	long_query_time = 1.0
	log_queries_not_using_indexes =1
	log_throttle_queries_not_using_indexes = 60
	min_examined_row_limit = 100
	log_slow_admin_statements = 1
	log_slow_slave_statements = 1
	log_timestamps=SYSTEM
	
	server-id = $SERVERID
	log-bin = /var/log/mysql/mysql-bin
	sync_binlog = 1
	binlog_cache_size = 4M
	max_binlog_cache_size = 2G
	max_binlog_size = 1G
	expire_logs_days = 30
	master_info_repository = TABLE
	relay_log_info_repository = TABLE

	gtid_mode = on
	enforce_gtid_consistency = 1
	log_slave_updates
	slave-rows-search-algorithms = 'INDEX_SCAN,HASH_SCAN'
	binlog_format = row
	binlog_checksum = 1
	relay_log_recovery = 1
	relay-log-purge = 1

	key_buffer_size = 32M
	read_buffer_size = 8M
	read_rnd_buffer_size = 16M
	bulk_insert_buffer_size = 64M
	myisam_sort_buffer_size = 128M
	myisam_max_sort_file_size = 10G
	myisam_repair_threads = 1
	lock_wait_timeout = 3600
	explicit_defaults_for_timestamp = 1

	innodb_thread_concurrency = 0
	innodb_sync_spin_loops = 100
	innodb_spin_wait_delay = 30

	transaction_isolation = REPEATABLE-READ
	#innodb_additional_mem_pool_size = 16M
	innodb_buffer_pool_size = 128M	#设置为物理内存的70%
	innodb_buffer_pool_instances = 8
	innodb_buffer_pool_load_at_startup = 1
	innodb_buffer_pool_dump_at_shutdown = 1
	#innodb_data_file_path = ibdata1:1G:autoextend
	innodb_flush_log_at_trx_commit = 1
	innodb_log_buffer_size = 32M
	innodb_log_file_size = 2G
	innodb_log_files_in_group = 2
	innodb_max_undo_log_size = 4G
	innodb_undo_directory = undolog
	#innodb_undo_tablespaces = 95

	# 根据您的服务器IOPS能力适当调整
	innodb_io_capacity = 4000
	innodb_io_capacity_max = 8000
	innodb_flush_neighbors = 0
	innodb_write_io_threads = 8
	innodb_read_io_threads = 8
	innodb_purge_threads = 4
	innodb_page_cleaners = 4
	innodb_open_files = 65535
	innodb_max_dirty_pages_pct = 50
	innodb_flush_method = O_DIRECT
	innodb_lru_scan_depth = 4000
	innodb_checksum_algorithm = crc32
	innodb_lock_wait_timeout = 10
	innodb_rollback_on_timeout = 1
	innodb_print_all_deadlocks = 1
	innodb_file_per_table = 1
	innodb_online_alter_log_max_size = 4G
	internal_tmp_disk_storage_engine = InnoDB
	innodb_stats_on_metadata = 0

	# some var for MySQL 5.7
	innodb_checksums = 1
	#innodb_file_format = Barracuda
	#innodb_file_format_max = Barracuda
	query_cache_size = 0
	query_cache_type = 0
	innodb_undo_logs = 128

	innodb_status_file = 1
	# 开启 innodb_status_output & innodb_status_output_locks 后, 可能会导致log-error文件增长较快
	innodb_status_output = 0
	innodb_status_output_locks = 0

	#performance_schema
	performance_schema = 1
	performance_schema_instrument = '%=on'

	# innodb monitor
	innodb_monitor_enable="module_innodb"
	innodb_monitor_enable="module_server"
	innodb_monitor_enable="module_dml"
	innodb_monitor_enable="module_ddl"
	innodb_monitor_enable="module_trx"
	innodb_monitor_enable="module_os"
	innodb_monitor_enable="module_purge"
	innodb_monitor_enable="module_log"
	innodb_monitor_enable="module_lock"
	innodb_monitor_enable="module_buffer"
	innodb_monitor_enable="module_index"
	innodb_monitor_enable="module_ibuf_system"
	innodb_monitor_enable="module_buffer_page"
	innodb_monitor_enable="module_adaptive_hash"

	[mysqldump]
	quick
	max_allowed_packet = 32M
	EOF
    #重新启动mysql服务,使新的配置文件生效
	systemctl restart mysqld.service
	sleep 30
	wait
	mysql_status=$(service mysqld status |awk '/Active/{print $3}')
        if [ "$mysql_status" != "(running)" ];then
		exit
	fi
    #根据需求创建指定数据库
	dialog --inputbox "输入要创建的数据库" 10 20 2>$temp_out
	NEW_DATABASE=$(cat $temp_out)
	dialog --inputbox "输入要创建的用户名" 10 20 2>$temp_out
	SQL_USER=$(cat $temp_out)
	dialog --inputbox "请输入新用户的密码" 10 20 2>$temp_out
	SQL_PASS=$(cat $temp_out)
	MYSQL=$(which mysql)
	$MYSQL -u root -p'(Sme_123456)' <<-EOF
	set global validate_password_length=8;

	set global validate_password_policy=0;

	CREATE DATABASE IF NOT EXISTS $NEW_DATABASE DEFAULT CHARSET utf8 COLLATE utf8_general_ci;

	grant all privileges on $NEW_DATABASE.* to "$SQL_USER"@"localhost" identified by "$SQL_PASS";

	grant all privileges on $NEW_DATABASE.* to "$SQL_USER"@"$HOSTNAME" identified by "$SQL_PASS";

	grant all privileges on $NEW_DATABASE.* to "$SQL_USER"@"%" identified by "$SQL_PASS";
	
	grant all privileges on *.* to root@"%";
	
	grant all privileges on *.* to root@"localhost";

	use mysql;

	select host,user,password from user;

	delete from user where user=' ';

	delete from user where password=' ';

	flush privileges;
	EOF
	if [ $? -eq 0 ];then
	dialog --title "MySQL Server Process Info" --msgbox "`ps aux |grep mysql |grep -v kaifu |grep -v grep`" 10 90
	fi
}

function mysql8_install {
    rpm -qa |grep -e wget -e yum-utils || yum -y install wget yum-utils
    local MYSQL8_REPO_URL=https://repo.mysql.com//mysql80-community-release-el7-1.noarch.rpm
	local MYSQL8_REPO_FILE=mysql80-community-release-el7-1.noarch.rpm
	local SERVERID=$(ifconfig |awk 'NR==2{print $2}' |awk -F "." '{print $NF}')
	cd $shell_dir
    if [ ! -f ./${MYSQL8_REPO_FILE} ];then
		wget $MYSQL8_REPO_URL
	fi

    rpm -ivh mysql80-community-release-el7-1.noarch.rpm
    yum -y install mysql-server

    echo ulimit -SHn 65535 >>/etc/profile 
    source /etc/profile

    ls -d /var/log/mysql &>/dev/null || mkdir -p /var/log/mysql

    chown -R mysql:mysql /var/lib/mysql
    chown -R mysql:mysql /var/log/mysql

    #修改配置文件 my.cnf
	cp /etc/my.cnf /etc/my.cnf_bak
	cat <<-EOF >/etc/my.cnf
[client]
port	= 3306
socket	= /var/lib/mysql/mysql.sock
default-character-set = utf8mb4

[mysql]
prompt="\u@MySQL_80 \R:\m:\s [\d]> "
no-auto-rehash
default-character-set = utf8mb4 # 设置mysql客户端默认字符集

[mysqld]
user = mysql
port = 3306
datadir	= /var/lib/mysql
socket	= /var/lib/mysql/mysql.sock
pid-file = /var/run/mysqld/mysqld.pid
log-error = /var/log/mysql/error.log

character-set-server = utf8mb4
skip_name_resolve = 1
max_connections = 2000
max_connect_errors = 16
open_files_limit = 10000
back_log = 1024

table_open_cache = 2048
table_definition_cache = 2048
table_open_cache_instances = 64
lower_case_table_names = 1

thread_stack = 512K
external-locking = FALSE
max_allowed_packet = 32M
sort_buffer_size = 16M
join_buffer_size = 16M
thread_cache_size = 3000
lock_wait_timeout = 3600

tmp_table_size = 96M
max_heap_table_size = 96M

# 慢SQL日志记录
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 1.0
log_queries_not_using_indexes =1
log_throttle_queries_not_using_indexes = 60
min_examined_row_limit = 100
log_slow_admin_statements = 1
log_slow_slave_statements = 1
log_timestamps=SYSTEM

#  Bin-Log设置
server-id = $SERVERID
log-bin = /var/log/mysql/mysql-bin
binlog_format = row
binlog_row_image = FULL
binlog_expire_logs_seconds = 2592000
log_slave_updates
relay_log_recovery = 1
sync_binlog = 1
innodb_flush_log_at_trx_commit = 1
binlog_cache_size = 4M
max_binlog_cache_size = 2G
max_binlog_size = 1G
gtid_mode = on
enforce_gtid_consistency = 1
binlog_checksum = 1
relay-log-purge = 1

# 其他特性
key_buffer_size = 32M
read_buffer_size = 8M
read_rnd_buffer_size = 16M
bulk_insert_buffer_size = 64M
myisam_sort_buffer_size = 128M
myisam_max_sort_file_size = 10G
myisam_repair_threads = 1
explicit_defaults_for_timestamp = 1

# innodb_thread_concurrency = 0
# innodb_buffer_pool_size = 128M
# innodb_buffer_pool_instances = 8
# innodb_buffer_pool_load_at_startup = 1
# innodb_buffer_pool_dump_at_shutdown = 1
# innodb_data_file_path = ibdata1:1G:autoextend
	
# innodb_log_buffer_size = 32M
# innodb_log_file_size = 2G
# innodb_log_files_in_group = 2
# transaction_isolation = REPEATABLE-READ
# innodb_max_undo_log_size = 4G
	
# # 根据您的服务器IOPS能力适当调整
# innodb_io_capacity = 4000
# innodb_io_capacity_max = 8000
# innodb_flush_neighbors = 0
# innodb_write_io_threads = 8
# innodb_read_io_threads = 8
# innodb_purge_threads = 4
# innodb_page_cleaners = 4
# innodb_open_files = 65535
# innodb_max_dirty_pages_pct = 50
# innodb_flush_method = O_DIRECT
# innodb_lru_scan_depth = 4000
# innodb_checksum_algorithm = crc32
# innodb_lock_wait_timeout = 10
# innodb_rollback_on_timeout = 1
# innodb_print_all_deadlocks = 1
# innodb_file_per_table = 1
# innodb_online_alter_log_max_size = 4G

[mysqldump]
quick
max_allowed_packet = 128M

	EOF

    mysqld --initialize --lower-case-table-names=1

	/bin/systemctl start mysqld.service

	rm -rf /var/lib/mysql/*
	rm -rf /var/log/mysql/mysql-bin.index
	rm -rf /var/log/mysql/slow.log

    /bin/systemctl restart mysqld.service

	rm -rf /var/lib/mysql/*
	rm -rf /var/log/mysql/mysql-bin.index
	rm -rf /var/log/mysql/slow.log

    /bin/systemctl restart mysqld.service

    service mysqld status

    mysql_status=$(service mysqld status |awk '/Active/{print $3}')
	if [ "$mysql_status" == "(running)" ];then
		random_pass=`grep 'temporary password' /var/log/mysqld.log |awk '{print $NF}'`	
		mysqladmin -u root -p"$random_pass" password '(Sme_123456)' &>/dev/null
	else
		exit 1
	fi

    systemctl restart mysqld.service
	sleep 30
	wait
	mysql_status=$(service mysqld status |awk '/Active/{print $3}')
    if [ "$mysql_status" != "(running)" ];then
        echo "mysql重启失败！！！"
		exit
	fi

    #根据需求创建指定数据库
	dialog --inputbox "输入要创建的数据库" 10 20 2>$temp_out
	NEW_DATABASE=$(cat $temp_out)
	dialog --inputbox "输入要创建的用户名" 10 20 2>$temp_out
	SQL_USER=$(cat $temp_out)
	dialog --inputbox "请输入新用户的密码" 10 20 2>$temp_out
	SQL_PASS=$(cat $temp_out)
	MYSQL=$(which mysql)
	$MYSQL -u root -p'(Sme_123456)' <<-EOF
	set global validate_password_length=8;

	set global validate_password_policy=0;

	CREATE DATABASE IF NOT EXISTS $NEW_DATABASE DEFAULT CHARSET utf8 COLLATE utf8_general_ci;

	grant all privileges on $NEW_DATABASE.* to "$SQL_USER"@"localhost" identified by "$SQL_PASS";

	grant all privileges on $NEW_DATABASE.* to "$SQL_USER"@"$HOSTNAME" identified by "$SQL_PASS";

	grant all privileges on $NEW_DATABASE.* to "$SQL_USER"@"%" identified by "$SQL_PASS";
	
	grant all privileges on *.* to root@"%";
	
	grant all privileges on *.* to root@"localhost";

	use mysql;

	select host,user,password from user;

	delete from user where user=' ';

	delete from user where password=' ';

	flush privileges;
	EOF
	if [ $? -eq 0 ];then
    ver=$(mysqladmin --version|awk '{print $3}')
	dialog --title "MySQL ${ver} Server Process Info" --msgbox "`ps aux |grep mysql |grep -v kaifu |grep -v grep`" 10 90
	fi

}

#部署java环境.安装oracle-jdk
function tomcat_install {
    if [ -f ./jdk-8u211-linux-x64.tar.gz ];then
        tar -zxvf jdk-8u211-linux-x64.tar.gz -C /usr/local/
        mv -f /usr/local/jdk1.8.0_211 /usr/local/java
    else
        exit 1
    fi
    #java
    echo 'JAVA_HOME=/usr/local/java' >> /etc/profile
    echo 'JRE_HOME=/usr/local/java/jre' >> /etc/profile
    echo 'CLASS_PATH=.:$JAVA_HOME/lib/dt.jar:$JAVA_HOME/lib/tools.jar:$JRE_HOME/lib' >> /etc/profile
    echo 'PATH=$PATH:$JAVA_HOME/bin:$JRE_HOME/bin' >> /etc/profile
    echo 'export JAVA_HOME JRE_HOME CLASS_PATH PATH' >> /etc/profile
    
    source /etc/profile
    java -version &> /dev/null
    if [ $? -eq 0 ];then
        echo -e "\033[32mJAVA INSTALL SUCCESSFUL.GO ON..."
	sleep 5
    else
        exit 1
    fi

    #tomcat tomcat部署的前提是java环境已经配置完毕
    #local TOMCAT_FILE=apache-tomcat-8.5.40.tar.gz
	local TOMCAT_FILE=apache-tomcat-8.5.51.tar.gz
    local TOMCAT_SRC=`echo ${TOMCAT_FILE} |sed 's/\.tar\.gz//g'`
    #local TOMCAT_URL=https://mirrors.tuna.tsinghua.edu.cn/apache/tomcat/tomcat-8/v8.5.40/bin/apache-tomcat-8.5.40.tar.gz
    local TOMCAT_URL=http://mirror.bit.edu.cn/apache/tomcat/tomcat-8/v8.5.51/bin/apache-tomcat-8.5.51.tar.gz
	cd $shell_dir
    if [ ! -f ./${TOMCAT_FILE} ];then
    	wget $TOMCAT_URL
    fi
    dialog --inputbox "请输入 Tomcat 安装的目录" 10 20 2>$temp_out
    tomcat_path=`cat $temp_out`
    ls /home/webapp/$tomcat_path || mkdir -p /home/webapp/$tomcat_path

    tar -zxvf ${TOMCAT_FILE} -C /home/webapp/$tomcat_path

    cd /home/webapp/$tomcat_path && mv ${TOMCAT_SRC} tomcat

    chown -R webapp.webapp /home/webapp/$tomcat_path
    sed -ri '/^# OS/a\JAVA_OPTS="-XX:PermSize=64M -XX:MaxPermSize=128m -Xms256m -Xmx512m -Dfile.encoding=utf8"' /home/webapp/$tomcat_path/tomcat/bin/catalina.sh
    runuser -l webapp -s /bin/bash "/home/webapp/$tomcat_path/tomcat/bin/startup.sh"
    ps aux |grep tomcat |grep -v grep
    if [ $? -eq 0 ];then
        echo "The tomcat was start. please check catalina.out"
    	dialog --title "Tomcat Process Info" --msgbox "`echo "The tomcat was start. please check catalina.out" && ps aux |grep tomcat|grep -v kaifu |grep -v grep`" 10 90
    else
        dialog --title "Warming" --msgbox "`echo "The tomcat start failure. please check catalina.out"`" 10 90
        exit 1
    fi
    #tomcat配置文件可以从其它线上服务器取，根据需求修改。
}

#redis 编译安装的时候如果报错或者有依赖的包，先yum安装依赖的包
function redis_install {
    local REDIS_FILE=redis-5.0.4.tar.gz
    local REDIS_SRC=`echo $REDIS_FILE |sed 's/\.tar\.gz//g'`
    local REDIS_URL=http://download.redis.io/releases/redis-5.0.4.tar.gz
	rpm -qa |grep gcc-c++
		if [ $? -ne 0 ];then
			yum -y install gcc gcc-c++ libstdc++-devel
		fi
    cd $shell_dir
    if [ ! -f ./${REDIS_FILE} ];then
        wget $REDIS_URL
    fi
    tar -zxvf ${REDIS_FILE} -C /usr/local/ 
    cd /usr/local/${REDIS_FILE%.tar.gz}; make && make PREFIX=/usr/local/redis install
    mkdir -p /usr/local/redis/etc
    cp redis.conf /usr/local/redis/etc/
    sed -ri '/^protected-mode/c\protected-mode no' /usr/local/redis/etc/redis.conf
    sed -ri '/^bind 127/c\bind 0.0.0.0' /usr/local/redis/etc/redis.conf
	sed -ri '/^daemonize no/c\daemonize yes' /usr/local/redis/etc/redis.conf
	sed -ri '/^logfile ""/c\logfile "/var/log/redis/redis.log"' /usr/local/redis/etc/redis.conf
	mkdir -p /var/log/redis
    /usr/local/redis/bin/redis-server /usr/local/redis/etc/redis.conf
    sleep 15
    redis_stats=$(/usr/local/redis/bin/redis-cli ping)
    if [ "$redis_stats" == "PONG" ];then
       dialog --title "Ridis Server Process Info" --msgbox "`echo -e "\033[32mThe resdis-server is running\033[0m" && ps -aux |grep -w redis-server |grep -v kaifu |grep -v grep`" 10 90
    else
        dialog --title "Warming" --msgbox "`echo "The redis-server was not running."`" 0 0
        exit 1
    fi
    #配置文件根据具体需求修改
}

#安装Nginx Server
function nginx_install {
	local NGX_FILE=nginx-1.8.1.tar.gz
	local NGX_SRC=`echo $NGX_FILE |sed 's/\.tar\.gz//g'`
	local NGX_URL=http://nginx.org/download/nginx-1.8.1.tar.gz
    #安装nginx依赖包
	yum -y install gcc gcc-c++ make automake autoconf pcre pcre-devel libtool openssl openssl-devel zlib zlib-devel perl-devel perl-ExtUtils-Embed
    	cd $shell_dir
	if [ ! -f ./$NGX_FILE ];then
		wget $NGX_URL
	fi
	groupadd -r nginx
	useradd -r -g nginx -s /sbin/nologin -M nginx
	tar -zxvf $NGX_FILE && cd ${NGX_FILE%.tar.gz}
	./configure  --prefix=/usr/local/nginx --user=nginx --group=nginx --with-http_ssl_module  --with-http_auth_request_module --with-http_sub_module --with-http_gzip_static_module  --with-http_secure_link_module --with-http_stub_status_module --with-http_perl_module --with-ld-opt="-Wl,-E" --with-pcre --with-debug
	result=$?
	if [ $result -eq 0 ];then
		make && make install
	else
		echo "nginx configure failed"
		exit 
	fi
	/usr/local/nginx/sbin/nginx
	ln -s /usr/local/nginx/sbin/nginx /usr/local/sbin/nginx
	ngx_status=`$(which pidof) nginx |wc -l`
	if [ $ngx_status -eq 1 ];then
		dialog --title "Nginx Server Process Info" --msgbox "`echo -e "\033[32mThe nginx-server is running\033[0m" && ps -aux |grep -w nginx |grep -v kaifu |grep -v grep`" 10 90
	else
		dialog --title "Warming" --msbox "The Nginx Server Are Not Running."
	fi
}

#安装ActiveMQ消息队列.ActiveMQ依赖java环境.安装之前需要先执行安装Tomcat步骤.
function activemq_install {
	local ACTIVEMQ_FILE=apache-activemq-5.15.2-bin.tar.gz
	local ACVIVEMQ_SRC=`echo $ACTIVEMQ_FILE |sed 's/\-bin\.tar\.gz//g'`
	local ACTIVEMQ_URL=https://archive.apache.org/dist/activemq/5.15.2/apache-activemq-5.15.2-bin.tar.gz
    cd $shell_dir
	if [ ! -f ./${ACTIVEMQ_FILE} ];then
		wget $ACTIVEMQ_URL
	fi
	tar -zxvf ${ACTIVEMQ_FILE} -C /usr/local
	mv -f /usr/local/${ACVIVEMQ_SRC} /usr/local/activemq
	echo -e '\nJAVA_HOME="/usr/local/java"' >> /usr/local/activemq/bin/env
	source /usr/local/activemq/bin/env
	cd /usr/local/activemq/bin && ./activemq start
	active_status=`./activemq status |awk 'NR==3{print $2}'`
	if [ "$active_status" == "is" ];then
		dialog --title "ActiveMQ PRO Info" --msgbox "`./activemq status`" 10 90
	else
		dialog --title "Warming" --msgbox "ActiveMQ not running" 10 90
	fi
}

#安装入侵检测工具aide.配置邮箱报警.
function aide_install {
    	yum -y install aide mailx
	cat <<-EOF >>/etc/mail.rc
	set from=yunwei@smeyun.com
	set smtp=smtp.exmail.qq.com

	set smtp-auth-user=yunwei@smeyun.com
	set smtp-auth-password=Sh110120ok

	set smtp-auth=login
	EOF

    #初始化监控数据库(这需要一些时间)
    aide -c /etc/aide.conf --init | shtool prop -p "waiting..."

    #把当前初始化的数据库作为开始的基础数据库 
    cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz | shtool prop -p "waiting..."

    #添加crontab定时任务
    echo '00 05 * * * /usr/sbin/aide -C -V4 | /bin/mail -s "AIDE REPORT $(date +%Y%m%d)"' >> /etc/crontab

    #启用IPTABLES 防火墙

    #待完善


    #文件枷锁，禁止修改删除

    chattr +i /etc/passwd 
    chattr +i /etc/inittab 
    chattr +i /etc/group 
    chattr +i /etc/shadow 
    chattr +i /etc/gshadow 
    chattr +i /etc/resolv.conf 
    chattr +i /etc/hosts 
    chattr +i /etc/fstab
    chattr +i /etc/cron*
    chattr +i /var/spool/cron*

}

temp_out=$(mktemp -t text.XXXXX)
temp_menu=$(mktemp -t text.XXXXX)
while true
do
	dialog --title "锋云慧智开服脚本" --menu "Enter option" 20 30 10 1 "服务器初始化" 2 "安装MariaDB" 3 "安装Tomcat" 4 "安装Redis" 5 "安装Nginx" 6 "安装ActiveMQ" 7 "安装入侵检测系统" 8 "安装MySQL5.7" 9 "安装MySQL8.0" 10 "退出" 2> $temp_menu
	if [ $? -eq 1 ];then
		break
	fi

option=`cat $temp_menu`
	case $option in
	1)
	server_initial;;
	2)
	mariadb_install;;
	3)
	tomcat_install;;
	4)
	redis_install;;
	5)
	nginx_install;;
	6)
	activemq_install;;
	7)	
	aide_install;;
	8)
	mysql_install;;
	9)
	mysql8_install;;
	10)
	break;;
	*)
	dialog --msgbox "Sorry invalid option , please try again." 10 30;;
	esac
done
rm -rf $temp_menu 2> /dev/null
