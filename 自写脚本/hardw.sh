#!/bin/bash

# 远程访问主机，对主机的硬盘，内存，CPU获取使用参数

datetime=`date +"%Y-%m-%d_%H-%M-%S"`

username=fyhz_user
port=58422
host_ips=(10.10.0.157 10.10.0.66 10.10.0.53 10.10.0.133 10.10.0.137 10.10.0.52)
host_ips_d=(10.10.0.59 10.10.0.70 10.10.100.12 10.10.0.123 10.10.0.60 )

for i in ${host_ips_d[@]}
do 
      df_g_all=$(ssh -p $port $username@$i "df -hl /" |awk 'NR==2 { print $2  }')   
      df_h_all=$(ssh -p $port $username@$i "df -hl /home" |awk 'NR==2 { print $2  }')

      df_g_msg=$(ssh -p $port $username@$i "df -hl /" |awk 'NR==2 { print $4  }')   
      df_h_msg=$(ssh -p $port $username@$i "df -hl /home" |awk 'NR==2 { print $4  }')   

      cpu_msg=$(ssh -p $port $username@$i "top -bn 1 -i -c" | awk 'NR==3 {print $8}')    
      mem=$(ssh -p $port $username@$i "free -m" | awk 'NR==2 {print $2}')
      mem_free_msg=$(ssh -p $port $username@$i "free -m" | awk 'NR==2 {print $4}')
      mem_buffer_msg=$(ssh -p $port $username@$i "free -m" | awk 'NR==2 {print $6}')
      df_d_all=$(ssh -p $port $username@$ip_i "df -hl /data" |awk 'NR==2 { print $2  }')
      df_d_emp=$(ssh -p $port $username@$ip_i "df -hl /data" |awk 'NR==2 { print $4  }')
      echo $i disk_all："$df_g_all" + "$df_h_all" + "$df_d_all"，disk_emp："$df_g_msg" + "$df_h_msg" + "$df_d_emp"，cpu_emp："$cpu_msg"%，mem_all："$mem"，mem_emp："`expr $mem_free_msg + $mem_buffer_msg` m" >> ${datetime}_hardw.txt


done

for i in ${host_ips[@]}
do 
   
      df_g_all=$(ssh -p $port $username@$i "df -hl /" |awk 'NR==2 { print $2  }')   
      df_h_all=$(ssh -p $port $username@$i "df -hl /home" |awk 'NR==2 { print $2  }')

      df_g_msg=$(ssh -p $port $username@$i "df -hl /" |awk 'NR==2 { print $4  }')   
      df_h_msg=$(ssh -p $port $username@$i "df -hl /home" |awk 'NR==2 { print $4  }')   

      cpu_msg=$(ssh -p $port $username@$i "top -bn 1 -i -c" | awk 'NR==3 {print $8}')    
      mem=$(ssh -p $port $username@$i "free -m" | awk 'NR==2 {print $2}')
      mem_free_msg=$(ssh -p $port $username@$i "free -m" | awk 'NR==2 {print $4}')
      mem_buffer_msg=$(ssh -p $port $username@$i "free -m" | awk 'NR==2 {print $6}')
      df_d_all=$(ssh -p $port $username@$ip_i "df -hl /data" |awk 'NR==2 { print $2  }')
      df_d_emp=$(ssh -p $port $username@$ip_i "df -hl /data" |awk 'NR==2 { print $5  }')
      echo $i disk_all：" $df_g_all" + "$df_h_all"，disk_emp："$df_g_msg" + "$df_h_msg"，cpu_emp："$cpu_msg"%，mem_all："$mem"，mem_emp："`expr $mem_free_msg + $mem_buffer_msg` m" >> ${datetime}_hardw.txt


done