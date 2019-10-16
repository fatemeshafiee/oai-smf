# prompt has been removed for easier Ctrl+C Ctrl+V
sudo ifconfig eno1:n4 172.55.55.101 up # SMF N4 interface
sudo ifconfig eno1:an11 172.16.1.102 up # AMF N11 interface
sudo ifconfig eno1:sn11 172.16.1.101 up # SMF N11 interface
#for N10
sudo ifconfig eno1:un10 172.58.58.102 up  # UDM N10 interface 
sudo ifconfig eno1:sn10 172.58.58.101 up  # SMF N10 interface 



sudo ifconfig eno1:sxc 10.10.10.1 up  # SMF N10 interface
INSTANCE=1
PREFIX='/usr/local/etc/oai'
sudo mkdir -m 0777 -p $PREFIX
cp ../../etc/smf.conf  $PREFIX

declare -A SMF_CONF

SMF_CONF[@INSTANCE@]=$INSTANCE
SMF_CONF[@PREFIX@]=$PREFIX
SMF_CONF[@PID_DIRECTORY@]='/var/run'
SMF_CONF[@SMF_INTERFACE_NAME_FOR_N4@]='eno1:n4'
SMF_CONF[@SMF_INTERFACE_NAME_FOR_N11@]='eno1:sn11'
SMF_CONF[@SMF_INTERFACE_IPV4_ADDRESS_FOR_N11@]='172.16.1.101'

SMF_CONF[@SMF_INTERFACE_PORT_FOR_N11@]='8080'


SMF_CONF[@SMF_UDM_IPV4_ADDRESS@]='172.58.58.102'
SMF_CONF[@SMF_UDM_PORT@]='8181'

SMF_CONF[@SMF_AMF_IPV4_ADDRESS@]='172.16.1.102'
SMF_CONF[@SMF_AMF_PORT@]='8282'


SMF_CONF[@SGW_INTERFACE_NAME_FOR_S11@]='eno1:s11'
SMF_CONF[@PGW_INTERFACE_NAME_FOR_SX@]='eno1:sxc'
SMF_CONF[@DEFAULT_DNS_IPV4_ADDRESS@]='8.8.8.8'
SMF_CONF[@DEFAULT_DNS_SEC_IPV4_ADDRESS@]='4.4.4.4'

for K in "${!SMF_CONF[@]}"; do 
  egrep -lRZ "$K" $PREFIX | xargs -0 -l sed -i -e "s|$K|${SMF_CONF[$K]}|g"
  ret=$?;[[ ret -ne 0 ]] && echo "Tried to replace $K with ${SMF_CONF[$K]}"
done
