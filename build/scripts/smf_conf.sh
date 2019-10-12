# prompt has been removed for easier Ctrl+C Ctrl+V
sudo ifconfig eno1:sxc 172.55.55.101 up # SMF N4 interface
sudo ifconfig eno1:s5c 172.58.58.102 up # SGW-C S5S8 interface
sudo ifconfig eno1:p5c 172.58.58.101 up # PGW-C S5S8 interface
sudo ifconfig eno1:s11 172.16.1.104 up  # SGW-C S11 interface
#for AMF/UDM
sudo ifconfig eno1:n11 172.16.1.106 up  # AMF interface
sudo ifconfig eno1:n10 172.16.1.105 up  # UDM interface

INSTANCE=1
PREFIX='/usr/local/etc/oai'
sudo mkdir -m 0777 -p $PREFIX
cp ../../etc/smf.conf  $PREFIX

declare -A SMF_CONF

SMF_CONF[@INSTANCE@]=$INSTANCE
SMF_CONF[@PREFIX@]=$PREFIX
SMF_CONF[@PID_DIRECTORY@]='/var/run'
SMF_CONF[@SGW_INTERFACE_NAME_FOR_S11@]='eno1:s11'
SMF_CONF[@PGW_INTERFACE_NAME_FOR_S5_S8_CP@]='eno1:p5c'
SMF_CONF[@PGW_INTERFACE_NAME_FOR_SX@]='eno1:sxc'
SMF_CONF[@DEFAULT_DNS_IPV4_ADDRESS@]='8.8.8.8'
SMF_CONF[@DEFAULT_DNS_SEC_IPV4_ADDRESS@]='4.4.4.4'

for K in "${!SMF_CONF[@]}"; do 
  egrep -lRZ "$K" $PREFIX | xargs -0 -l sed -i -e "s|$K|${SMF_CONF[$K]}|g"
  ret=$?;[[ ret -ne 0 ]] && echo "Tried to replace $K with ${SMF_CONF[$K]}"
done
