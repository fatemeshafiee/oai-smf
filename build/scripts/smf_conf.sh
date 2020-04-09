# prompt has been removed for easier Ctrl+C Ctrl+V
sudo ifconfig eno1:smf  172.16.1.101 up # SMF 
sudo ifconfig eno1:amf  172.16.1.102 up # AMF 
sudo ifconfig eno1:udm  172.16.1.103 up # UDM
sudo ifconfig eno1:upf  172.16.1.104 up # UPF

INSTANCE=1
PREFIX='/usr/local/etc/oai'
sudo mkdir -m 0777 -p $PREFIX
cp ../../etc/smf.conf  $PREFIX

declare -A SMF_CONF

SMF_CONF[@INSTANCE@]=$INSTANCE
SMF_CONF[@PREFIX@]=$PREFIX
SMF_CONF[@PID_DIRECTORY@]='/var/run'
SMF_CONF[@SMF_INTERFACE_NAME_FOR_N4@]='eno1:smf'
SMF_CONF[@SMF_INTERFACE_NAME_FOR_N11@]='eno1:smf'
SMF_CONF[@SMF_INTERFACE_IPV4_ADDRESS_FOR_N11@]='172.16.1.101'

SMF_CONF[@SMF_INTERFACE_PORT_FOR_N11@]='80'

SMF_CONF[@UDM_IPV4_ADDRESS@]='172.16.1.103'
SMF_CONF[@UDM_PORT@]='8383'

SMF_CONF[@AMF_IPV4_ADDRESS@]='172.16.1.102'
SMF_CONF[@AMF_PORT@]='8282'

SMF_CONF[@UPF_IPV4_ADDRESS@]='172.16.1.104'

SMF_CONF[@DEFAULT_DNS_IPV4_ADDRESS@]='8.8.8.8'
SMF_CONF[@DEFAULT_DNS_SEC_IPV4_ADDRESS@]='4.4.4.4'

for K in "${!SMF_CONF[@]}"; do 
  egrep -lRZ "$K" $PREFIX | xargs -0 -l sed -i -e "s|$K|${SMF_CONF[$K]}|g"
  ret=$?;[[ ret -ne 0 ]] && echo "Tried to replace $K with ${SMF_CONF[$K]}"
done
