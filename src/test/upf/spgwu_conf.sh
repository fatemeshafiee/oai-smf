# prompt has been removed for easier Ctrl+C Ctrl+V
#sudo ifconfig eno1:sxu 172.55.55.102 up   # SPGW-U SXab interface
sudo ifconfig eno1:s1u 192.168.248.159 up # SPGW-U S1U interface
INSTANCE=1
PREFIX='/usr/local/etc/oai'
sudo mkdir -m 0777 -p $PREFIX
cp ../../etc/spgw_u.conf  $PREFIX

declare -A SPGWU_CONF

SPGWU_CONF[@INSTANCE@]=$INSTANCE
SPGWU_CONF[@PREFIX@]=$PREFIX
SPGWU_CONF[@PID_DIRECTORY@]='/var/run'
SPGWU_CONF[@SGW_INTERFACE_NAME_FOR_S1U_S12_S4_UP@]='eno1:s1u'
SPGWU_CONF[@SGW_INTERFACE_NAME_FOR_SX@]='eno1:un4'
SPGWU_CONF[@SGW_INTERFACE_NAME_FOR_SGI@]='eno1'

for K in "${!SPGWU_CONF[@]}"; do 
  egrep -lRZ "$K" $PREFIX | xargs -0 -l sed -i -e "s|$K|${SPGWU_CONF[$K]}|g"
  ret=$?;[[ ret -ne 0 ]] && echo "Tried to replace $K with ${SPGWU_CONF[$K]}"
done
