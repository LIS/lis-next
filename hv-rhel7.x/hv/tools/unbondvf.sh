#!/bin/bash

# This example script removes bonding network device configurations from a VM.
#
# What will be changed by this script?
# - If a bond interface is found, then this script tries to search its synthetic
#   slave and VF slave, based on the MAC address comparison.
# - If both of the slaves are found, then it will remove the bonding settings
#   from slave's ifcfg files.
# - Last, this script removes the bonding ifcfg file.
#
# Usage:
# - Run this scripts on the VM.
# - Reboot the VM.
#
# See /var/log/unbondvf.log for the log produced by this script.
#
# The config files for netvsc synthetic NICs will be reset to DHCP by default.
# You may edit them if you need to change to Static IP or change other settings.
#

sysdir=/sys/class/net
netvsc_cls={f8615163-df3e-46c5-913f-f2d2f965ed0e}
log_file="/var/log/unbondvf.log"

# Detect Distro
if [ -f /etc/redhat-release ];
then
	cfgdir=/etc/sysconfig/network-scripts
	distro=redhat
else
	echo "Unsupported Distro"
	exit 1
fi

function LOG() {
	echo "`date`: $1"
	echo "`date`: $1" >> $log_file
}

LOG "Detected Distro: $distro, or compatible"

# Get a list of ethernet names
list_bond_eth=(`cd $sysdir && ls -d */ | cut -d/ -f1 | grep bond`)
list_nonbond_eth=(`cd $sysdir && ls -d */ | cut -d/ -f1 | grep -v bond`)

if [[ -z "$list_bond_eth" ]]; then
	LOG "No bonding device present exiting..."
	exit 
fi

cnt_bond=${#list_bond_eth[@]}
cnt_nonbond=${#list_nonbond_eth[@]}

LOG "List of bonding devices:"
# Get the MAC addresses of bonding devices
for (( i=0; i<$cnt_bond; i++ ))
do
	list_bond_mac[$i]=`cat $sysdir/${list_bond_eth[$i]}/address`
	LOG "${list_bond_eth[$i]}, ${list_bond_mac[$i]}"
done

LOG ""

# Get the MAC addresses of non-bonding devices
for (( i=0; i<$cnt_nonbond; i++ ))
do
	list_nonbond_mac[$i]=`cat $sysdir/${list_nonbond_eth[$i]}/address`
done

# Find slave NICs of the bonding devices
for (( i=0; i<$cnt_bond; i++ ))
do
	LOG "Search slaves for ${list_bond_eth[$i]}"
	for (( j=0; j<$cnt_nonbond; j++ ))
	do
		if [ "${list_bond_mac[$i]}" = "${list_nonbond_mac[$j]}" ]
		then
			class_id=`cat $sysdir/${list_nonbond_eth[$j]}/device/class_id 2>/dev/null`
			if [ "$class_id" = "$netvsc_cls" ]
			then
				LOG "    netvsc device:  ${list_nonbond_eth[$j]}"
				list_netvsc[$i]=${list_nonbond_eth[$j]}
			else
				LOG "    vf device: ${list_nonbond_eth[$j]}"
				list_vf[$i]=${list_nonbond_eth[$j]}
			fi
		fi
	done
done

# Remove bonding
for (( i=0; i<$cnt_bond; i++ ))
do
	LOG ""
	LOG "Processing ${list_bond_eth[$i]}"

	if [ list_netvsc[$i] != "" ] && [ list_vf[$i] != "" ]
	then
		netvsc_config_file=$cfgdir/ifcfg-${list_netvsc[$i]}
		LOG "    Configure $netvsc_config_file"
		if grep -E -q 'MASTER=bond0|SLAVE=yes' $netvsc_config_file
		then
			# Remove bonding settings
			sed -i 's/^MASTER=bond0//' $netvsc_config_file
			sed -i 's/^SLAVE=yes//' $netvsc_config_file
			# Change BOOTPROTO to dhcp
			sed -i 's/^BOOTPROTO=none/BOOTPROTO=dhcp/' $netvsc_config_file
		else
			LOG "WARNING! Incomplete bonding found. Ignore this file."
		fi

		vf_config_file=$cfgdir/ifcfg-${list_vf[$i]}
		LOG "    Configure $vf_config_file"
		if grep -E -q 'MASTER=bond0|SLAVE=yes' $vf_config_file
		then
			# Remove bonding settings
			sed -i 's/^MASTER=bond0//' $vf_config_file
			sed -i 's/^SLAVE=yes//' $vf_config_file
		else
			LOG "WARNING! Incomplete bonding found. Ignore this file."
		fi

		bond_config_file=$cfgdir/ifcfg-${list_bond_eth[$i]}
		LOG "    Remove $bond_config_file"
		rm -f $bond_config_file
	else
		LOG "WARNING! Missing slaves. Ignore this bonding device."
	fi
done

LOG "Bonding cleanup finished. Please check the log, and reboot the system if no WARNING or ERROR found."

exit 0
