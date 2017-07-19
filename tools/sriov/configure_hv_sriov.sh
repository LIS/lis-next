#!/bin/bash

######################################################################## 
# 
# Linux on Hyper-V and Azure Test Code, ver. 1.0.0 
# Copyright (c) Microsoft Corporation 
# 
# All rights reserved.  
# Licensed under the Apache License, Version 2.0 (the ""License""); 
# you may not use this file except in compliance with the License. 
# You may obtain a copy of the License at 
#     http://www.apache.org/licenses/LICENSE-2.0   
# 
# THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS 
# OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION 
# ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR 
# PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT. 
# 
# See the Apache Version 2.0 License for specific language governing 
# permissions and limitations under the License. 
# 
######################################################################## 

######################################################################## 
#
# This is a script to configure SRIOV for Linux VMs on Azure.
# 
# How to use this:
#    $sudo ./configure_hv_sriov.sh
# Logging:
#    See log: "/var/log/configure_hv_sriov.log"
#
########################################################################

log_file="/var/log/configure_hv_sriov.log"

########################################
# Detect Distro
########################################
if [ -f /etc/redhat-release ];
then
    cfgdir="/etc/sysconfig/network-scripts"
    distro=redhat
elif grep -q 'Ubuntu' /etc/issue
then
    cfgdir="/etc/network"
    distro=ubuntu
elif grep -q 'SUSE' /etc/issue
then
    cfgdir="/etc/sysconfig/network"
    distro=suse
else
    echo "Unsupported Distro"
    exit 1
fi

function LOG() {
    echo "`date`: $1"
    echo "`date`: $1" >> $log_file
}

LOG "---------------------------------------"
LOG "Configure SRIOV for $distro"

########################################
# Write configuration for:
# vf, synthetic NIC, bond interfaces 
########################################
if [ $distro == 'ubuntu' ]; then
    default_net_config=$cfgdir/interfaces

    LOG "Running on Ubuntu: making change to ${default_net_config} ..."
    sed -i 's/^source/#source/' $default_net_config
    echo "allow-hotplug vf1"       >> $default_net_config
    echo "iface vf1 inet manual"   >> $default_net_config
    echo "bond-master bond0"       >> $default_net_config
    echo "bond-primary vf1"        >> $default_net_config
    echo ""                        >> $default_net_config
    echo "auto eth0"               >> $default_net_config
    echo "iface eth0 inet manual"  >> $default_net_config
    echo "bond-master bond0"       >> $default_net_config
    echo ""                        >> $default_net_config
    echo "auto bond0"              >> $default_net_config
    echo "iface bond0 inet dhcp"   >> $default_net_config
    echo "bond-mode active-backup" >> $default_net_config
    echo "bond-miimon 100"         >> $default_net_config
    echo "bond-slaves none"        >> $default_net_config

    n_line1=`cat $default_net_config | grep "allow-hotplug" | grep "vf1" | wc -l`
    if [ $n_line1 -ne 1 ]; then
        LOG "[Failed] allow-hotplug vf1: was defined multiple times in ${default_net_config}"
        exit
    fi

    n_line2=`cat $default_net_config | grep "auto" | grep "eth0" | wc -l`
    if [ $n_line2 -ne 1 ]; then
        LOG "[Failed] auto eth0: was defined multiple times in ${default_net_config}"
        exit
    fi
	
	n_line3=`cat $default_net_config | grep "auto" | grep "bond0" | wc -l`
    if [ $n_line3 -ne 1 ]; then
        LOG "[Failed] auto bond0: was defined multiple times in ${default_net_config}"
        exit
    fi
elif [ $distro == 'suse' ]; then
    ifcfg_bond0_cfg=$cfgdir/ifcfg-bond0
    ifcfg_eth0_cfg=$cfgdir/ifcfg-eth0
    ifcfg_eth0_old_cfg=$cfgdir/old.ifcfg-eth0.backup
    ifcfg_vf1_cfg=$cfgdir/ifcfg-vf1

    LOG "Running on Suse: making change to:"
    LOG "${ifcfg_bond0_cfg} ..."
	echo "BOOTPROTO=dhcp"       >  $ifcfg_bond0_cfg
	echo "STARTMODE=auto"       >> $ifcfg_bond0_cfg
	echo "BONDING_MASTER=yes"   >> $ifcfg_bond0_cfg
	echo "BONDING_SLAVE_0=vf1"  >> $ifcfg_bond0_cfg
	echo "BONDING_SLAVE_1=eth0" >> $ifcfg_bond0_cfg
	echo "BONDING_MODULE_OPTS='mode=active-backup miimon=100 primary=vf1'"  >> $ifcfg_bond0_cfg

    LOG "${ifcfg_eth0_cfg} ..."
	mv $ifcfg_eth0_cfg $ifcfg_eth0_old_cfg
	echo "BOOTPROTO=none"       >  $ifcfg_eth0_cfg
	echo "STARTMODE=auto"       >> $ifcfg_eth0_cfg
	
    LOG "${ifcfg_vf1_cfg} ..."
	echo "BOOTPROTO=none"       >  $ifcfg_vf1_cfg
	echo "STARTMODE=hotplug"    >> $ifcfg_vf1_cfg
else
    echo "Unsupported distro. Exiting."
    exit 1
fi

########################################
# Download files
########################################
bin_folder="/usr/sbin/"
udev_folder="/etc/udev/rules.d/"
udev_file="60-hyperv-vf-name.rules"
hv_vf_name_file="hv_vf_name"
bondvf_sh_file="bondvf.sh"
all_files_downloaded=true

LOG "Start downloading udev rule and config scripts ..."
cd /tmp
wget "https://raw.githubusercontent.com/LIS/lis-next/master/tools/sriov/${udev_file}"
wget "https://raw.githubusercontent.com/LIS/lis-next/master/tools/sriov/${hv_vf_name_file}"
wget "https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/plain/tools/hv/${bondvf_sh_file}"

LOG "Move configuration to the destination folder ..."
mv -f $udev_file $udev_folder
chmod +x $hv_vf_name_file $bondvf_sh_file
mv -f $hv_vf_name_file  $bin_folder
mv -f $bondvf_sh_file   $bin_folder

########################################
# Check downloaded files
########################################
LOG "Check downloaded files ..."
if [ ! -f ${udev_folder}${udev_file} ]; then
    all_files_downloaded=false
    LOG "${udev_file} is not found in ${udev_folder}!"
fi

if [ ! -f ${bin_folder}${hv_vf_name_file} ]; then
    all_files_downloaded=false
    LOG "${hv_vf_name_file} is not found in ${bin_folder}!"
fi

if [ ! -f ${bin_folder}${bondvf_sh_file} ]; then
    all_files_downloaded=false
    LOG "${bondvf_sh_file} is not found in ${bin_folder}!"
fi

if [ $all_files_downloaded == false ]; then
    LOG "[Failed] Some files are missing; please download them again."
    exit
else
    LOG "This system will reboot within 60 seconds ..."
    sleep 60
    LOG "Rebooting now."
    reboot
fi

