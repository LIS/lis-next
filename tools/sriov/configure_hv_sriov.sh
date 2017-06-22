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
# This is a script to configure SRIOV for Ubuntu 1604 VM on Azure.
# 
# How to use this:
#    $sudo ./configure_sriov_ubuntu1604.sh
# Logging:
#    See log: "/var/log/configure_sriov_ubuntu1604.log"
#
########################################################################

log_file="/var/log/configure_sriov_ubuntu1604.log"
bin_folder="/usr/sbin/"
udev_folder="/etc/udev/rules.d/"
udev_file="60-hyperv-sriov.rules"
hv_vf_name_file="hv_vf_name"
bondvf_lock_file="bondvf_lock"
bondvf_sh_file="bondvf.sh"
default_net_config="/etc/network/interfaces"
eth0_dhcp_config_line1="auto eth0"
eth0_dhcp_config_line2="iface eth0 inet dhcp"
all_files_downloaded=true


function LOG() {
    echo "`date`: $1"
    echo "`date`: $1" >> $log_file
}

LOG "---------------------------------------"

########################################
# Download files
########################################
LOG "Start downloading configuration files ..."
cd /tmp
wget "https://raw.githubusercontent.com/LIS/lis-next/master/tools/sriov/60-hyperv-sriov.rules"
wget "https://raw.githubusercontent.com/LIS/lis-next/master/tools/sriov/hv_vf_name"
wget "https://raw.githubusercontent.com/LIS/lis-next/master/tools/sriov/bondvf_lock"
wget "https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/plain/tools/hv/bondvf.sh"

LOG "Move configuration to the destination folder ..."
mv -f $udev_file $udev_folder
chmod +x $hv_vf_name_file $bondvf_lock_file $bondvf_sh_file
mv -f $hv_vf_name_file  $bin_folder
mv -f $bondvf_lock_file $bin_folder
mv -f $bondvf_sh_file   $bin_folder

if [ ! -f ${udev_folder}${udev_file} ]; then
    all_files_downloaded=false
    LOG "${udev_file} is not found in ${udev_folder}!"
fi

if [ ! -f ${bin_folder}${hv_vf_name_file} ]; then
    all_files_downloaded=false
    LOG "${hv_vf_name_file} is not found in ${bin_folder}!"
fi
	
if [ ! -f ${bin_folder}${bondvf_lock_file} ]; then
    all_files_downloaded=false
    LOG "${bondvf_lock_file} is not found in ${bin_folder}!"
fi

if [ ! -f ${bin_folder}${bondvf_sh_file} ]; then
    all_files_downloaded=false
    LOG "${bondvf_sh_file} is not found in ${bin_folder}!"
fi

########################################
# Change eth0 DHCP configuration
########################################
LOG "Make change to the eth0 DHCP configuration ..."
sed -i 's/^source/#source/' $default_net_config
echo "$eth0_dhcp_config_line1" >> $default_net_config
echo "$eth0_dhcp_config_line2" >> $default_net_config

LOG "Check files ..."
n_line1=`cat $default_net_config | grep "$eth0_dhcp_config_line1" | wc -l`
if [ $n_line1 -ne 1 ]; then
    LOG "[Failed] $n_line1 line(s) of '${eth0_dhcp_config_line1}' in $default_net_config"
    exit
fi

n_line2=`cat $default_net_config | grep "$eth0_dhcp_config_line2" | wc -l`
if [ $n_line2 -ne 1 ]; then
    LOG "[Failed] $n_line2 line(s) of '${eth0_dhcp_config_line2}' in $default_net_config"
    exit
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

