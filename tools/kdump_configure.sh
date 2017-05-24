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
#.Synopsis
#    Configured Kdump on Linux VMs running on Hyper-V.
#
#.Description
#    
#    Test parameters
#
#.Parameter  host_version
#    Version of the Hyper-V server hosting the VM.
#
########################################################################


#######################################################################
#
# ResetLogFiles()
#
#######################################################################
ResetLogFiles()
{
    echo "" > ~/kdump_config.log
    echo "" > ~/summary.log
}

#######################################################################
#
# LogMsg()
#
#######################################################################
LogMsg()
{
    echo `date "+%b %d %Y %T"` : "${1}"    # Add the time stamp to the log message
    echo "${1}" >> ~/kdump_config.log
}

#######################################################################
#
# UpdateSummary()
#
#######################################################################
UpdateSummary()
{
    echo "${1}" >> ~/summary.log
    if [ $1 == "ABORTED" ]; then
        exit -1
    fi
}
#######################################################################
#
# get_host_version()
#
#######################################################################
function get_host_version ()
{
    if [ x$1 == "x" ]; then
        Server_version=`dmesg | grep "Host Build" | sed "s/.*Host Build://"|sed "s/^.*-\([0-9]*\.[0-9]*\)-.*/\1 /"`
    else
        Server_version=$1
    fi
    
    if [ x$Server_version != "x" ]; then
        if [ $Server_version == "6.2" ];then
            echo "WS2012"
        elif [ $Server_version == "6.3" ];then
            echo "WS2012R2"
        elif [ $Server_version == "10.0" ];then
            echo "WS2016"
        else
            echo "Unknown host OS version: $Server_version"
        fi
    else
        LogMsg "Unable to ditect hostOS version :|"
    fi
}
#######################################################################
#
# check_exit_status()
#
#######################################################################
function check_exit_status ()
{
    exit_status=$?
    message=$1

    if [ $exit_status -ne 0 ]; then
        LogMsg "$message : Failed (exit code: $exit_status)" 
        if [ "$2" == "exit" ]
        then
            UpdateSummary "ABORTED"
            exit $exit_status
        fi 
    else
        LogMsg "$message : Success"
    fi
}
#######################################################################
#
# detect_linux_ditribution_version()
#
#######################################################################
function detect_linux_ditribution_version()
{
    local  distro_version="Unknown"
    if [ `which lsb_release 2>/dev/null` ]; then
        distro_version=`lsb_release -a  2>/dev/null | grep Release| sed "s/.*:\s*//"`
    else
        local temp_text=`cat /etc/*release*`
        distro_version=`cat /etc/*release*| grep release| sed "s/^.*release \([0-9]*\)\.\([0-9]*\).*(.*/\1\.\2/" | head -1`
    fi

    echo $distro_version
}
#######################################################################
#
# detect_distribution()
#
#######################################################################
function detect_distribution()
{
    linux_ditribution_type='UNKNOWN'
    if [ `which lsb_release 2>/dev/null` ]; then
        if [ `lsb_release -a 2>/dev/null| grep "Distributor ID:"| grep -i Ubuntu | wc -l` -eq 1 ]; then
            linux_ditribution_type="Ubuntu"
        elif [ `lsb_release -a 2>/dev/null| grep "Distributor ID:"| grep -i redhat | wc -l` -eq 1 ]; then
            linux_ditribution_type="RHEL"
        elif [ `lsb_release -a 2>/dev/null| grep "Distributor ID:"| grep -i CentOS | wc -l` -eq 1 ]; then
            linux_ditribution_type="CentOS"
        fi
    else
        local temp_text=`cat /etc/*release*|grep "^ID="`

        if echo "$temp_text" | grep -qi "ol"; then
            linux_ditribution_type='Oracle'
        elif echo "$temp_text" | grep -qi "Ubuntu"; then
            linux_ditribution_type='Ubuntu'
        elif echo "$temp_text" | grep -qi "SUSE"; then
            linux_ditribution_type='SUSE'
        elif echo "$temp_text" | grep -qi "openSUSE"; then
            linux_ditribution_type='OpenSUSE'
        elif [ `echo "$temp_text" | grep -i "centos"|wc -l` -gt 0 ] ; then
            linux_ditribution_type='CentOS'
        elif echo "$temp_text" | grep -qi "Oracle"; then
            linux_ditribution_type='Oracle'
        elif echo "$temp_text" | grep -qi "Red.Hat"; then
            linux_ditribution_type='RHEL'
        else
            linux_ditribution_type='unknown'
        fi
    fi
    
    echo $linux_ditribution_type
}
#######################################################################
#
# updaterepos()
#
#######################################################################
function updaterepos()
{
   if [ `which yum 2>/dev/null` ]; then
        yum makecache
    elif [ `which apt-get 2>/dev/null` ]; then
        apt-get update
    elif [ `which zypper 2>/dev/null` ]; then
        zypper refresh
    fi
}
#######################################################################
#
# install_rpm()
#
#######################################################################
function install_rpm ()
{
    package_name=$1
    rpm -ivh $package_name
    check_exit_status "install_rpm $package_name"
}
#######################################################################
#
# install_deb()
#
#######################################################################
function install_deb ()
{
    package_name=$1
    dpkg -i  $package_name
    apt-get install -f
    check_exit_status "install_deb $package_name"
}
#######################################################################
#
# apt_get_install()
#
#######################################################################
function apt_get_install ()
{
    package_name=$1
    DEBIAN_FRONTEND=noninteractive apt-get install -y  --force-yes $package_name
    check_exit_status "apt_get_install $package_name"
}
#######################################################################
#
# yum_install()
#
#######################################################################
function yum_install ()
{
    package_name=$1
    yum install -y $package_name
    check_exit_status "yum_install $package_name"
}
#######################################################################
#
# zypper_install()
#
#######################################################################
function zypper_install ()
{
    package_name=$1
    zypper --non-interactive in $package_name
    check_exit_status "zypper_install $package_name"
}
#######################################################################
#
# install_package()
#
#######################################################################
function install_package ()
{
    local package_name=$@

    if [ `which yum` ]; then
        yum_install "$package_name"
    elif [ `which apt-get` ]; then
        apt_get_install "$package_name"
    elif [ `which zypper` ]; then
        zypper_install "$package_name"
    fi
}
#######################################################################
#
# config_kdump_RHEL()
#
#######################################################################
function config_kdump_RHEL
{
    local distro_version=`detect_linux_ditribution_version`
    
    LogMsg "Configuring Kdump on RHEL $distro_version"
    if [ x$host_version == "x" ]; then
        $host_version=`dmesg | grep "Host Build" | sed "s/.*Host Build://"|sed "s/^.*-\([0-9]*\.[0-9]*\)-.*/\1 /"`
        if [ x$host_version == "x" ]; then
            LogMsg "Unable to find Host version"
            UpdateSummary "ABORTED"
        fi
    fi
    LogMsg "Installing required packages"
    install_package "kexec-tool crash"
    if [ $distro_version == "6.0" ] || [ $distro_version == "6.3" ] || [ $distro_version == "6.4" || [ $distro_version == "6.5" ] ; then
        if [ $host_version == "6.2" ]; then
            LogMsg "Configuring Kdump for `detect_distribution`-$distro_version VM running on `get_host_version $host_version`"
            sed -i "s/\(^default.*\)/#\1/" /etc/kdump.conf
            LogMsg "/etc/kdump.conf 'default' action is commented to boot from 'initrd-...kdump.img'."

            if [ `cat /etc/kdump.conf | grep -v "#"| grep "path /var/crash" | wc -l` == 0 ]; then
                echo "path /var/crash" >> /boot/grub/grub.conf
                LogMsg "Configured '/etc/kdump.conf' with 'path /var/crash'"
            else
                LogMsg "'/etc/kdump.conf' already configured with 'path /var/crash' skipping ..."
            fi

            sed -i "s/\(^core_collector.*\)/#\1/" /etc/kdump.conf
            if [ `cat /etc/kdump.conf | grep -v "#"| grep "core_collector makedumpfile -c --message-level 1 -d 31" | wc -l` == 0 ]; then
                echo "core_collector makedumpfile -c --message-level 1 -d 31" >> /etc/kdump.conf
                LogMsg "Configured '/etc/kdump.conf' with 'core_collector makedumpfile -c --message-level 1 -d 31'"
            else
                LogMsg "'/etc/kdump.conf' already configured with 'core_collector makedumpfile -c --message-level 1 -d 31' skipping ..."
            fi

            if [ `cat /etc/kdump.conf | grep -v "#"| grep "blacklist hv_vmbus hv_storvsc hv_utils hv_netvsc hid-hyperv" | wc -l` == 0 ]; then
                echo "blacklist hv_vmbus hv_storvsc hv_utils hv_netvsc hid-hyperv" >> /etc/kdump.conf
                LogMsg "Configured '/etc/kdump.conf' with 'blacklist hv_vmbus hv_storvsc hv_utils hv_netvsc hid-hyperv'"
            else
                LogMsg "'/etc/kdump.conf' already configured with 'blacklist hv_vmbus hv_storvsc hv_utils hv_netvsc hid-hyperv' skipping ..."
            fi

            sed -i "s/\(^disk_timeout.*\)/#\1/" /etc/kdump.conf
            if [ `cat /etc/kdump.conf | grep -v "#"| grep "disk_timeout 100" | wc -l` == 0 ]; then
                echo "disk_timeout 100" >> /etc/kdump.conf
                LogMsg "Configured '/etc/kdump.conf' with 'disk_timeout 100'"
            else
                LogMsg "'/etc/kdump.conf' already configured with 'disk_timeout 100' skipping ..."
            fi

            if [ $distro_version == "6.0" ] || [ $distro_version == "6.3" ] ; then
                sed -i "s/\(^KDUMP_COMMANDLINE_APPEND.*\)/#\1/" /etc/sysconfig/kdump
                if [ `cat /etc/sysconfig/kdump | grep -v "#"| grep "KDUMP_COMMANDLINE_APPEND" | wc -l` == 0 ]; then
                    echo 'KDUMP_COMMANDLINE_APPEND="irqpoll maxcpus=1 reset_devices ide_core.prefer_ms_hyperv=0"' >> /etc/sysconfig/kdump
                    LogMsg "Configured '/etc/sysconfig/kdump' with 'KDUMP_COMMANDLINE_APPEND=irqpoll maxcpus=1 reset_devices ide_core.prefer_ms_hyperv=0'"
                else
                    LogMsg "'/etc/sysconfig/kdump' already configured with 'KDUMP_COMMANDLINE_APPEND=irqpoll maxcpus=1 reset_devices ide_core.prefer_ms_hyperv=0' skipping ..."
                fi
            fi

            if [ $distro_version == "6.4" || [ $distro_version == "6.5" ] ; then
                sed -i "s/\(^extra_modules.*\)/#\1/" /etc/kdump.conf
                if [ `cat /etc/kdump.conf | grep -v "#"| grep "extra_modules ata_piix sr_mod sd_mod" | wc -l` == 0 ]; then
                    echo "extra_modules ata_piix sr_mod sd_mod" >> /etc/kdump.conf
                    LogMsg "Configured '/etc/kdump.conf' with 'extra_modules ata_piix sr_mod sd_mod'"
                else
                    LogMsg "'/etc/kdump.conf' already configured with 'extra_modules ata_piix sr_mod sd_mod' skipping ..."
                fi

                sed -i "s/\(^options.*\)/#\1/" /etc/kdump.conf
                if [ `cat /etc/kdump.conf | grep -v "#"| grep "options ata_piix prefer_ms_hyperv=0" | wc -l` == 0 ]; then
                    echo "options ata_piix prefer_ms_hyperv=0" >> /etc/kdump.conf
                    LogMsg "Configured '/etc/kdump.conf' with 'options ata_piix prefer_ms_hyperv=0'"
                else
                    LogMsg "'/etc/kdump.conf' already configured with 'options ata_piix prefer_ms_hyperv=0' skipping ..."
                fi
            fi

            sed -i "s/crashkernel=auto//" /boot/grub/grub.conf
            if [ `cat /boot/grub/grub.conf | grep -v "#"| grep kernel.*root=| grep "crashkernel=384M" | wc -l` == 0 ]; then
                sed -i "s/\(kernel.*root.*\)/\1 crashkernel=384M/" /boot/grub/grub.conf
                LogMsg "Configured '/boot/grub/grub.conf' with 'crashkernel=384M'"                
            else
                LogMsg "'/boot/grub/grub.conf' already configured with 'crashkernel=384M' skipping grub configuration..."
            fi
        else
            LogMsg "Unsupported Host version $host_version"
            UpdateSummary "ABORTED"
        fi
    else
        LogMsg "Unsupported OS version $distro_version"
        UpdateSummary "ABORTED"
    fi
    LogMsg "Kdump configuration is completed. Please reboot VM to apply the changes."
    echo "KDUMP_CONFIGURED"
}
#######################################################################
#
# config_kdump_Ubuntu()
#
#######################################################################
config_kdump_Ubuntu()
{
    local distro_version=`detect_linux_ditribution_version`
    LogMsg "Unsupported OS version $distro_version"
    UpdateSummary "ABORTED"
}
#######################################################################
#
# config_kdump_CentOS()
#
#######################################################################
config_kdump_CentOS()
{
    local distro_version=`detect_linux_ditribution_version`
    LogMsg "Unsupported OS version $distro_version"
    UpdateSummary "ABORTED"
}

#######################################################################
#
# Execution starts from here
#
#######################################################################
host_version=$1
ResetLogFiles

if [ x$host_version == "x" ]; then
    echo "Usage: 'bash $0 <host version>"
    echo "Example:
    bash $0 6.2 #for Windows Server 2012 host
    bash $0 6.3 #for Windows Server 2012 R2 host
    bash $0 10.0 #for Windows Server 2016 host"
    UpdateSummary "ABORTED"
fi

linux_ditribution_type=`detect_distribution`

if [ `detect_distribution` == "Ubuntu" ]; then
    result=`config_kdump_Ubuntu`
elif [ `detect_distribution` == "RHEL" ]; then
    result=`config_kdump_RHEL`
elif [ `detect_distribution` == "CentOS" ]; then
    result=`config_kdump_CentOS`
fi

if echo $result | grep "KDUMP_CONFIGURED" ; then
    UpdateSummary "KDUMP_CONFIGURED"
else
    UpdateSummary "KDUMP_CONFIG_FAILED"    
fi
