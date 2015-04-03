#!/bin/bash

#####################################################################
#
# Install LIS 4.0 by performing the following tasks
#   - Verfiy we are running on a RHEL or CentOS distribution.
#     Note: for the preview release only CentOS is supported.
#   - Determine the version of the distribution we are running on.
#   - cd to the apporpriate subdirectory for the version.
#   - Remove the Hyper-V daemons if they are installed.
#   - Invoke the version specific install.sh script.
#
# Kernel version
#  7.1    3.10.0-229
#  7.0    3.10.0-123
#  6.6    2.6.32-504
#  6.5    2.6.32-431
#  6.4    2.6.32-358
#  6.3    2.6.32-279
#  6.2    2.6.32-220
#  6.1    2.6.32-131.0.15
#  6.0    2.6.32-71
#  5.11   2.6.18-398
#  5.10   2.6.18-371
#  5.9    2.6.18-348
#  5.8    2.6.18-308
#  5.7    2.6.18-274
#  5.6    2.6.18-238
#  5.5    2.6.18-194
#
#  Other releases are not supported.
#
#####################################################################

architecture=`uname -m`

distro_name="unknown"
distro_version="unknown"

GetDistroName()
{
	linuxString=$(grep -ihs "CentOS\|Red Hat Enterprise Linux" /etc/redhat-release)

	case $linuxString in
		*CentOS*)
			distro_name=CentOs
			;;
		*Red*)
			distro_name=RHEL
			;;
		*)
			distro_name=unknown
			return 1
			;;
	esac

	return 0
}


GetDistroVersion()
{
	kernelVersion=$(uname -r)
	regex='[0-9]+\.[0-9]+\.[0-9]+-[0-9]+'

	if [[ "$kernelVersion" =~ $regex  ]]; then
		case ${BASH_REMATCH} in
		'2.6.18-194')
			linuxVersion='55'
			;;
		'2.6.18-238')
			linuxVersion='56'
			;;
		'2.6.18-274')
			distro_version='57'
			;;
		'2.6.18-308')
			distro_version='58'
			;;
		'2.6.18-348')
			distro_version='59'
			;;
		'2.6.18-371')
			distro_version='510'
			;;
		'2.6.18-398')
			distro_version='511'
			;;
		'2.6.32-71')
			distro_version='60'
			;;
		'2.6.32-131')
			distro_version='61'
			;;
		'2.6.32-220')
			distro_version='62'
			;;
		'2.6.32-279')
			distro_version='63'
			;;
		'2.6.32-358')
			distro_version='64'
			;;
		'2.6.32-431')
			distro_version='65'
			;;
		'2.6.32-504')
			distro_version='66'
			;;
		'3.10.0-123')
			distro_version='70'
			;;
		'3.10.0-123')
			distro_version='71'
			;;
		*)
			distro_version="unknown"
			return 1
			;;
		esac
	fi
}

RemoveHypervDaemons()
{
	echo "Removing Hyper-V daemons"

	#
	# Try remove hyperv-daemons
	#
	rpm -q hyperv-daemons &> /dev/null
	if [ $? -eq 0 ]; then
		echo "Removing the hyperv-daemons package"
		rpm -e hyperv-daemons &> /dev/null
		if [ $? -ne 0 ]; then
			echo "Unable to remove the hyperv-daemons package"
			echo "Remove the daemon with the command 'rpm -e hyperv-daemons' and try the install again"
			exit 1
		fi
	fi

	#
	# Try removing hypervkvpd
	#
	rpm -q hypervkvpd &> /dev/null
	if [ $? -eq 0 ]; then
		echo "Removing the hypervkvpd package"
		rpm -e hypervkvpd &> /dev/null
		if [ $? -ne 0 ]; then
			echo "Unable to remove the hypervkvpd package"
			echo "Remove the daemon with the command 'rpm -e hypervkvpd' and try the install again"
			exit 1
		fi
	fi

	#
	# Try removing the hypervvssd package
	#
	rpm -q hypervvssd &> /dev/null
	if [ $? -eq 0 ]; then
		echo "Removing the hypervvssd package"
		rpm -e hypervvssd &> /dev/null
		if [ $? -ne 0 ]; then
			echo "Unable to remove the hypervvssd package"
			echo "Remove the daemon with the command 'rpm -e hypervvssd' and try the install again"
			exit 1
		fi
	fi
}


#
# Main script body
#
GetDistroName
if [ $distro_name = "unknown" ]; then
    echo "Unable to determine the Linux distribution"
    exit 1
fi

GetDistroVersion
if [ $distro_version = "unknown" ]; then
    echo "Unable to determine the kernel version"
    exit 1
fi

targetDir="${distro_name}${distro_version}"

if [ ! -e "./${targetDir}" ]; then
	echo "The distribution specific directory '${targetDir}' does not exist"
	exit 1
fi

cd ${targetDir}

#
# If the daemons are left installed, the new rpms will fail to install
#
RemoveHypervDaemons

#
# Invoke the release specific install script
#
echo "Invoking release specific install file in directory ${targetDir}"
./install.sh

exit 0

