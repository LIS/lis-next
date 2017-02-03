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
#  7.3    3.10.0-514
#  7.2    3.10.0-327
#  7.1    3.10.0-229
#  7.0    3.10.0-123
#  6.8    2.6.32-642
#  6.7    2.6.32-573
#  6.6    2.6.32-504
#  6.5    2.6.32-431
#  6.4    2.6.32-358
#  6.3    2.6.32-279
#  6.2    2.6.32-220
#  6.1    2.6.32-131.0.15
#  6.0    2.6.32-71
#  5.11   2.6.18-398
#  5.11.1   2.6.18-408
#  5.10   2.6.18-371
#  5.9    2.6.18-348
#  5.8    2.6.18-308
#  5.7    2.6.18-274
#  5.6    2.6.18-238
#  5.5    2.6.18-194
#  5.4    2.6.18-164
#  5.3    2.6.18-128
#  5.2    2.6.18-92
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
			distro_name=CentOS
			;;
		*Red*)
			distro_name=RHEL
			;;
		*Oracle*)
                        distro_name=Oracle
                        ;;

		*)
			distro_name=unknown
			return 1
			;;
	esac

	return 0
}


#
# The grouping of the regular expression using () will
# result in the following BASH_REMATCH matches:
#    BASE_REMATCH[0] = 2.6.18-398
#    BASE_REMATCH[1] = 2.6.18
#    BASE_REMATCH[2] = 398
#
GetDistroVersion()
{
	kernelVersionString=$(uname -r)
	regex='([0-9]+\.[0-9]+\.[0-9]+)-([0-9]+)'

	if [[ "${kernelVersionString}" =~ $regex  ]]; then
		kernelVersion=${BASH_REMATCH[1]}
		kernelChange=${BASH_REMATCH[2]}

		#
		# If a 5.x kernel
		#
		if [ "2.6.18" == ${kernelVersion} ]; then
			if [ ${kernelChange} -ge 412 ]; then
                                distro_version='unknown'
			elif [ ${kernelChange} -ge 411 ]; then
				distro_version='511_UPDATE'
			elif [ ${kernelChange} -ge 398 ]; then
				distro_version='511'
			elif [ ${kernelChange} -ge 371 ]; then
				distro_version='510'
			elif [ ${kernelChange} -ge 348 ]; then
				distro_version='59'
			elif [ ${kernelChange} -ge 308 ]; then
				distro_version='58'
			elif [ ${kernelChange} -ge 274 ]; then
				distro_version='57'
			elif [ ${kernelChange} -ge 238 ]; then
				distro_version='56'
			elif [ ${kernelChange} -ge 194 ]; then
				distro_version='55'
			elif [ ${kernelChange} -ge 164 ]; then
				distro_version='54'
			elif [ ${kernelChange} -ge 128 ]; then
				distro_version='53'
			elif [ ${kernelChange} -ge 92 ]; then
				distro_version='52'
			else
				echo "Error: Unknown 5.x kernel change: '${kernelChange}'"
				return 1
			fi
		#
		# If a 6.x kernel
		#
		elif [ "2.6.32" == ${kernelVersion} ]; then
			if [ ${kernelChange} -ge 643 ]; then
                                distro_version='unknown'
			elif [ ${kernelChange} -ge 642 ]; then
				distro_version='68'
			elif [ ${kernelChange} -ge 573 ]; then
				distro_version='67'
			elif [ ${kernelChange} -ge 504 ]; then
				distro_version='66'
			elif [ ${kernelChange} -ge 431 ]; then
				distro_version='65'
			elif [ ${kernelChange} -ge 358 ]; then
				distro_version='64'
			elif [ ${kernelChange} -ge 279 ]; then
				distro_version='63'
			elif [ ${kernelChange} -ge 220 ]; then
				distro_version='62'
			elif [ ${kernelChange} -ge 131 ]; then
				distro_version='61'
			elif [ ${kernelChange} -ge 71 ]; then
				distro_version='60'
			else
				echo "Error: Unknown 6.x kernel change:  '${kernelChange}'"
				return 1
			fi
		#
		# If a 7.x kernel
		#
		elif [ "3.10.0" == ${kernelVersion} ]; then
			if [ ${kernelChange} -ge 515 ]; then
                                distro_version='unknown'
			elif [ ${kernelChange} -ge 514 ]; then
				distro_version='73'
			elif [ ${kernelChange} -ge 324 ]; then
				distro_version='72'
			elif [ ${kernelChange} -ge 229 ]; then
				distro_version='71'
			elif [ ${kernelChange} -ge 123 ]; then
                                distro_version='70'
			else
				echo "Error: Unknown 7.x kernel change: '${kernelChange}'"
				return 1
			fi
		else
			# Not a 2.6.18, 2.6.32, or 3.10.0 kernel - unsupported kernel version
			echo "Error: Unknown kernel version: '${kernelVersion}'"
			return 1
		fi
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

        # Try removing the hypervfcopy package
        #
        rpm -q hypervfcopyd &> /dev/null
        if [ $? -eq 0 ]; then
                echo "Removing the hypervfcopyd package"
                rpm -e hypervfcopyd  &> /dev/null
                if [ $? -ne 0 ]; then
                        echo "Unable to remove the hypervfcopyd package"
                        echo "Remove the daemon with the command 'rpm -e hypervfcopyd and try the install again"
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

	#
        # Try remove hyperv-daemons-license
        #
        rpm -q hyperv-daemons-license &> /dev/null
        if [ $? -eq 0 ]; then
                echo "Removing the hyperv-daemons-license package"
                rpm -e hyperv-daemons-license &> /dev/null
                if [ $? -ne 0 ]; then
                        echo "Unable to remove the hyperv-daemons-license package"
                        echo "Remove the package with the command 'rpm -e hyperv-daemons-license' and try the install again"
                        exit 1
                fi
        fi


}


#
# Main script body
#
# Check if kernel version running is higher compared to installed kernel.
# This is important because kmod are dependent on Kernel version

GetDistroName
if [ $distro_name = "unknown" ]; then
    echo "Unsupported Linux distribution"
    exit 1
fi

GetDistroVersion
if [ $distro_version = "unknown" ]; then
    echo "Unsupported kernel version"
    exit 1
fi

if [[ $distro_version != "5"* ]]; then
 latestkernel=(`rpm -q kernel | tail -n1 | cut -c 8-`)
 runningkernel=(`uname -r`)
 if [ ${latestkernel} != ${runningkernel} ] ; then
   echo "your running kernel ${runningkernel} is not your latest installed kernel, aborting installation"
   exit 1
 fi
fi

targetDir="${distro_name}${distro_version}"

if [ ! -e "./${targetDir}" ]; then
	echo "The distribution specific directory '${targetDir}' does not exist"
	exit 1
fi

if [[ $distro_version == "7"* ]]; then
 if [ -e /etc/modprobe.d/hyperv_pvdrivers.conf ]; then
  mv /etc/modprobe.d/hyperv_pvdrivers.conf /opt/files/
 fi
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

exit $? 

