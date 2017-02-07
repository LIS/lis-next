#!/bin/bash

#####################################################################
# Script to Uninstall LIS RPM's.
####################################################################

lisarr=($(rpm -qa | grep microsoft-hyper-v))

#Making sure LIS RPM's are present
if [ ${#lisarr[@]} -gt 0 ]; then
	echo "Uninstalling the Linux Integration Services for Microsoft Hyper-V..."
 	rpm -e ${lisarr[@]}		
	exit=$?
        if [ $exit -eq 0 ]; then
	      echo "Uninstalled Linux Integration Services for Microsoft Hyper-V..."
	else
              echo "Uninstallation of Linux Integration Services for Microsoft Hyper-V failed , Exiting"
              exit 1
       fi
else 
	echo "No LIS RPM's are present"

fi

