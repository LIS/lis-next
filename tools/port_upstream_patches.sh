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
# This is a script to help port LIS driver patches from upstream (e.g.
# linux-next, net-next) into the LIS-Next repository.
# 
# How to use this:
# 1) Place the set of patches (e.g. from kernel.org) to a directory and 
# name them in some order (01.patch, 02.patch, etc…)
# 
# 2) Run 'cd ~/lis-next/hv-rhel7.x/hv'
#    You can change to whichever target OS you are working on.
#
# 3) Run 'port_usptream_patches.sh <directory containing patches>'
#
########################################################################



PATCHDIR=$1
RHELVERSION=$2
#DEPTH=$3

result=0

if [ -z $RHELVERSION ]; then
	RHELVERSION=$(pwd | grep -oP '(?<=hv-rhel)[0-9]+')
fi

if [ -z $PATCHDIR ]; then
	echo "Usage: port_upstream_patches <Patch Directory>"
	exit 1
fi

echo "=== Porting to RHEL Version $RHELVERSION"

for patchfile in ${PATCHDIR}/*.patch; do
	commit_desc=$(grep Subject $patchfile -m1 | cut -d ":" -f2-)
	commit_id=$(grep From $patchfile -m1 | cut -d " " -f2)

	echo "=== Working on $patchfile..."
	echo "=== Title: $commit_desc"
	echo "=== ID: $commit_id"

	echo "Normalizing the paths in the patch..."
	sed -i 's/--- a\/drivers\/hv/--- a/g' $patchfile
	sed -i 's/+++ b\/drivers\/hv/+++ b/g' $patchfile
	sed -i 's/--- a\/drivers\/scsi/--- a/g' $patchfile
	sed -i 's/+++ b\/drivers\/scsi/+++ b/g' $patchfile
	sed -i 's/--- a\/tools\/hv\//--- a\/tools\//g' $patchfile
	sed -i 's/+++ b\/tools\/hv\//+++ b\/tools\//g' $patchfile
	sed -i 's/--- a\/drivers\/net\/hyperv/ --- a/g' $patchfile
	sed -i 's/+++ b\/drivers\/net\/hyperv/ +++ b/g' $patchfile
	sed -i 's/--- a\/arch\/x86\/include\/asm/ --- a\/arch\/x86\/include\/lis\/asm/g' $patchfile
	sed -i 's/+++ b\/arch\/x86\/include\/asm/ +++ b\/arch\/x86\/include\/lis\/asm/g' $patchfile
	sed -i 's/--- a\/arch\/x86\/include\/uapi\/asm/ --- a\/arch\/x86\/include\/uapi\/lis\/asm/g' $patchfile
	sed -i 's/+++ b\/arch\/x86\/include\/uapi\/asm/ +++ b\/arch\/x86\/include\/uapi\/lis\/asm/g' $patchfile
	sed -i 's/--- a\/drivers\/pci\/host/--- a/g' $patchfile
	sed -i 's/+++ b\/drivers\/pci\/host/+++ b/g' $patchfile

	echo "Applying patch in DRY RUN..."
	#depth=$DEPTH
	#if [ -z $DEPTH ]; then	
	#	depth=$(grep "\-\-\- a" $patchfile -m1 | grep -o "\/" | wc -l)
	#fi

	echo "patch --dry-run --ignore-whitespace -p1 -F1 -f < $patchfile"
	patch --dry-run --ignore-whitespace -p1 -F1 -f < $patchfile
	result=$?
	if [ $result -ne 0 ]; then
		echo "Failed to apply patch in dry run. Please manually port it."
		break
	fi

	echo "Applying patch for real this time..."
	patch --ignore-whitespace -p1 -F1 -f < $patchfile
	result=$?
	if [ $result -ne 0 ]; then
		echo "Failed to apply patch. Please manually port it."
		break
	fi

	echo "Building LIS drivers..."
	make -C /lib/modules/$(uname -r)/build M=`pwd` clean
	make -C /lib/modules/$(uname -r)/build M=`pwd` modules
	result=$?
	if [ $result -ne 0 ]; then
		echo "Failed to build LIS drivers."
		break
	fi

	echo "Building LIS daemons..."
	make -C ./tools clean
	make -C ./tools
	result=$?
	if [ $result -ne 0 ]; then
		echo "Failed to build LIS daemons."
		break
	fi

	echo "Committing ported patch..."
	make -C ./tools clean
	make -C /lib/modules/$(uname -r)/build M=`pwd` clean
	git add -u .
	git add ./\*.c
	git add ./\*.h
	git commit -m "RH${RHELVERSION}:$commit_desc <upstream:$commit_id>"
	result=$?
	if [ $result -ne 0 ]; then
		echo "Failed to commit patch."
		break
	fi

	echo "Marking patch as ported..."
	mv $patchfile ${patchfile}.done
done

exit $result
