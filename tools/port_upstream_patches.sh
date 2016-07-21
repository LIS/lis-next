#!/bin/bash

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
	sed -i 's/--- a\/tools\/hv/--- a\/tools/g' $patchfile
	sed -i 's/+++ b\/tools\/hv/+++ b\/tools/g' $patchfile
	sed -i 's/--- a\/drivers\/net/hyperv/ --- a/g' $patchfile
	sed -i 's/+++ b\/drivers\/net/hyperv/ +++ b/g' $patchfile

	echo "Applying patch..."
	#depth=$DEPTH
	#if [ -z $DEPTH ]; then	
	#	depth=$(grep "\-\-\- a" $patchfile -m1 | grep -o "\/" | wc -l)
	#fi

	patch --dry-run --ignore-whitespace -p1 -f < $patchfile
	result=$?
	if [ $result -ne 0 ]; then
		echo "Failed to apply patch in dry run. Please manually port it."
		break
	fi

	patch --ignore-whitespace -p1 -f < $patchfile
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
