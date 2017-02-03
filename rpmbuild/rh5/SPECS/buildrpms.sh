#!/bin/bash

# This scripts neeeds to be run in /{user}/rpmbuild/SPECS

cd /$HOME/rpmbuild/SPECS

Runbuild()
{
        rm -vrf /root/rpmbuild/RPMS/*
        rm -vrf /root/rpmbuild/SPECS/SRPMS/*
#        rpmbuild --clean /root/rpmbuild/SPECS/lis-rhel5.spec
	rpmbuild --clean /root/rpmbuild/SPECS/lis-centos5.spec
#        rpmbuild -ba /root/rpmbuild/SPECS/lis-rhel5.spec
	rpmbuild -ba /root/rpmbuild/SPECS/lis-centos5.spec	
}

# Determine kernel architecture version
osbit=`uname -m`

# Get kernel version and trim last 3 charcter for preamble . 
kernver=$(echo `uname -r` | rev |cut -c 5- | rev)
lastno=$(echo $kernver | rev |cut -c 1 | rev )
nextno=$((lastno+1))
nextkern=$(echo `uname -r` | rev |cut -c 6- | rev)$nextno

# Now create a preamble file with current kernel and next kernel.


#Selecting appropriate rpm, 64 bit rpm for x86_64 based VM
if [ "$osbit" == "x86_64" ]; then
	{
		echo -e "%defattr (-,root,root)\n/lib/modules/`uname -r`\n%config /etc/depmod.d/hyperv.conf" > config
		echo -e "REQUIRES :  kernel >= $kernver\nREQUIRES :  kernel < $nextkern" > preamble
		Runbuild
	}
elif [ "$osbit" == "i686" ]; then
	{
		echo -e "%defattr (-,root,root)\n/lib/modules/`uname -r`PAE\n%config /etc/depmod.d/hyperv.conf" > config
#		echo -e "REQUIRES :  kernel >= $kernver.el5PAE\nREQUIRES :  kernel < $nextkern.el5PAE" > preamble
		Runbuild
		sleep 1
		mkdir tmp
		cp ../RPMS/i686/kmod-microsoft-hyper-v-PAE* tmp/
		# build rpm's for non PAE kernel now
		echo -e "%defattr (-,root,root)\n/lib/modules/`uname -r`\n%config /etc/depmod.d/hyperv.conf" > config
#		echo -e "REQUIRES :  kernel >= $kernver\nREQUIRES :  kernel < $nextkern" > preamble
		Runbuild
		cp -r tmp/kmod-microsoft-hyper-v-PAE* ../RPMS/i686/
		rm -rf tmp
		
	}
fi

# cleanup 
#rm -rf config
