#################################################################
# This script is to automate Upgradation of Linux Integration Services for 
# Microsoft Hyper-V
#
################################################################

# Determine kernel architecture version 
osbit=`uname -m`


#Selecting appropriate rpm, 64 bit rpm for x86_64 based VM
if [ "$osbit" == "x86_64" ]; then
       {
              kmodrpm=`ls kmod-microsoft-hyper-v-*.x86_64.rpm`
              msrpm=`ls microsoft-hyper-v-*.x86_64.rpm`
       }
elif [ "$osbit" == "i686" ]; then
       {
              kmodrpm=`ls kmod-microsoft-hyper-v-*.i686.rpm`
              msrpm=`ls microsoft-hyper-v-*.i686.rpm`
       }
fi

#Making sure both rpms are present
if [ "$kmodrpm" != "" ] && [ "$msrpm" != ""  ]; then
       echo "Upgrading the Linux Integration Services for Microsoft Hyper-V..."
       rpm -Uvh $kmodrpm $msrpm
       msexit=$?
       if [ "$msexit" != 0 ]; then
               echo "Microsoft-Hyper-V rpm Upgradation failed, Exiting"
               exit 1;
       else
               echo " Linux Integration Services for Hyper-V has been Upgraded. Please reboot your system"
       fi
      
else 
       echo "RPM's are missing"
fi

