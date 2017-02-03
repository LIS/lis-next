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
              kmodrpm=`ls lis-57/x86_64/kmod-microsoft-hyper-v-*.x86_64.rpm`
              msrpm=`ls lis-57/x86_64/microsoft-hyper-v-*.x86_64.rpm`
       }
elif [ "$osbit" == "i686" ]; then

        PAE=` uname -r | grep PAE`
        if [ "$PAE" == "" ]; then
        {
              kmodrpm=`ls lis-57/x86/kmod-microsoft-hyper-v-4*.i686.rpm`
              msrpm=`ls lis-57/x86/microsoft-hyper-v-*.i686.rpm`
        }
        else
        {
              kmodrpm=`ls lis-57/x86/kmod-microsoft-hyper-v-PAE-*.i686.rpm`
              msrpm=`ls lis-57/x86/microsoft-hyper-v-*.i686.rpm`
        }
        fi

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

