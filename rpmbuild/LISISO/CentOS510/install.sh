################################################################################
#
# This script is to automate installation of Linux Integration Services for 
# Microsoft Hyper-V
#
################################################################################

# Determine kernel architecture version 
osbit=`uname -m`

# Determine if its PAE kernel


#Selecting appropriate rpm, 64 bit rpm for x86_64 based VM
if [ "$osbit" == "x86_64" ]; then
       {
              kmodrpm=`ls lis-510/x86_64/kmod-microsoft-hyper-v-*.x86_64.rpm`
              msrpm=`ls lis-510/x86_64/microsoft-hyper-v-*.x86_64.rpm`
       }
elif [ "$osbit" == "i686" ]; then
       
	PAE=` uname -r | grep PAE`
	if [ "$PAE" == "" ]; then 
	{
              kmodrpm=`ls lis-510/x86/kmod-microsoft-hyper-v-4*.i686.rpm`
              msrpm=`ls lis-510/x86/microsoft-hyper-v-*.i686.rpm`
	}
	else
	{
              kmodrpm=`ls lis-510/x86/kmod-microsoft-hyper-v-PAE-*.i686.rpm`
              msrpm=`ls lis-510/x86/microsoft-hyper-v-*.i686.rpm`
	}
	fi	
       
fi

#Making sure both rpms are present
if [ "$kmodrpm" != "" ] && [ "$msrpm" != ""  ]; then
       echo "Installing the Linux Integration Services for Microsoft Hyper-V..."
       rpm -ivh --nodeps $kmodrpm
       kmodexit=$?
       if [ "$kmodexit" == 0 ]; then
              rpm -ivh --nodeps $msrpm
              msexit=$?
              if [ "$msexit" != 0 ]; then
                     echo "Microsoft-Hyper-V rpm installation failed, Exiting"
                     exit 1;
              else
                     echo " Linux Integration Services for Hyper-V has been installed. Please reboot your system"
              fi
       else
              echo "Kmod RPM installation failed, Exiting"
              exit 1
       fi
else 
       echo "RPM's are missing"
fi

