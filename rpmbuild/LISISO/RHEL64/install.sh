################################################################################
#
# This script is to automate installation of Linux Integration Services for 
# Microsoft Hyper-V
#
################################################################################

# Determine kernel architecture version 
osbit=`uname -m`
kernelver=`uname -r`

regex='2.6.32-358.[0-9]+\.[0-9]+'
if [[ "$kernelver" =~ $regex ]]; then
   { 
	cd update 
	kmodrpm=`ls kmod-microsoft-hyper-v-4*.x86_64.rpm`
 	msrpm=`ls microsoft-hyper-v-4*.x86_64.rpm`
	if [ "$kmodrpm" != "" ] && [ "$msrpm" != ""  ]; then
       	echo "Installing the Linux Integration Services for Microsoft Hyper-V..."
       	rpm -ivh $kmodrpm
	kmodexit=$?
       if [ "$kmodexit" == 0 ]; then
              rpm -ivh $msrpm
              msexit=$?
              if [ "$msexit" != 0 ]; then
                     echo "Microsoft-Hyper-V RPM installation failed, Exiting."
                     exit 1;
              else
                     echo " Linux Integration Services for Hyper-V has been installed. Please reboot your system."
			exit 0
              fi
       else
              echo "Kmod RPM installation failed, Exiting."
              exit 1
       fi
      fi	
   }

fi 

#Selecting appropriate rpm, 64 bit rpm for x86_64 based VM
if [ "$osbit" == "x86_64" ]; then
       {
              kmodrpm=`ls kmod-microsoft-hyper-v-4*.x86_64.rpm`
              msrpm=`ls microsoft-hyper-v-4*.x86_64.rpm`
       }
elif [ "$osbit" == "i686" ]; then
       {
              kmodrpm=`ls kmod-microsoft-hyper-v-4*.i686.rpm`
              msrpm=`ls microsoft-hyper-v-4*.i686.rpm`
       }
fi

#Making sure both rpms are present

if [ "$kmodrpm" != "" ] && [ "$msrpm" != ""  ]; then
       echo "Installing the Linux Integration Services for Microsoft Hyper-V..."
       rpm -ivh $kmodrpm
       kmodexit=$?
       if [ "$kmodexit" == 0 ]; then
              rpm -ivh $msrpm
              msexit=$?
              if [ "$msexit" != 0 ]; then
                     echo "Microsoft-Hyper-V RPM installation failed, Exiting."
                     exit 1;
              else
                     echo " Linux Integration Services for Hyper-V has been installed. Please reboot your system."
              fi
       else
              echo "Kmod RPM installation failed, Exiting."
              exit 1
       fi
else 
       echo "RPM's are missing"
fi

