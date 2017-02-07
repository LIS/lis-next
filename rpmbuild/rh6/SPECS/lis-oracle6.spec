#
# spec file for package microsoft-hyper-v
#
# Copyright (c) 2010 SUSE LINUX Products GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.
#
#

# nodebuginfo
# norootforbuild

%ifarch i386
Buildarch: i686
%endif

%ifarch i686
%define MODULES hv_vmbus hv_storvsc
%endif
%ifarch x86_64
%define MODULES hv_vmbus hv_storvsc
%endif
%define releasetag public
%define release %(date +%Y%m%d)
%define _unpackaged_files_terminate_build 0

Name:			microsoft-hyper-v

%ifarch x86_64
BuildRequires:          %kernel_module_package_buildreqs
%else
BuildRequires:          %kernel_module_package_buildreqs
%endif
Requires:               microsoft-hyper-v-kmod = 4.1.3
Requires:               policycoreutils 
License:		GPLv2+
Group:			System/Kernel
Summary:		Microsoft hyper-v drivers and utilities
Version:		4.1.3
Release:		%{release}
Source0:		lis-next-rh6.tar.gz	
Source1:		hypervkvpd
Source6:        	hypervvssd
Source7:        	hypervfcopy
Source8:        	100-balloon.rules
BuildRoot:		%{_tmppath}/%{name}-%{version}-build

%kernel_module_package -f config -p preamble

%description
This package and subpackage contain drivers and utilities for the Microsoft Hyper-V environment.

%prep
%setup -n hv 
cp hyperv_pvdrivers.conf %_sourcedir/
cp tools/hv_get_dns_info.sh hv_get_dns_info
cp tools/hv_get_dhcp_info.sh hv_get_dhcp_info
cp tools/hv_set_ifconfig.sh hv_set_ifconfig
cp tools/lsvmbus lsvmbus
cp %_sourcedir/100-balloon.rules 100-balloon.rules
cp tools/hv_kvp_daemon.c %_sourcedir/
cp tools/hv_vss_daemon.c %_sourcedir/
cp tools/hv_fcopy_daemon.c %_sourcedir/
set -- *
mkdir source
mv "$@" source/
sed -i 's/hv_context.guestid = generate_guest_id(0x20, LINUX_VERSION_CODE, 0);/hv_context.guestid = generate_guest_id(0x22, LINUX_VERSION_CODE, 0);/g' source/hv.c
sed -i 's/#define HV_DRV_VERSION\t"4.1.3"/#define HV_DRV_VERSION\t"4.1.3"/g' source/include/linux/hv_compat.h

mkdir obj

%build
for flavor in %flavors_to_build; do
        rm -rf obj/$flavor
        cp -r source obj/$flavor
        make -C %{kernel_source $flavor} M=$PWD/obj/$flavor modules
done

pushd source/tools
make
popd

%install
export INSTALL_MOD_PATH=$RPM_BUILD_ROOT
export INSTALL_MOD_DIR=extra/%{name}
for flavor in %flavors_to_build; do
        make -C %{kernel_source $flavor} M=$PWD/obj/$flavor modules_install
done
install -d -m0755 $RPM_BUILD_ROOT/etc/udev/rules.d/
install    -m0644 source/100-balloon.rules $RPM_BUILD_ROOT/etc/udev/rules.d/
install -d -m0755 $RPM_BUILD_ROOT/etc/depmod.d/
install    -m0644 source/hyperv.conf $RPM_BUILD_ROOT/etc/depmod.d/hyperv.conf
install -d -m0755 $RPM_BUILD_ROOT/opt/files
install -d -m0755 $RPM_BUILD_ROOT/etc/modprobe.d
install    -m0644 source/hyperv_pvdrivers.conf $RPM_BUILD_ROOT/etc/modprobe.d/
install -d -m0755 $RPM_BUILD_ROOT/sbin
install -m0755 source/lsvmbus $RPM_BUILD_ROOT/sbin/
install -d -m0755 $RPM_BUILD_ROOT/usr/sbin
install -m0755 source/hv_get_dns_info $RPM_BUILD_ROOT/usr/sbin/
install -m0755 source/hv_get_dhcp_info $RPM_BUILD_ROOT/usr/sbin/
install -m0755 source/hv_set_ifconfig $RPM_BUILD_ROOT/usr/sbin/
install    -m0755 source/tools/hv_kvp_daemon $RPM_BUILD_ROOT/usr/sbin/
install    -m0755 source/tools/hv_fcopy_daemon $RPM_BUILD_ROOT/usr/sbin/
install    -m0755 source/tools/hv_vss_daemon $RPM_BUILD_ROOT/usr/sbin/
install -d -m0755 $RPM_BUILD_ROOT/etc/init.d
install    -m0755 %{S:1} $RPM_BUILD_ROOT/etc/init.d/hv_kvp_daemon
install    -m0755 %{S:7} $RPM_BUILD_ROOT/etc/init.d/hv_fcopy_daemon
install    -m0755 %{S:6} $RPM_BUILD_ROOT/etc/init.d/hv_vss_daemon

%pre
if [ $1 -eq 1 ]; then
 latestkernel=(`rpm -q kernel | tail -n1 | cut -c 8-`)
 runningkernel=(`uname -r`)
 if [ ${latestkernel} != ${runningkernel} ] ; then
   echo "your running kernel ${runningkernel} is not your latest installed kernel, aborting installation"
   (sleep 2; rpm -e kmod-microsoft-hyper-v ) &
   echo "removing kmod-microsoft-hyper-v..."
   exit 1
 fi
fi

%ifarch i686
if [ `uname -i` == "x86_64" ]; then
  echo "This system supports 64-bit; please install the x86_64 versions of the Hyper-V modules.  Exiting now..."
  exit 1
fi
%endif

%ifarch x86_64
if [ `uname -i` == "i686" ]; then
  echo "This system supports 32-bit; please install the x86 versions of the Hyper-V modules.  Exiting now..."
  exit 1
fi
%endif

if [ ! `grep -q -E "6.0|6.1|6.2|6.3" /etc/*-release` ] ; then
 rm -rf /etc/modprobe.d/hyperv_pvdrivers.conf
fi

%post

# Update initrd
dracut --force "initramfs-$(uname -r).img" $(uname -r)
echo "Saving old initramfs"
if [ ! -e /boot/"initramfs-$(uname -r).img-old" ]
then
  cp -f /boot/"initramfs-$(uname -r).img" /boot/"initramfs-$(uname -r).img-old"
fi
echo "Installing new initramfs"
cp -f "initramfs-$(uname -r).img" /boot/"initramfs-$(uname -r).img"
# If this is an upgrade, put new initrd into /tmp so postrans can
# copy it over to fix the fact that the postun from the previous package
# version will overwrite the updated initrd.
cp /etc/depmod.d/hyperv.conf /opt/files/
if [ $1 -eq 2 ]; then
   cp -f "initramfs-$(uname -r).img" /opt/files/"initramfs-$(uname -r).img"
fi

if [ $1 -eq 1 ]; then
  rm -rf /etc/depmod.d/hyperv.conf
fi

/sbin/chkconfig --add hv_kvp_daemon
echo "Adding KVP Daemon to Chkconfig...."
/etc/init.d/hv_kvp_daemon start >/dev/null
echo "Starting KVP Daemon...."

/sbin/chkconfig --add hv_vss_daemon
echo "Adding VSS Daemon to Chkconfig...."
/etc/init.d/hv_vss_daemon start >/dev/null
echo "Starting VSS Daemon...."

/sbin/chkconfig --add hv_fcopy_daemon
echo "Adding FCOPY Daemon to Chkconfig...."
/etc/init.d/hv_fcopy_daemon start >/dev/null
echo "Starting FCOPY Daemon...."

%preun
if [ $1 -eq 0 ]; then # package is being erased, not upgraded
    echo "Removing Package.."
    /sbin/service hv_kvp_daemon stop > /dev/null 2>&1
    echo "Stopping KVP Daemon...."
    /sbin/chkconfig --del hv_kvp_daemon
    echo "Deleting KVP Daemon from Chkconfig...."
    /sbin/service hv_vss_daemon stop > /dev/null 2>&1
    echo "Stopping VSS Daemon...."
    /sbin/chkconfig --del hv_vss_daemon
    echo "Deleting VSS Daemon from Chkconfig...."    
    /sbin/service hv_fcopy_daemon stop > /dev/null 2>&1
    echo "Stopping FCOPY Daemon...."
    /sbin/chkconfig --del hv_fcopy_daemon
    echo "Deleting FCOPY Daemon from Chkconfig...."	

fi

%postun
if [ "$1" -ge "1" ]; then # Upgrade
    echo "Upgrading RPMs Started"
#    /sbin/service vmbus condrestart > /dev/null 2>&1
else # package is being erased, not upgraded
    echo "Create and install initramfs without Hyper-V drivers"
    dracut --force "initramfs-$(uname -r).img" $(uname -r)
    cp -f "initramfs-$(uname -r).img" /boot/"initramfs-$(uname -r).img"
    rm -rf /opt/files/"initramfs-$(uname -r).img"
    cp /opt/files/hyperv.conf /etc/depmod.d/
    rm -rf  /opt/files/hyperv.conf
    echo "Linux Integration Services for Hyper-V has been removed.  Please reboot your system."
fi

%posttrans
if [ -e /opt/files/"initramfs-$(uname -r).img" ]; then #Recopying new initrd , as it got replaced because postun of old package
    cp -f /opt/files/"initramfs-$(uname -r).img" /boot/"initramfs-$(uname -r).img"
    echo "Upgrading RPMs Completed"
    rm -rf /etc/depmod.d/hyperv.conf
fi

%files
%defattr(0755,root,root)
/etc/udev/rules.d/100-balloon.rules
/etc/modprobe.d/hyperv_pvdrivers.conf
/etc/init.d/hv_kvp_daemon
/usr/sbin/hv_kvp_daemon
/etc/init.d/hv_vss_daemon
/usr/sbin/hv_vss_daemon
/etc/init.d/hv_fcopy_daemon
/usr/sbin/hv_fcopy_daemon
/usr/sbin/hv_get_dns_info
/usr/sbin/hv_get_dhcp_info
/usr/sbin/hv_set_ifconfig
/opt/files/
/sbin/lsvmbus
%changelog
* Mon Jan 7 2015 - vyadav@microsoft.com
New Features Added in LIS 4.0
-Refer README with released LIS for detailed list of features

* Thu Jul 26 2012 - vijayt@microsoft.com
Guest ID Issue Fixed in code version 3.3.5.Code base Now same for all rhel6.x Version
* Sun Apr 25 2010 - andavis@novell.com
- Initial PLDP packages from code version 2.1.25.
