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
License:		GPLv2+
Group:			System/Kernel
Summary:		Microsoft hyper-v drivers and utilities
Version:		4.1.3
Release:		%{release}
Source0:		lis-next-rh7.tar.gz	
BuildRoot:		%{_tmppath}/%{name}-%{version}-build

%kernel_module_package -f config -p preamble

%description
This package and subpackage contain drivers and utilities for the Microsoft Hyper-V environment.

%prep
%setup -n hv
cp tools/hv_get_dns_info hv_get_dns_info
cp tools/hv_get_dhcp_info hv_get_dhcp_info
cp tools/hv_set_ifconfig hv_set_ifconfig
cp tools/lsvmbus lsvmbus
cp tools/systemd/hv_fcopy_daemon.service hv_fcopy_daemon.service
cp tools/systemd/hv_kvp_daemon.service hv_kvp_daemon.service
cp tools/systemd/hv_vss_daemon.service hv_vss_daemon.service
cp tools/systemd/70-hv_fcopy.rules 70-hv_fcopy.rules
cp tools/systemd/70-hv_kvp.rules 70-hv_kvp.rules
cp tools/systemd/70-hv_vss.rules 70-hv_vss.rules
cp %_sourcedir/100-balloon.rules 100-balloon.rules
cp %_sourcedir/68-azure-sriov-nm-unmanaged.rules 68-azure-sriov-nm-unmanaged.rules
cp tools/hv_kvp_daemon.c %_sourcedir/
cp tools/hv_vss_daemon.c %_sourcedir/
cp tools/hv_fcopy_daemon.c %_sourcedir/
set -- *
mkdir source
mv "$@" source/
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
install    -m0644 source/68-azure-sriov-nm-unmanaged.rules $RPM_BUILD_ROOT/lib/udev/rules.d/
install -d -m0755 $RPM_BUILD_ROOT/etc/depmod.d/
install    -m0644 source/hyperv.conf $RPM_BUILD_ROOT/etc/depmod.d/hyperv.conf
install -d -m0755 $RPM_BUILD_ROOT/opt/files
install -d -m0755 $RPM_BUILD_ROOT/sbin
install -m0755 source/lsvmbus $RPM_BUILD_ROOT/sbin/
install -d -m0755 $RPM_BUILD_ROOT/usr/sbin
install -m0755 source/hv_get_dns_info $RPM_BUILD_ROOT/usr/sbin/
install -m0755 source/hv_get_dhcp_info $RPM_BUILD_ROOT/usr/sbin/
install -m0755 source/hv_set_ifconfig $RPM_BUILD_ROOT/usr/sbin/
install    -m0755 source/tools/hv_kvp_daemon $RPM_BUILD_ROOT/usr/sbin/
install    -m0755 source/tools/hv_fcopy_daemon $RPM_BUILD_ROOT/usr/sbin/
install    -m0755 source/tools/hv_vss_daemon $RPM_BUILD_ROOT/usr/sbin/
install -d -m0755 $RPM_BUILD_ROOT/lib/systemd/system/
install    -m0644 source/hv_kvp_daemon.service $RPM_BUILD_ROOT/lib/systemd/system/hv_kvp_daemon.service
install    -m0644 source/hv_fcopy_daemon.service $RPM_BUILD_ROOT/lib/systemd/system/hv_fcopy_daemon.service
install    -m0644 source/hv_vss_daemon.service $RPM_BUILD_ROOT/lib/systemd/system/hv_vss_daemon.service
install -d -m0755 $RPM_BUILD_ROOT/usr/lib/udev/rules.d/
install    -m0644 source/70-hv_kvp.rules $RPM_BUILD_ROOT/usr/lib/udev/rules.d/70-hv_kvp.rules
install    -m0644 source/70-hv_fcopy.rules $RPM_BUILD_ROOT/usr/lib/udev/rules.d/70-hv_fcopy.rules
install    -m0644 source/70-hv_vss.rules $RPM_BUILD_ROOT/usr/lib/udev/rules.d/70-hv_vss.rules

find %{buildroot} -name "modules.devname" -delete
find %{buildroot} -name "modules.alias" -delete
find %{buildroot} -name "modules.alias.bin" -delete
find %{buildroot} -name "modules.dep" -delete
find %{buildroot} -name "modules.softdep" -delete
find %{buildroot} -name "modules.dep.bin" -delete
find %{buildroot} -name "modules.softdep" -delete
find %{buildroot} -name "modules.symbols" -delete
find %{buildroot} -name "modules.symbols.bin" -delete
find %{buildroot} -name "modules.builtin.bin" -delete

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

# This is  added to remove/move file before upgrade. 
if [ $1 -eq 2 ]; then
 if [  -e /opt/files/hyperv_pvdrivers.conf ] ; then
   mv /opt/files/hyperv_pvdrivers.conf /etc/modprobe.d/
 fi
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

echo "Starting KVP Daemon...."
systemctl daemon-reload
systemctl enable hv_kvp_daemon.service > /dev/null 2>&1
#systemctl start hv_kvp_daemon

echo "Starting VSS Daemon...."
systemctl enable hv_vss_daemon.service > /dev/null 2>&1
#systemctl start hv_vss_daemon

echo "Starting FCOPY Daemon...."
systemctl enable hv_fcopy_daemon.service > /dev/null 2>&1
#systemctl start hv_fcopy_daemon

%preun
if [ $1 -eq 0 ]; then # package is being erased, not upgraded
    echo "Removing Package.."
    echo "Stopping KVP Daemon...."
    systemctl stop hv_kvp_daemon
    echo "Stopping FCOPY Daemon...."
    systemctl stop hv_fcopy_daemon
    echo "Stopping VSS Daemon...."
    systemctl stop hv_vss_daemon

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

if [  -e /etc/modprobe.d/hyperv_pvdrivers.conf ] ; then
   rm -rf /etc/modprobe.d/hyperv_pvdrivers.conf
fi

%files
%defattr(0644, root, root)
/etc/udev/rules.d/100-balloon.rules
/lib/udev/rules.d/68-azure-sriov-nm-unmanaged.rules
/usr/lib/udev/rules.d/70-hv_vss.rules
/usr/lib/udev/rules.d/70-hv_kvp.rules
/usr/lib/udev/rules.d/70-hv_fcopy.rules
/lib/systemd/system/hv_fcopy_daemon.service
/lib/systemd/system/hv_kvp_daemon.service
/lib/systemd/system/hv_vss_daemon.service
%defattr(0755, root, root)
/usr/sbin/hv_kvp_daemon
/usr/sbin/hv_vss_daemon
/usr/sbin/hv_fcopy_daemon
/usr/sbin/hv_get_dns_info
/usr/sbin/hv_get_dhcp_info
/usr/sbin/hv_set_ifconfig
/sbin/lsvmbus
/opt/files/
%changelog
* Mon Jan 7 2015 - vyadav@microsoft.com
New Features Added in LIS 4.0
-Refer README with released LIS for detailed list of features

* Thu Jul 26 2012 - vijayt@microsoft.com
Guest ID Issue Fixed in code version 3.3.5.Code base Now same for all rhel6.x Version
* Sun Apr 25 2010 - andavis@novell.com
- Initial PLDP packages from code version 2.1.25.
