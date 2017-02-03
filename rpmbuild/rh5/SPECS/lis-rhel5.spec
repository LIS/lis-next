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
%define MODULES hv_vmbus hv_netvsc hv_storvsc 

%endif
%ifarch x86_64
%define MODULES hv_vmbus hv_netvsc hv_storvsc
%endif
%define releasetag beta 
%define my_release %(date +%Y%m%d)
Name:			microsoft-hyper-v
%ifarch x86_64
BuildRequires:          %kernel_module_package_buildreqs
%else
BuildRequires:		%kernel_module_package_buildreqs kernel-PAE-devel
%endif
%define _unpackaged_files_terminate_build 0

Requires:               microsoft-hyper-v-kmod = 4.1.3
License:		GPLv2+
Group:			System/Kernel
Summary:		Microsoft hyper-v drivers and utilities
Version:		4.1.3
Release:		%{my_release}
Source0:		lis-next-rh5.tar.gz	
Source1:                hypervkvpd
Source3:		hypervvssd
Source4:		updategrub.pl
Source8:                xorg.conf
Source9:                hypervfcopy
BuildRoot:		%{_tmppath}/%{name}-%{version}-build

# Define the filter.
%define __find_requires sh %{_builddir}/filter-requires.sh


%kernel_module_package -f config -p preamble

%description
This package and subpackage contain drivers and utilities for the Microsoft Hyper-V environment.

%prep
%setup -n hv
cp %_sourcedir/updategrub.pl updategrub.pl
cp tools/hv_get_dns_info.sh hv_get_dns_info
cp tools/hv_set_ifconfig.sh hv_set_ifconfig
cp tools/hv_get_dhcp_info.sh hv_get_dhcp_info
cp tools/hv_kvp_daemon.c %_sourcedir/
cp tools/hv_vss_daemon.c %_sourcedir/
cp %_sourcedir/xorg.conf xorg.conf
cp tools/hv_fcopy_daemon.c %_sourcedir/

echo "/usr/lib/rpm/redhat/find-requires | %{__sed} -e '/^ksym.*/d'" > %{_builddir}/filter-requires.sh

set -- *
mkdir source
mv "$@" source/

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

# copy scripts to be used by post install
install -d -m0755 $RPM_BUILD_ROOT/etc/depmod.d/
install    -m0644 source/hyperv.conf $RPM_BUILD_ROOT/etc/depmod.d/hyperv.conf
install -d -m0755 $RPM_BUILD_ROOT/opt/files
install -d -m0755 $RPM_BUILD_ROOT/etc/X11
install -m0755 source/xorg.conf $RPM_BUILD_ROOT/etc/X11/
install    -m0755 source/updategrub.pl $RPM_BUILD_ROOT/opt/files/
install -d -m0755 $RPM_BUILD_ROOT/usr/sbin
install -m0755 source/hv_get_dns_info $RPM_BUILD_ROOT/usr/sbin/
install -m0755 source/hv_get_dhcp_info $RPM_BUILD_ROOT/usr/sbin/
install -m0755 source/hv_set_ifconfig $RPM_BUILD_ROOT/usr/sbin/
install    -m0755 source/tools/hv_kvp_daemon $RPM_BUILD_ROOT/usr/sbin/
install    -m0755 source/tools/hv_fcopy_daemon $RPM_BUILD_ROOT/usr/sbin/
install    -m0755 source/tools/hv_vss_daemon $RPM_BUILD_ROOT/usr/sbin/
install -d -m0755 $RPM_BUILD_ROOT/etc/init.d
install    -m0755 %{S:1} $RPM_BUILD_ROOT/etc/init.d/hv_kvp_daemon
install    -m0755 %{S:3} $RPM_BUILD_ROOT/etc/init.d/hv_vss_daemon
install    -m0755 %{S:9} $RPM_BUILD_ROOT/etc/init.d/hv_fcopy_daemon

%pre
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


%post
# Update initrd
mkinitrd -f --preload=hv_storvsc "initrd-$(uname -r).img" "$(uname -r)"
echo "Saving old initrd"
if [ ! -e /boot/"initrd-$(uname -r).img-old" ]; then
  cp -f /boot/"initrd-$(uname -r).img" /boot/"initrd-$(uname -r).img-old"
fi
echo "Installing new initrd"
cp -f "initrd-$(uname -r).img" /boot/"initrd-$(uname -r).img"
# If this is an upgrade, put new initrd into /tmp so postrans can
# copy it over to fix the fact that the postun from the previous package
# version will overwrite the updated initrd.
if [ $1 -eq 2 ]; then
   cp -f "initrd-$(uname -r).img" /opt/files/"initrd-$(uname -r).img"
fi
/opt/files/updategrub.pl
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
if [ $1 -ge 1 ]; then # package is being upgraded
  echo "Upgrading RPMs Started"
else # package is being erased, not upgraded
  echo "Create and install initrd without Hyper-V drivers"
  mkinitrd -f "initrd-$(uname -r).img" "$(uname -r)"
  cp -f "initrd-$(uname -r).img" /boot/"initrd-$(uname -r).img"
  rm -rf /opt/files/"initramfs-$(uname -r).img"
  echo "Linux Integration Services for Hyper-V has been removed.Please remove hda=noprobe hdb=noprobe from grub file and reboot your system."
fi

%posttrans 
if [ -e /opt/files/"initrd-$(uname -r).img" ]; then #Recopying new initrd , as it got replaced because postun of old package
    cp -f /opt/files/"initrd-$(uname -r).img" /boot/"initrd-$(uname -r).img"
    echo "Upgrading RPMs Completed"
fi

%files
%defattr(0755,root,root)
/etc/init.d/hv_kvp_daemon
/usr/sbin/hv_kvp_daemon
/etc/init.d/hv_vss_daemon
/usr/sbin/hv_vss_daemon
/usr/sbin/hv_get_dns_info
/usr/sbin/hv_get_dhcp_info
/usr/sbin/hv_set_ifconfig
/opt/files/
/etc/X11/xorg.conf
/etc/init.d/hv_fcopy_daemon
/usr/sbin/hv_fcopy_daemon

%changelog
* Mon Jan 15 2014 - vyadavt@microsoft.com 4.0
New Features Added in LIS 4.0

* Mon Jul 19 2013 - vijayt@microsoft.com 3.5.1
New Features Added in LIS 3.5.1 LIS
-Refer README with released LIS for detailed list of features

* Sat Apr 6 2013 - vijayt@microsoft.com 3.4.2
Fixed non-graceful shutdown issue in 3.4 LIS 
Included posttrans option to support RPM upgrade

* Sun Apr 25 2010 - andavis@novell.com
root- Initial PLDP packages from code version 2.1.25.
