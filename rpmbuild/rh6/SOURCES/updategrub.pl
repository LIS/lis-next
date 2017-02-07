#!/usr/bin/env perl
#
# Copyright (c) 2009, Microsoft Corporation - All rights reserved.
#
# This software is available to you under a choice of one of two
# licenses.  You may choose to be licensed under the terms of the GNU
# General Public License (GPL) Version 2, available from the file
# LICENSE-GPL in the main directory of this source tree, or the
# BSD license (http://opensource.org/licenses/bsd-license.php).
#
#     Redistribution and use in source and binary forms, with or
#     without modification, are permitted provided that the following
#     conditions are met:
#
#      - Redistributions of source code must retain the above
#        copyright notice, this list of conditions and the following
#        disclaimer.
#
#      - Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials
#        provided with the distribution.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Authors:
#   Haiyang Zhang <haiyangz@microsoft.com>
#   Hank Janssen  <hjanssen@microsoft.com>
#

#
# updategrubconf.pl
# This script is used to update the grub.conf or menu.lst file to use the enlightened ide device.
#
use strict;
use File::Basename;
use File::Copy;

#
# Declare subroutines.
#

sub update_grub_file;

#
# Declare globals.
#
my $grubfile = "/boot/grub/grub.conf";
my $kernel_ver = `uname -r`;
my $matchkernel = "vmlinuz-" . $kernel_ver;


#
# main entry point
#
chomp $matchkernel;

if (-e "/etc/SuSE-release") {
	$grubfile = "/boot/grub/menu.lst";
}

update_grub_file();

print "\tDone.\n";

sub update_grub_file() {
	my $grubfiletmp = $grubfile . ".tmp123";
	my $modified = 0;

	if ( -e $grubfiletmp) {
		die "\tError $grubfiletmp exists. Please rename the file and rerun this.\n";
	}
	
	if (!open(GRUB_CONF_FILE_TMP, ">$grubfiletmp")) {
		die "\tError opening $grubfiletmp. Running as root?\n";
	}
	
	if (!open(GRUB_CONF_FILE, "<$grubfile")) {
		close GRUB_CONF_FILE_TMP;
		unlink $grubfiletmp;
		die "\tError opening $grubfile. Running as root?\n";
	}
		
	#print "\tLooking for kernel match - $matchkernel.\n";
		
	while (<GRUB_CONF_FILE>) {
		if ($_ =~ /$matchkernel/) {
			#print "\tKernel match found - $matchkernel.\n";

			if ($_ =~ /hda=noprobe hdb=noprobe/) {
				printf GRUB_CONF_FILE_TMP $_;
			} else {
				chomp $_;
				printf GRUB_CONF_FILE_TMP $_ . " hda=noprobe hdb=noprobe\n";
				$modified = 1;
			}
		} else {
			printf GRUB_CONF_FILE_TMP $_;
		}		
	}
	
	close GRUB_CONF_FILE;
	close GRUB_CONF_FILE_TMP;
		
	if ($modified == 1) {
		move($grubfiletmp, $grubfile);
	} else {
		unlink $grubfiletmp;
	}
}
