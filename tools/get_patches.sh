#!/bin/bash

######################################################################## 
# 
# Linux on Hyper-V and Azure Test Code, ver. 1.0.0 
# Copyright (c) Microsoft Corporation 
# 
# All rights reserved.  
# Licensed under the Apache License, Version 2.0 (the ""License""); 
# you may not use this file except in compliance with the License. 
# You may obtain a copy of the License at 
#     http://www.apache.org/licenses/LICENSE-2.0   
# 
# THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS 
# OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION 
# ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR 
# PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT. 
# 
# See the Apache Version 2.0 License for specific language governing 
# permissions and limitations under the License. 
# 
######################################################################## 

######################################################################## 
#
# This is a script to help download LIS driver patches from upstream (e.g.
# linux-next, net-next).
# 
# How to use this:
# 1) Place each upstream commit id  (e.g. from kernel.org) in a file
#    (e.g. patches.txt)
# 
# 2) Run 'get_patches.sh <file containing commit IDs>'
#
########################################################################

FILENAME=$1
OUTPUT=$2
count=0
url=""
urlprefix="https://git.kernel.org/cgit/linux/kernel/git/next/linux-next.git/patch?id="

cat $FILENAME | while read LINE

do

let count++
url="${urlprefix}${LINE}"

echo "$count $url"
printf -v file "%02d" $count
wget $url -O $OUTPUT/$file.patch --no-check-certificate

done

