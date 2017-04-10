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

<#
.Synopsis
    Configured Kdump on Linux VMs running on Hyper-V.

.Description
    
    Test parameters

.Parameter vmName
    Name of the VM to test.

.Parameter  hvServer
    Name of the Hyper-V server hosting the VM.

.Parameter  vmIP
    IP address of the VM.

.Parameter  vmRootPasswd
    Root password of the VM.

Please keep plink.exe, pscp.exe in bin\ folder where script is.
#>

#param ([String] $vmName, [String] $hvServer, [String] $vmRootPasswd)

param(
    [Parameter(Mandatory=$true)][String] $vmName,
    [Parameter(Mandatory=$true)][String] $hvServer,
    [Parameter(Mandatory=$true)][String] $vmRootPasswd,
    [String] $vmIP
)

#######################################################################
#
# GetIPv4ViaHyperV()
#
# Description:
#    Looks at the IP address of each NIC. IPv4 addresses are 
#    tested with a ping to check the connectivity then returns the 
#    working IPV4 address
#
#######################################################################

function GetIPv4ViaHyperV([String] $vmName, [String] $server)
{
    <#
    .Synopsis
        Use the Hyper-V network cmdlets to retrieve a VMs IPv4 address.
    .Description
        Look at the IP addresses on each NIC the VM has.  For each
        address, see if it in IPv4 address and then see if it is
        reachable via a ping.
    .Parameter vmName
        Name of the VM to retrieve the IP address from.
    .Parameter server
        Name of the server hosting the VM
    .Example
        GetIpv4ViaHyperV $testVMName $serverName
    #>

    $vm = Get-VM -Name $vmName -ComputerName $server -ErrorAction SilentlyContinue
    if (-not $vm)
    {
        Write-Error -Message "GetIPv4ViaHyperV: Unable to create VM object for VM ${vmName}" -Category ObjectNotFound -ErrorAction SilentlyContinue
        return $null
    }

    $networkAdapters = $vm.NetworkAdapters
    if (-not $networkAdapters)
    {
        Write-Error -Message "GetIPv4ViaHyperV: No network adapters found on VM ${vmName}" -Category ObjectNotFound -ErrorAction SilentlyContinue
        return $null
    }

    foreach ($nic in $networkAdapters)
    {
        $ipAddresses = $nic.IPAddresses
        if (-not $ipAddresses)
        {
            Continue
        }

        foreach ($address in $ipAddresses)
        {
            # Ignore address if it is not an IPv4 address
            $addr = [IPAddress] $address
            if ($addr.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork)
            {
                Continue
            }

            # Ignore address if it a loopback address
            if ($address.StartsWith("127."))
            {
                Continue
            }

            # See if it is an address we can access
            $ping = New-Object System.Net.NetworkInformation.Ping
            $sts = $ping.Send($address)
            if ($sts -and $sts.Status -eq [System.Net.NetworkInformation.IPStatus]::Success)
            {
                return $address
            }
        }
    }

    Write-Error -Message "GetIPv4ViaHyperV: No IPv4 address found on any NICs for VM ${vmName}" -Category ObjectNotFound -ErrorAction SilentlyContinue
    return $null
}

if (-not $vmIP)
{
    $vmIP=GetIPv4ViaHyperV $vmName $hvServer

    if (-not $vmIP)
    {
        "Error: Unable to find IP address for vm ${vmName}"
        return $False
    }
}

$kdump_configure="kdump_configure.sh"
$bash_kdump_verify="kdump_verify.sh"
 
$OSDetails =Get-WmiObject -class Win32_OperatingSystem -computername $hvServer
$hvServerOsVersion=($OSDetails.version -split "\.")[0]+"."+($OSDetails.version -split "\.")[1]

"${vmName} IP address: ${vmIP}, hvServerOsVersion: $hvServerOsVersion"
"Copying files to VM..."

echo "y" | bin\pscp -pw ${vmRootPasswd} $kdump_configure root@${vmIP}:/root/

$cmd="dos2unix *.sh"
echo y | bin\plink.exe  root@${vmIP} -pw  ${vmRootPasswd} $cmd

$cmd="bash /root/$kdump_configure $hvServerOsVersion"
$cmd
echo y | bin\plink.exe  root@${vmIP} -pw  ${vmRootPasswd} $cmd

$status=echo y | bin\plink.exe root@${vmIP} -pw  ${vmRootPasswd} "cat /root/summary.log"

if($status -match "KDUMP_CONFIGURED") {
    "Kdump configued succesfullly"
}else{
    "Error: Kdump configuration failed!!"
}

"Downloading log files.."
echo "y" | bin\pscp -pw ${vmRootPasswd} root@${vmIP}:/root/kdump_config.log . 
if ($LASTEXITCODE -ne 0){
"Failed to download file: kdump_config.log"
}else{
"Succesfully downloaded file: kdump_config.log"
}
echo "y" | bin\pscp -pw ${vmRootPasswd} root@${vmIP}:/root/summary.log . 
if ($LASTEXITCODE -ne 0){
"Failed to download file: summary.log"
}else{
"Succesfully downloaded file: summary.log"
}

