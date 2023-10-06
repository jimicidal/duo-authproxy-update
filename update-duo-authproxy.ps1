#Duo AuthProxy's display name when installed
$Global:TargetInstalledDisplayName = 'Duo Security Authentication Proxy'
$Global:TargetServiceName = 'DuoAuthProxy'

#Registry locations to check for existing installations
$Global:Targetx64RegistryLocation = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\'
$Global:Targetx86RegistryLocation = 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\'

#Possible config file locations
$Global:Targetx64ConfigDir = 'C:\Program Files\Duo Security Authentication Proxy\conf'
$Global:Targetx86ConfigDir = 'C:\Program Files (x86)\Duo Security Authentication Proxy\conf'
$Global:TargetConfigFileName = 'authproxy.cfg'

#Duo's checksum information URL to determine the latest AuthProxy version available on the web
$Global:TargetChecksumURL = 'https://duo.com/docs/checksums'

#Initialize flags for potential remediations needed after audit
$RemediationNeeded = @{'UpdateNeeded' = $false;
                        'UpdateCheckFailed' = $false;
                        'ExtraFiles' = $false;
                        'BadFailmode' = $false;
                        'EncryptionNeeded' = $false}

<#Initialize flags for possible fixes that can be made by this script
#Hacky due to Datto passing a component's "Boolean" values as strings
#https://community.datto.com/t5/RMM/Powershell-Scripting-DattoRMM-Components-and-Boolean-values/m-p/102099
$AutoFix = @{}
if ($env:AutoFixExtraFiles -eq $true) {$AutoFix['ExtraFiles'] = $true} else {$AutoFix['ExtraFiles'] = $false}
if ($env:AutoFixBadFailmode -eq $true) {$AutoFix['BadFailmode'] = $true} else {$AutoFix['BadFailmode'] = $false}
if ($env:AutoFixEncryptionNeeded -eq $true) {$AutoFix['EncryptionNeeded'] = $true} else {$AutoFix['EncryptionNeeded'] = $false}
if ($env:AutoFixUpdateNeeded -eq $true) {$AutoFix['UpdateNeeded'] = $true} else {$AutoFix['UpdateNeeded'] = $false}#>

$AutoFix = @{'ExtraFiles' = $true;#                 for local testing only
                'BadFailmode' = $true;#             for local testing only
                'EncryptionNeeded' = $true;#        for local testing only
                'UpdateNeeded' = $true}#            for local testing only



##########
### These "Write-*" functions customize output formatting to make the PowerShell and Datto StdOut easier to read
#
Function Write-OK() {   #Custom OK message prefix + color
    param (
        $message
    )

    write-host "  + $message" -ForegroundColor Green
}

Function Write-Warn() { #Custom warning message prefix + color
    param (
        $message,
        [int]$level = 1 #Assume level 1 unless you pass another value
    )

    Switch ($level) {
        1 {$prefix = '  - '} #Level 1, warning item
        2 {$prefix = '    -- '} #Level 2, basically just a nested sub-item for additional info
    }
    write-host $prefix$message -ForegroundColor Yellow
}

##########
### These "Get-*"/"Find-*" functions retrieve information about the installed AuthProxy/config file/newly available versions, etc.
#
Function Get-LatestAuthProxyVersion() {
    #Return the latest Duo authproxy version number fetched from the web if possible
    try {
        #Make three attempts at grabbing this info from duo.com
        for ($attemptNumber = 1; $attemptNumber -lt 4; $attemptNumber++) {
            #Find the URL for the latest Duo Authproxy installer using known naming pattern at Duo's checksums page
            $LatestAuthProxyDownloadURL = $(invoke-webrequest $TargetChecksumURL -UseBasicParsing).links.href | select-string -pattern "/duoauthproxy-[0-9\.]+\.exe" | out-string

            #Parse the installer's filename to extract just the version information
            $LatestAuthProxyVersion = $($($LatestAuthProxyDownloadURL -split "duoauthproxy-")[1] -split ".exe" | out-string).trim()
            if ($null -ne $LatestAuthProxyVersion) {
                return $LatestAuthProxyVersion #Stop trying if version number retrieved, or after three tries
            } elseif ($attemptNumber -eq 3) {
                Write-warn -message 'Unable to get current version number after 3 attempts.'
            }
        }
    } catch {
        $RemediationNeeded["UpdateCheckFailed"] = $true

        Write-warn -message "Unable to get current version number from duo.com"
        write-warn -message $_ -level 2
    }
}
Function Find-InstalledDuoAuthProxyVersion() {
    #Return the installed Duo AuthProxy version if found on this PC
    try {
        #Check for Duo uninstall string in x64 registry location
        $RegistryInstallObject = Get-ItemProperty "$Targetx64RegistryLocation*" | where-object -property displayname -Match $TargetInstalledDisplayName
        if ($null -eq $RegistryInstallObject) {
            #Check for uninstall string in x86 registry location
            $RegistryInstallObject = Get-ItemProperty "$Targetx86RegistryLocation*" | where-object -property displayname -Match $TargetInstalledDisplayName
        }
        return $RegistryInstallObject.displayversion
    } catch {
        Write-warn -message 'Could not detect Duo AuthProxy version.'
        write-warn -message $_ -level 2
    }
}

Function Find-DuoAuthProxyConfigFile() {
    #Return the directory containing the Duo AuthProxy's config file if found
    try {
        if (test-Path "$Targetx64ConfigDir\$TargetConfigFileName") {
            return $Targetx64ConfigDir
        } elseif (test-path "$Targetx86ConfigDir\$TargetConfigFileName") {
            return $Targetx86ConfigDir
        } else {
            Write-warn -message 'No authproxy.cfg file found.'
        }
    } catch {
        Write-warn -message "Problem accessing authproxy.cfg file."
        write-warn -message $_ -level 2
        exit 1  #Nothing further to do without the config file
    }
}

Function Find-ExtraFiles() {
    #Look for unnecessary files in the requested path, as they may contain old or unencrypted secrets. Return $true if issue found
    param (
        $configFileLocation
    )

    try {
        #Ignore the config file itself and the ca-bundle.crt
        $ExtraFiles = get-childitem -Path $configFileLocation -exclude $TargetConfigFileName,"ca-bundle.crt"
        if ($ExtraFiles) {
            Write-Warn -message "Extra files found in Duo's conf directory. These may contain plaintext secrets."
            return $true
        } else {
            Write-ok "No extra .cfg files found in Duo's conf directory."
            return $false
        }
    } catch {
        Write-Warn -message "Unable to check for extra files in Duo's conf directory."
    }
}

Function Find-Failmodes() {
    #Grab all the failmode assignment lines in the requested config file. Return $true if issue found
    param (
        $configFileLocation
    )
    $remediationNeeded = $false

    $ConfiguredFailmodes = Select-String -Path "$configFileLocation\$TargetConfigFilename" -Pattern 'failmode.*=.*\S+' -AllMatches
    foreach ($FailmodeLine in $ConfiguredFailmodes) {
        $FailmodeLine = $($($FailmodeLine -split ':')[-1].ToString()).trim()
        #We only care about uncommented lines
        if ($FailmodeLine[0] -ne ';') {
            #Cut out just the assigned values for analysis
            $Failmode = $($($FailmodeLine -split '=')[-1]).trim()
            if ($Failmode -eq 'secure') {
                Write-ok "Failmode correctly set to 'secure'."
            } else {
                Write-warn -message "Failmode incorrectly set to '$Failmode'."
                $remediationNeeded = $true
            }
        }
    }
    if ($remediationNeeded) {return $true}
    else {return $false}
}

Function Find-PlaintextSecrets() {
    #Grab lines containing secrets and check that they're encrypted. Return $true if issue found
    param (
        $configFileLocation,
        $suppressOutput = $false    #Optionally suppress STDOUT for this function
    )
    $remediationNeeded = $false

    $ConfiguredSecrets = Select-String -Path "$ConfigFileLocation\$TargetConfigFilename" -Pattern '(skey|secret|password).*=.*\S+' -AllMatches
    foreach ($SecretLine in $ConfiguredSecrets) {
        #Cut out just the configured setting name, we don't care about the assigned value
        $SecretLine = $($($($($($SecretLine -split '=')[0]) -split ':')[-1]).tostring()).trim()
        if ($SecretLine -match 'protected') {
            if (!($suppressOutput)) {Write-ok "'$SecretLine' - encrypted line OK."}
        } elseif ($SecretLine -notmatch 'protected') {
            if (!($suppressOutput)) {
                switch ($SecretLine[0]) {
                    {$_ -ne ';'} {write-warn -message "'$SecretLine' - line not encrypted."}
                    {$_ -eq ';'} {write-warn -message "'$SecretLine' - commented plaintext secret should be removed."}
                }
            }
            $remediationNeeded = $true
        }
    }
    if ($remediationNeeded) {return $true}
    else {return $false}
}

##########
### These "Repair-*"/"Restart-*" functions attempt to actually make changes to the PC
#
Function Repair-ExtraFiles() {
    #Try to remove all extra files from the AuthProxy's conf directory
    param (
        $configFileLocation
    )

    try {
        get-childitem -Path $configFileLocation -exclude $TargetConfigFileName,'ca-bundle.crt' | remove-item

        write-ok 'Removed extra files.'

        return $false   #Remediation no longer needed if this was successful
    } catch {
        Write-warn -message "Failed to automatically remove extra files."
        write-warn -message $_ -level 2

        return $true    #Remediation still needed on failure
    }
}

Function Repair-BadFailmode() {
    #Try to re-write failmodes in the AuthProxy configuration file from "safe" to "secure"
    param (
        $configFileLocation
    )

    Try {
        $ConfigFileContents = get-content -path "$ConfigFileLocation\$TargetConfigFilename" | `
            ForEach-Object {$_ -Replace '=.*safe.*', '=secure'}

        set-content -path "$ConfigFileLocation\$TargetConfigFilename" -value $ConfigFileContents

        Write-ok 'Set failmode(s) to "secure".'

        return $false   #Remediation no longer needed if this was successful
    } catch {
        Write-warn -message "Failed to automatically repair failmodes."
        write-warn -message $_ -level 2

        return $true    #Remediation still needed on failure
    }
}

Function Repair-EncryptionNeeded() {
    #Try to use Duo's encryption binary to encrypt all secrets in the config file
    param (
        $configFileLocation
    )
    $remediationNeeded = $false

    try {
        #Run authproxy_passwd.exe to address secrets in use by the authproxy
        Start-Process -FilePath "$configFileLocation\..\bin\authproxy_passwd.exe" -ArgumentList "--whole-config -y" -ErrorAction stop -WarningAction Ignore -wait

        Write-ok 'Encrypted all secrets.'
    } catch {
        Write-warn -message "Failed to automatically encrypt secrets."
        write-warn -message $_ -level 2

        $remediationNeeded = $true  #Remediation still needed on failure
    }

    #Check again for plaintext secrets. This would indicate they are commented out and those lines just need to be removed
    if (Find-PlaintextSecrets $configFileLocation -suppressOutput $true) {
        #If any plaintext secrets still exist, attempt repairs and check whether that was successful
        if (Repair-CommentedSecrets($configFileLocation) -eq $true) {
            $remediationNeeded = $true  #Remediation still needed on failure
        }
    }

    #If authproxy_passwd.exe or removing commented plaintext secrets failed, there are still issues to be addressed
    if ($remediationNeeded) {return $true}
    else {return $false}
}

Function Repair-CommentedSecrets() {
    #Try to remove entire lines containing commented secrets in the config file
    param (
        $configFileLocation
    )

    try {
        #Get the contents of the config file, but ignore commented lines containing secrets
        $newConfigContent = Get-Content -Path "$ConfigFileLocation\$TargetConfigFilename" | Where-Object { $_ -notmatch '^;.*(skey|secret|password).*=.*\S+' }

        #Attempt to replace the config file with the filtered contents
        Set-Content -Path "$ConfigFileLocation\$TargetConfigFilename" -value $newConfigContent

        Write-ok 'Removed all commented plaintext secrets.'

        return $false   #Remediation no longer needed if this was successful
    } catch {
        Write-warn -message "Failed to automatically remove commented plaintext secrets."
        write-warn -message $_ -level 2

        return $true    #Remediation still needed on failure
    }
}

Function Repair-UpdateNeeded() {
    #Try to fetch and install the latest AuthProxy version available on the web

    #Unfortunately, some services interfere with installing the update. They cause the /bin/servicemanger.pyd file
    #to become locked and the installer will ask for a reboot to release the file lock. For Perch services, stopping
    #them temporarily lets you proceed with the update. The "Event log" service will also lock the .pyd file as a
    #DLL and LogicMonitor may have something to do with it. Stopping the LogicMonitor services has no effect, and
    #there may be another service still that causes Event Log to lock the file. In any case, we will just save the
    #installer to disk if the upgrade can't continue.

    #Where to grab the latest installer
    $DownloadURL = "https://dl.duosecurity.com/duoauthproxy-latest.exe"

    #Save any downloads to this temp folder
    $SavePath = "C:\Users\Public\Downloads"

    #Create the temp folder if it doesn't already exist
    if ( -not (Test-Path -Path $SavePath)) {New-Item -ItemType Directory -Path $SavePath}

    #Try to download the latest installer
    try {
        Invoke-WebRequest -URI $DownloadURL -OutFile "$SavePath\DuoAuthProxyUpdate.exe"
    } catch {
        Write-warn -message "Failed to download the latest AuthProxy installer."
        write-warn -message $_ -level 2

        return $true    #Update still needed on failure
    }

    #Check for and stop any Perch services
    if (get-service -name "perch*beat") {
        $PerchServices = get-service -name "perch*beat" | Where-Object {$_.Status -eq "Running"}
        try {
            stop-service $PerchServices
            start-sleep 2
        }
        catch {}
    }

    #Stop the DuoAuthProxy service if its running
    if (get-service -name $TargetServiceName | Where-Object {$_.Status -eq "Running"}) {
        $DuoServiceRunning = $true
        try {
            stop-service -name $TargetServiceName
            start-sleep 2
        }
        catch {}
    } else {
        $DuoServiceRunning = $false
    }

    #Check if the .pyd file is still locked
    $FileLocked = $false
    try {
        $FileCheck = [System.IO.File]::Open("C:\Program Files\Duo Security Authentication Proxy\bin\servicemanager.pyd",'Open','Write')
        $FileCheck.Close()
        $FileCheck.Dispose()
    } catch {
        $FileLocked = $true
    }

    #Attempt install if the file is not locked
    $InstallFailed = $false
    if ($FileLocked) {
        Write-warn -message "AuthProxy update failed - bin\servicemanager.pyd file is locked."
        write-warn -message "Update will require reboot. Installer saved in $SavePath." -level 2
        $InstallFailed = $true
    } else {
        try {
            start-process -FilePath "$SavePath\DuoAuthProxyUpdate.exe" -ArgumentList "/S" -WarningAction SilentlyContinue
            Write-OK "AuthProxy update was successfully installed."
        } catch {
            Write-warn -message "Failure during AuthProxy update installation."
            write-warn -message "Check log\install.log. Installer saved in $SavePath." -level 2
            write-warn -message $_ -level 2
            $InstallFailed = $true
        }
    }

    #Restart DuoAuthProxy service if it was already running
    if ($DuoServiceRunning) {
        try {start-service -name $TargetServiceName -WarningAction SilentlyContinue}
        catch {}
    } else {
        Write-warn -message "Duo service was not already running. Opting not to try starting it." -level 2
    }

    #Restart Perch services if applicable
    if ($PerchServices) {
        try {start-service $PerchServices}
        catch {}
    }

    #Report back whether update is still needed
    return $InstallFailed
}

##########
### Begin the main body of the component; actually calling the functions above to act on what's been found
#
#First ensure we are using TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#Make sure we have Duo installed on this machine. Quit if not found
Write-Host 'Checking registry to confirm the Duo Authentication Proxy is installed...'
$InstalledAuthProxyVersion = Find-InstalledDuoAuthProxyVersion

if ($null -eq $InstalledAuthProxyVersion) {
    exit 1  #Nothing further to do without Duo installed
} else {
    #Then see what the newest version available for download is
    Write-Host 'Checking latest AuthProxy version available for download...'
    $LatestAuthProxyVersion = Get-LatestAuthProxyVersion

    #Compare installed version to latest available version
    if ($null -eq $LatestAuthProxyVersion) {
        Write-warn -message "Unable to determine if the installed AuthProxy version $InstalledAuthProxyVersion is up to date."
    } elseif ($InstalledAuthProxyVersion -ne $LatestAuthProxyVersion) {
        Write-warn -message "Installed version $InstalledAuthProxyVersion needs update to $LatestAuthProxyVersion."
        $RemediationNeeded["UpdateNeeded"] = $true
    } else {
        Write-ok "Installed version $InstalledAuthProxyVersion is up to date."
    }

    #Determine the correct path of the AuthProxy configuration file. Quit if not found
    Write-Host 'Checking authproxy.cfg file...'
    $ConfigFileLocation = Find-DuoAuthProxyConfigFile
    if ($null -eq $ConfigFileLocation) {
        exit 1  #Nothing further to do without the config file
    } else {
        #Config file found, start looking for common (auto-fixable) issues
        $RemediationNeeded["ExtraFiles"] = Find-ExtraFiles($ConfigFileLocation)
        $RemediationNeeded["BadFailmode"] = Find-Failmodes($ConfigFileLocation)
        $RemediationNeeded["EncryptionNeeded"] = Find-PlaintextSecrets($configFileLocation)
    }
}

#Now that we've determined whether there are any issues, check if any autofix requests apply
$AutoFixApplies = $false                    #Assume no autofixes are applicable
if ($AutoFix.ContainsValue($true)) {        #If autofix(es) requested,
    $AutoFix.keys | foreach-object {        #Look at each possible autofix-able value
        #If a particular autofix was requested and that same problem was actually found,
        if (($RemediationNeeded[$_] -eq $true) -and ($AutoFix[$_] -eq $RemediationNeeded[$_])) {
            #Then we know we should attempt fixes
            $AutoFixApplies = $true
        }
    }
}

#If we need to attempt any autofixes, start by assuming the Duo service will not need to be restarted
if ($AutoFixApplies) {
    $ServiceRestartNeeded = $false

    write-host "`r`n----------`r`n"
    Write-Host 'Automatic fix(es) applied:'

    #Re-check whether remediation is still needed after trying to fix each applicable issue
    if ($RemediationNeeded['ExtraFiles'] -and $AutoFix['ExtraFiles']) {
        $RemediationNeeded['ExtraFiles'] = Repair-ExtraFiles($ConfigFileLocation)
    }
    if ($RemediationNeeded['BadFailmode'] -and $AutoFix['BadFailmode']) {
        $RemediationNeeded['BadFailmode'] = Repair-BadFailmode($ConfigFileLocation)
        $ServiceRestartNeeded = $true #Service restart needed due to changes to the config file
    }
    if ($RemediationNeeded['EncryptionNeeded'] -and $AutoFix['EncryptionNeeded']) {
        $RemediationNeeded['EncryptionNeeded'] = Repair-EncryptionNeeded($ConfigFileLocation)
        $ServiceRestartNeeded = $true #Service restart needed due to changes to the config file
    }
    if ($RemediationNeeded['UpdateNeeded'] -and $AutoFix['UpdateNeeded']) {
        $RemediationNeeded['UpdateNeeded'] = Repair-UpdateNeeded
    }
    if ($ServiceRestartNeeded) {$ServiceRestartNeeded = Restart-DuoService}
}

#Notify engineer of any outstanding manual remediation steps needed
if (($RemediationNeeded.ContainsValue($true)) -or ($ServiceRestartNeeded)) {
    write-host "`r`n----------`r`n"
    Write-host 'Follow-up action(s) needed:'

    if ($RemediationNeeded['UpdateCheckFailed']) {Write-warn 'Please check AuthProxy for latest version available at duo.com.'}
    if ($RemediationNeeded['ExtraFiles']) {Write-warn 'Please remove extra config files from the conf directory.'}
    if ($RemediationNeeded['BadFailmode']) {Write-warn 'Please ensure failmodes are set to "secure" and restart the Duo service.'}
    if ($RemediationNeeded['EncryptionNeeded']) {Write-warn 'Please remove any commented plaintext secrets and/or run "authproxy_passwd.exe --whole-config -y", then restart the Duo service.'}
    if ($RemediationNeeded['UpdateNeeded']) {Write-warn 'Please schedule a time to update the AuthProxy to the latest version.'}
    if ($ServiceRestartNeeded) {Write-warn 'Please ensure the DuoAuthProxy service has restarted.'}
}