<# Custom Script for Windows #>
$Computername = $env:COMPUTERNAME
$Username = $config.public.vmLocalUserName 
write-output $Username >> "D:\script.logs"         
$PlainPassword = $config.private.vmLocalUserPassword 
write-output $PlainPassword >> "D:\script.logs"     
$Password = ConvertTo-SecureString $PlainPassword -AsPlainText -Force

#Create User
write-output "Creating User" >> "D:\script.logs"
$ADSIComp = [adsi]"WinNT://$Computername"
$NewUser = $ADSIComp.Children | ? {$_.SchemaClassName -eq 'User' -and $_.Name -eq $Username};
if (!$NewUser) {
  $NewUser = $ADSIComp.Create('User',$Username)
}

#Create password
write-output "Creating password" >> "D:\script.logs"
$BSTR = [system.runtime.interopservices.marshal]::SecureStringToBSTR($Password)
$_password = [system.runtime.interopservices.marshal]::PtrToStringAuto($BSTR)

#Set password on account 
write-output "Set password on account" >> "D:\script.logs"
$NewUser.SetPassword(($_password))
$NewUser.SetInfo()

#Add user to Local Administrators Group
write-output "Add user to Local Administrators Group" >> "D:\script.logs"
$AdminGroup = [ADSI]"WinNT://$Computername/Administrators,group"
$User = [ADSI]"WinNT://$Computername/$Username,user"
if (!($AdminGroup.Members() | ? {$_.Name() -eq $Username})) {
  $AdminGroup.Add($User.Path)
}

#Set account to never expire
write-output "Set account to never expire" >> "D:\script.logs"
$User.UserFlags.value = $user.UserFlags.value -bor 0x10000
$User.CommitChanges()

#Setting logon picture to block colour
write-output "Setting logon picture to block colour" >> "D:\script.logs"
$registryPath = "HKLM:\Software\Policies\Microsoft\Windows\System"
$Name = "DisableLogonBackgroundImage"
$value = "1"
if(!(Test-Path $registryPath)) {
  New-Item -Path $registryPath -Force | Out-Null
  New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
} else {
  New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
}  

#Cleanup 
write-output "Cleanup" >> "D:\script.logs"
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR) 
Remove-Variable Password,BSTR,_password

#Set AutoadminLogin and Run Once
write-output "Set AutoadminLogin and Run Once" >> "D:\script.logs"
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 1 -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoLogonCount -Value 1 -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUserName -Value "$Computername\$Username" -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -Value $PlainPassword -Force
$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
Set-ItemProperty $RunOnceKey "NextRun" "C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -ExecutionPolicy Unrestricted -File $temploc\PostReboot.ps1"

#Remove OneDrive from System Tray
write-output "Remove OneDrive from System Tray" >> "D:\script.logs"
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows' -Name OneDrive -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name DisableFileSyncNGSC -value 1 -Force

#WindowsUpdates Download
write-output "WindowsUpdates Download" >> "D:\script.logs"
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -value 1 -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name AUOptions -value 2 -Force

#Load default registry hive
write-output "Load default registry hive" >> "D:\script.logs"
& reg load HKLM\DEFAULT C:\Users\Default\NTUSER.DAT

#Allow InternetExplorer toolbars when running in InPrivate mode
write-output "Allow InternetExplorer toolbars when running in InPrivate mode" >> "D:\script.logs"
New-Item -Path 'HKLM:\DEFAULT\SOFTWARE\Policies\Microsoft' -Name 'Internet Explorer' -Force
New-Item -Path 'HKLM:\DEFAULT\SOFTWARE\Policies\Microsoft\Internet Explorer' -Name 'Safety' -Force
New-Item -Path 'HKLM:\DEFAULT\SOFTWARE\Policies\Microsoft\Internet Explorer\Safety' -Name 'PrivacIE' -Force
New-ItemProperty -Path 'HKLM:\DEFAULT\SOFTWARE\Policies\Microsoft\Internet Explorer\Safety\PrivacIE' -Name DisableToolbars -Value 0 -PropertyType DWORD -Force

#Disable Balloon Notifications
write-output "Disable Balloon Notifications" >> "D:\script.logs"
New-ItemProperty -Path 'HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name EnableBalloonTips -Value 0 -PropertyType DWORD -Force

#Unload default registry hive
 & reg unload HKLM\DEFAULT
write-output "Unload default registry hive" >> "D:\script.logs" 

#Reboot
write-output "Restart Server" >> "D:\script.logs" 
& shutdown /r /t 30 /f
