# Try write Immersion sentinel file to allow pending deployments to proceed
write-output "-----Running PostReboot script-----" >> "D:\script.logs"
$temploc = "D:\Temp"
$sentinel_config = Get-Content (Join-Path $tempLoc 'blob_storage_config.json') | ConvertFrom-Json

write-output "sentinel_config statement executed" >> "D:\script.logs"

# Find and import azure blob storage helper module
Get-ChildItem -Recurse -Path 'C:\Packages' -Include 'Immersion.psm1' | Select -First 1 | Import-Module

write-output "Get-ChildItem statement executed" >> "D:\script.logs"

Write-AzureBlobFile -StorageAccountName $sentinel_config.PrimaryStorageAccountName `
                    -StorageAccountKey $sentinel_config.PrimaryStorageAccountKey `
                    -BlobPath "assets/$($sentinel_config.ScriptSentinelFileName)" `
                    -SourceBytes @( 0 )

write-output $sentinel_config.PrimaryStorageAccountName >> "D:\script.logs"
write-output $sentinel_config.PrimaryStorageAccountKey >> "D:\script.logs"
write-output $sentinel_config.ScriptSentinelFileName >> "D:\script.logs"

write-output "Remove Autoadmin login and RunOnce" >> "D:\script.logs"
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 0 -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoLogonCount -Value 0 -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUserName -Value "" -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -Value "" -Force

write-output "-----PostReboot script complete. Rebooting Machin-----" >> "D:\script.logs"

#Force Log off of user
(gwmi win32_operatingsystem -ComputerName .).Win32Shutdown(4)
