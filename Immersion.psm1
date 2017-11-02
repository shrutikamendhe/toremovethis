
function Get-SharedKeyLite {
    param (
        [Parameter(Mandatory=$true)][string]    $StorageAccountName,
        [Parameter(Mandatory=$true)][string]    $StorageAccountKey,
        [Parameter(Mandatory=$true)][string]    $Method,
        [Parameter(Mandatory=$true)][uri]       $BlobUrl,
        [Parameter(Mandatory=$true)][hashtable] $Headers
    )

    # SharedKeyLite for Blob Storage
    $signature = . {
        $Method = $Method
        $ContentMd5 = ''  # Not required (not providing MD5)
        $ContentType = '' # Not required (not set)
        $RequestDate = '' # Not required (use x-ms-date in $Headers collection)
        # Note: $Headers sorted lexicographically
        # See: https://msdn.microsoft.com/en-us/library/azure/dd179428.aspx
        $CanonicalizedHeaders = [string]::join("`n", ($headers.Keys | sort | % { "$($_.ToLowerInvariant()):$($headers[$_])" }))
        $CanonicalizedResource = "/$StorageAccountName$($BlobUrl.AbsolutePath)"

        $signature_input = "$Method`n$ContentMd5`n$ContentType`n$RequestDate`n$CanonicalizedHeaders`n$CanonicalizedResource"

        $hasher = New-Object System.Security.Cryptography.HMACSHA256
        $hasher.Key = [Convert]::FromBase64String($StorageAccountKey)
        [Convert]::ToBase64String($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($signature_input)))
    }

    return "SharedKeyLite $($StorageAccountName):$($signature)"
}

<#
    Uploads a blob to Azure Blob Storage

    E.g.
        $response = Upload-AzureBlobFile -StorageAccountName 'mystorageaccount' `
                                         -StorageAccountKey 'mystorageaccountkey' `
                                         -BlobPath 'path/to/the/blob' `
                                         -SourceFile 'path/to/the/file'
#>
function Write-AzureBlobFile {
    param (
        [Parameter(Mandatory = $true)]
        [string] $StorageAccountName,
        
        [Parameter(Mandatory = $true)]
        [string] $StorageAccountKey,

        [Parameter(Mandatory = $true)]
        [string] $BlobPath,

        [Parameter(ParameterSetName='FromSourceFile', Mandatory = $true)]
        [string] $SourceFile,

        [Parameter(ParameterSetName='FromSourceBytes', Mandatory = $true)]
        [byte[]] $SourceBytes
    )

    # See: https://msdn.microsoft.com/en-us/library/azure/dd179428.aspx
    # Note: headers automatically sorted lexicographically below
    $headers = @{
        'x-ms-blob-type' = 'BlockBlob';
        'x-ms-version' = '2015-04-05';
        'x-ms-date' = [datetime]::UtcNow.ToString('R', [System.Globalization.CultureInfo]::InvariantCulture);
    }

    if ($BlobPath.StartsWith('/')) {
        $BlobPath = $BlobPath.Substring(1)
    }

    $uri = [uri] "https://$($StorageAccountName).blob.core.windows.net/$($BlobPath)"

    $headers['Authorization'] = Get-SharedKeyLite -StorageAccountName $StorageAccountName `
                                                  -StorageAccountKey $StorageAccountKey `
                                                  -Method 'PUT' `
                                                  -BlobUrl $uri `
                                                  -Headers $headers

    switch ($PsCmdlet.ParameterSetName) {
        'FromSourceFile'  { Invoke-WebRequest -Method 'PUT' -Uri $uri -Headers $headers -InFile $SourceFile -UseBasicParsing | Out-Null }
        'FromSourceBytes' { Invoke-WebRequest -Method 'PUT' -Uri $uri -Headers $headers -Body $SourceBytes -UseBasicParsing | Out-Null }
    }
}



<#
    Downloads a blob from Azure Blob Storage

    E.g.
        $response = Download-AzureBlobFile -StorageAccountName 'mystorageaccount' `
                                           -StorageAccountKey 'mystorageaccountkey' `
                                           -BlobPath 'path/to/the/blob'
#>
function Read-AzureBlobFile {
    param (
        [Parameter(Mandatory = $true)]
        [string] $StorageAccountName,
        
        [Parameter(Mandatory = $true)]
        [string] $StorageAccountKey,

        [Parameter(Mandatory = $true)]
        [string] $BlobPath,

        [Parameter(ParameterSetName='ToFile')]
        [string] $OutFile
    )

    if ($BlobPath.StartsWith('/')) {
        $BlobPath = $BlobPath.Substring(1)
    }

    $uri = [uri] "https://$($StorageAccountName).blob.core.windows.net/$($BlobPath)"

    # See: https://msdn.microsoft.com/en-us/library/azure/dd179428.aspx
    # Note: headers automatically sorted lexicographically below
    $headers = @{
        'x-ms-date' = [datetime]::UtcNow.ToString('R', [System.Globalization.CultureInfo]::InvariantCulture);
        'x-ms-version' = '2015-04-05';
    }

    $headers['Authorization'] = Get-SharedKeyLite -StorageAccountName $StorageAccountName `
                                                  -StorageAccountKey $StorageAccountKey `
                                                  -Method 'GET' `
                                                  -BlobUrl $uri `
                                                  -Headers $headers

    switch ($PsCmdlet.ParameterSetName) {
        'ToFile' { Invoke-WebRequest -Method 'GET' -Uri $uri -Headers $headers -OutFile $OutFile | Out-Null }
        default  { Invoke-WebRequest -Method 'GET' -Uri $uri -Headers $headers | Select -Expand Content }
    }
}

<#
    Downloads and installs the Immersion Guide app.
#>
function Install-GuideApp {
    param (
        [Parameter(Mandatory = $true)]
        [string] $StorageAccountName,
        
        [Parameter(Mandatory = $true)]
        [string] $StorageAccountKey
    )

    # Download the Guide application
    Add-Type -AssemblyName 'System.IO.Compression.FileSystem'

    $guide_directory = "$env:SystemDrive\Guide"
    If (!(Test-Path $guide_directory)) {New-Item $guide_directory -Type Directory}

    $guide_source_uri = "https://immteststorage.blob.core.windows.net/deployment/Guide.zip?sv=2015-04-05&sr=b&sig=CQSKDsrMO1dnNGmUt8eI3lok1dLNfAtsi57IUQJiZWQ%3D&spr=https&st=2016-07-05T04%3A35%3A08Z&se=2018-07-05T04%3A35%3A08Z&sp=r"
    $guide_package = "$env:SystemDrive\Guide\Guide.zip"
    (New-Object System.Net.WebClient).DownloadFile($guide_source_uri, $guide_package)

    if ((Test-Path $guide_package)) {
        [System.IO.Compression.ZipFile]::ExtractToDirectory($guide_package, $guide_directory)
    }

    # Write out application startup configuration
    $startup_config = @{
        PrimaryStorageAccountName = $StorageAccountName;
        PrimaryStorageAccountKey = $StorageAccountKey;
    }

    $startup_config | ConvertTo-Json | Out-File -Encoding UTF8 "$guide_directory\app.startup.json"

    # Create desktop shortcut/autolaunch shortcuts
    $shortcut_name = "Immersion Hands-on Lab.lnk"

    # Public/Desktop
    $shell = New-Object -ComObject ("WScript.Shell")
    $shortcut = $shell.CreateShortcut((join-path "C:\Users\Public\Desktop\" $shortcut_name))
    $shortcut.TargetPath = "$guide_directory\ImmersionGuide.exe"
    $shortcut.WorkingDirectory = $guide_directory;
    $shortcut.IconLocation = 'ImmersionGuide.exe, 0';
    $shortcut.Description = 'Launch the Immersion Hands-on Lab Guide';
    $shortcut.Save()

    # Public/Start Menu/Programs/Startup
    $shortcut = $shell.CreateShortcut((join-path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\" $shortcut_name))
    $shortcut.TargetPath = "$guide_directory\ImmersionGuide.exe"
    $shortcut.WorkingDirectory = $guide_directory;
    $shortcut.IconLocation = 'ImmersionGuide.exe, 0';
    $shortcut.Description = 'Launch the Immersion Hands-on Lab Guide';
    $shortcut.Save()
}

function Get-CustomScriptConfig {
    $config = (ConvertFrom-Json (Get-Content 'C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.8\RuntimeSettings\0.settings' -Raw)).runtimeSettings[0].handlerSettings

    $public = $config.publicSettings
    $private = $null

    if ($config.protectedSettings) {
        Add-Type -AssemblyName System.Security
        $cm = New-Object System.Security.Cryptography.Pkcs.EnvelopedCms

        $cert = Get-ChildItem Cert:\LocalMachine\My | ? {$_.Thumbprint -eq $config.protectedSettingsCertThumbprint}
        $cm.Decode([Convert]::FromBase64String($config.protectedSettings))    
        $cm.Decrypt($cert)

        $private = ConvertFrom-Json ([Text.Encoding]::UTF8.GetString($cm.ContentInfo.Content))
    }

    @{'public' = $public; 'private' = $private}
}

function Get-FileFromUri {
    param (
        [Parameter(Mandatory = $true)]
        [string]$TempLoc,
        [Parameter(Mandatory = $true)]
        [string]$FileUri
    )

    $uri = New-Object System.Uri $FileUri
    $file = Join-Path $TempLoc ($uri.Segments[$uri.Segments.Length - 1])

    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile($FileUri, $file)

    $file
}

function Invoke-CustomScript {
    $testFile = "$env:SystemDrive\immersion"
    if (Test-Path $testFile) {
        return;
    }

    $config = Get-CustomScriptConfig    

    $tempLoc = 'D:\Temp'
    if (!(Test-Path $tempLoc)) {New-Item $tempLoc -Type Directory}

    $config.public.otherFileUris | ? {-not [string]::IsNullOrEmpty($_)} | % {Get-FileFromUri -TempLoc $tempLoc -FileUri $_} | Out-Null
    $scriptFile = Get-FileFromUri -TempLoc $tempLoc -FileUri $config.public.scriptFileUri

    if ($config.public.installGuide) {
        Install-GuideApp -StorageAccountName $config.private.storageAccountName -StorageAccountKey $config.private.storageAccountKey
    }

    New-Item $testFile -Type File

    & $scriptFile
}

Export-ModuleMember -Function Write-AzureBlobFile,Read-AzureBlobFile,Get-CustomScriptConfig,Invoke-CustomScript
