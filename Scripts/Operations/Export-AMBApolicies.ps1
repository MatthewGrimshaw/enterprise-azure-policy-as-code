
# clone github repo
git clone https://github.com/anwather/amba-export.git tmp 


Push-Location
Set-Location -Path .\tmp\Definitions

$policyAssignments = Get-ChildItem -Path .\policyAssignments -Recurse -Include *.jsonc
$policyDefinitions = Get-ChildItem -Path .\policyDefinitions -Recurse -Include *.jsonc
$policySetDefinitions = Get-ChildItem -Path .\policySetDefinitions -Recurse -Include *.jsonc

foreach ($policyAssignment in $policyAssignments) {
    $policyAssignmentContent = Get-Content -Path $policyAssignment.FullName
    If(!(Test-Path -Path "..\..\Definitions\policyAssignments\AMBA\$($policyAssignment.BaseName).jsonc")){
        If(!(Test-Path -Path "..\..\Definitions\policyAssignments\AMBA\")){
            New-Item -Path "..\..\Definitions\policyAssignments\AMBA\" -ItemType "directory"
        }
        New-Item -Path "..\..\Definitions\policyAssignments\AMBA\" -Name "$($policyAssignment.BaseName).jsonc" -ItemType "file" -Value $policyAssignmentContent
    } else {
        Write-Host "File $($policyAssignment.BaseName) already exists"
    }
    $policyAssignmentContent | ConvertFrom-Json | ConvertTo-Json -Depth 100 | Out-File -FilePath "..\..\Definitions\policyAssignments\AMBA\$($policyAssignment.BaseName).json"
}

foreach ($policyDefinition in $policyDefinitions) {
    $policyDefinitionContent = Get-Content -Path $policyDefinition.FullName

    $policyDefinition.Directory.Name

    If(!(Test-Path -Path "..\..\Definitions\policyDefinitions\$($policyDefinition.Directory.Name)\$($policyDefinition.BaseName).jsonc")){
        New-Item -Path "..\..\Definitions\policyDefinitions\AMBA\" -Name "$($policyDefinition.BaseName).jsonc" -ItemType "file" -Value $policyDefinitionContent
    } else {
        Write-Host "File $($policyDefinition.BaseName) already exists"
    }
    $policyDefinitionContent | ConvertFrom-Json | ConvertTo-Json -Depth 100 | Out-File -FilePath "..\..\Definitions\policyDefinitions\$($policyDefinition.Directory.Name)$($policyDefinition.BaseName).json"
}


foreach ($policySetDefinition in $policySetDefinitions) {
    $policySetDefinitionContent = Get-Content -Path $policySetDefinition.FullName
    If(!(Test-Path -Path "..\..\Definitions\policySetDefinitions\AMBA\$($policySetDefinition.BaseName).jsonc")){
        If(!(Test-Path -Path "..\..\Definitions\policySetDefinitions\AMBA")){
            New-Item -Path "..\..\Definitions\policySetDefinitions\AMBA\" -ItemType "directory"
        }
        New-Item -Path "..\..\Definitions\policySetDefinitions\AMBA\" -Name "$($policySetDefinition.BaseName).jsonc" -ItemType "file" -Value $policySetDefinitionContent
    } else {
        Write-Host "File $($policySetDefinition.BaseName) already exists"
    }
    $policySetDefinitionContent | ConvertFrom-Json | ConvertTo-Json -Depth 100 | Out-File -FilePath "..\..Definitions\policySetDefinitions\AMBA\$($policySetDefinition.BaseName).json"
}

Pop-Location

Remove-Item -Path .\tmp -Recurse -Force