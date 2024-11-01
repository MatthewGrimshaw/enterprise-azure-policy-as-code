
# clone github repo
git clone https://github.com/anwather/spb-export.git tmp 


Push-Location
Set-Location -Path .\tmp\Definitions

$policyAssignments = Get-ChildItem -Path .\policyAssignments -Recurse -Include *.jsonc
$policySetDefinitions = Get-ChildItem -Path .\policySetDefinitions -Recurse -Include *.jsonc

foreach ($policyAssignment in $policyAssignments) {
    $policyAssignmentContent = Get-Content -Path $policyAssignment.FullName
    If(!(Test-Path -Path "..\..\Definitions\policyAssignments\ALZ\$($policyAssignment.BaseName).jsonc")){
        New-Item -Path "..\..\Definitions\policyAssignments\ALZ\" -Name "$($policyAssignment.BaseName).jsonc" -ItemType "file" -Value $policyAssignmentContent
    } else {
        Write-Host "File $($policyAssignment.BaseName) already exists"
    }
    $policyAssignmentContent | ConvertFrom-Json | ConvertTo-Json -Depth 100 | Out-File -FilePath "..\..\Definitions\policyAssignments\$($policyAssignment.BaseName).json"
}


foreach ($policySetDefinition in $policySetDefinitions) {
    $policySetDefinitionContent = Get-Content -Path $policySetDefinition.FullName
    If(!(Test-Path -Path "..\..\Definitions\policySetDefinitions\ALZ\$($policySetDefinition.BaseName).jsonc")){
        If(!(Test-Path -Path "..\..\Definitions\policySetDefinitions\ALZ\SoverignLandingZones\")){
            New-Item -Path "..\..\Definitions\policySetDefinitions\ALZ\SoverignLandingZones\" -ItemType "directory"
        }
        New-Item -Path "..\..\eDefinitions\policySetDefinitions\ALZ\SoverignLandingZones\" -Name "$($policySetDefinition.BaseName).jsonc" -ItemType "file" -Value $policySetDefinitionContent
    } else {
        Write-Host "File $($policySetDefinition.BaseName) already exists"
    }
    $policySetDefinitionContent | ConvertFrom-Json | ConvertTo-Json -Depth 100 | Out-File -FilePath "..\..Definitions\policySetDefinitions\ALZ\\SoverignLandingZones\$($policySetDefinition.BaseName).json"
}

Pop-Location

Remove-Item -Path .\tmp -Recurse -Force