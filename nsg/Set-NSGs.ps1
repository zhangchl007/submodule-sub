<#
.DESCRIPTION
    Sets NSG Rules for Network Security Groups
.EXAMPLE
    PS >> .\Set-NSGs.ps1
.NOTES
    AUTHORS: Otto Helweg
    LASTEDIT: February 9, 2021
    VERSION: 1.0.0
    POWERSHELL: Requires version 6
    Update Execution Policy and Modules:
        Set-ExecutionPolicy Bypass -Force
    Login to Azure first:
            Logout-AzAccount
            Login-AzAccount -Subscription "<Azure Subscription>"
            Select-AzSubscription -Subscription "<Azure Subscription>"
    Example:
        .\Set-NSGs.ps1 -Wait -inputFile "Set-NSGs.csv"
#>

param($inputFile)

if (!($inputFile)) {
    $inputFile = "Set-NSGs.csv"
}

$csvContent = Get-Content "./$inputFile"
foreach ($item in $csvContent) {
    $duplicateRule = $false
    $nsgName,$ruleName,$priority,$access,$protocol,$direction,$sourcePrefix,$sourcePort,$destinationPrefix,$destinationPort = $item.Split(",")

    Write-Output "Working on Rule: $nsgName - $ruleName"
    $nsg = Get-AzNetworkSecurityGroup -Name $nsgName

    foreach ($rule in $nsg.SecurityRules) {
        if (($rule.Name -eq $ruleName) -or (($rule.Direction -eq $direction) -and ($rule.Priority -eq $priority))) {
            Write-Output ">> Duplicate Rule Found! Check $ruleName, $direction and $priority"
            $duplicateRule = $true
        }
    }

    if ($duplicateRule -eq $false) {
        Write-Output "> Creating new NSG Rule"

        # Add the inbound security rule.
        $nsg | Add-AzNetworkSecurityRuleConfig -Name $ruleName -Description "Added by PowerShell" -Access $access `
            -Protocol $protocol -Direction $direction -Priority $priority -SourceAddressPrefix $sourcePrefix -SourcePortRange $sourcePort `
            -DestinationAddressPrefix $destinationPrefix -DestinationPortRange $destinationPort

        # Update the NSG.
        $nsg | Set-AzNetworkSecurityGroup
    }
}