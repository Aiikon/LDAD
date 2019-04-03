Function Get-LDADUser
{
    Param
    (
        [Parameter(ValueFromPipeline=$true, Position=0)] [object] $InputObject,
        [Parameter(ValueFromPipelineByPropertyName=$true)] [Alias('Username')] [string] $SamAccountName,
        [Parameter(ValueFromPipelineByPropertyName=$true)] [string] $Domain,
        [Parameter()] [string] $Context,
        [Parameter()] [string] $GivenName,
        [Parameter()] [string] $Surname,
        [Parameter()] [switch] $ShowDN,
        [Parameter()] [switch] $GetNames,
        [Parameter()] [switch] $GetPwd,
        [Parameter()] [switch] $GetOrg,
        [Parameter()] [switch] $GetMail,
        [Parameter()] [switch] $GetIds,
        [Parameter()] [switch] $ListAll,
        [Parameter()] [System.Management.Automation.PSCredential] $Credential
    )
    Begin
    {
        $mailList = @{}
        $userNameList = @{}
        $domainNameList = @{}
        $inputObjectList = New-Object System.Collections.Generic.List[object]
    }
    Process
    {
        if ($InputObject -is [string])
        {
            if ($InputObject -like '*@*') { $mailList.$InputObject = $null }
            else { $userNameList.$InputObject = $null }
        }
        elseif ($SamAccountName)
        {
            $userNameList.$SamAccountName = $null
        }
        if ($Domain) { $domainNameList.$Domain = $null }
        $inputObjectList.Add($InputObject)
    }
    End
    {
        if ($domainNameList.Keys.Count -gt 1)
        {
            [void]$PSBoundParameters.Remove('InputObject')
            [void]$PSBoundParameters.Remove('Domain')
            [void]$PSBoundParameters.Remove('SamAccountName')

            $inputObjectList | Group-Object Domain | ForEach-Object {              
                $_.Group | Get-LDADUser @PSBoundParameters
            }
            return
        }

        $count = 0 + $mailList.Keys.Count + $userNameList.Keys.Count

        if ($count -eq 0 -and -not $GivenName -and -not $Surname -and -not $ListAll.IsPresent) {
            throw "One or more input must be provided." }

        if (!$Domain) { $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name }
        if ($Domain -notlike $env:USERDNSDOMAIN -and -not $Credential) { $Credential = Get-WFCredential $Domain Server }
        if (!$Context) { $Context = Get-LDADDefaultContext $Domain $Credential }

        $filterList = @()

        $filterList += ($mailList.Keys | Get-LdapFilter 'mail')
        $filterList += ($userNameList.Keys | Get-LdapFilter 'samaccountname')
        $filterList += ($GivenName | Get-LdapFilter 'givenname')
        $filterList += ($Surname | Get-LdapFilter 'sn')

        $filterLdap = $filterList | Where-Object { $_ }
        $filterLdap = $filterLdap -join ""
        $filterLdap = "(&(objectCategory=person)(objectClass=user)$filterLdap)"


        $propertyList = 'cn', 'distinguishedName', 'userAccountControl', 'sAMAccountName', 'description'

        $userTemplate = New-Object 'System.Object'
        $userTemplate | Add-Member NoteProperty CN ''
        $userTemplate | Add-Member NoteProperty OU ''
        $userTemplate | Add-Member NoteProperty IsEnabled $false
        $userTemplate | Add-Member NoteProperty SamAccountName ''

        if ($GetNames)
        {
            $propertyList += @('displayName', 'givenName', 'sn')
            $userTemplate | Add-Member NoteProperty DisplayName $null
            $userTemplate | Add-Member NoteProperty GivenName $null
            $userTemplate | Add-Member NoteProperty Surname $null
        }

        if ($GetPwd)
        {
            $propertyList += @('pwdLastSet')
            $userTemplate | Add-Member NoteProperty PasswordLastSet $null
            $userTemplate | Add-Member NoteProperty PasswordNeverExpires $null
        }

        if ($GetOrg)
        {
            $propertyList += @('title', 'department', 'manager')

            $userTemplate | Add-Member NoteProperty Title $null
            $userTemplate | Add-Member NoteProperty Department $null
            $userTemplate | Add-Member NoteProperty ManagerDN $null
        }

        if ($GetMail)
        {
            $propertyList += @('mail', 'proxyAddresses')

            $userTemplate | Add-Member NoteProperty Email $null
            $userTemplate | Add-Member NoteProperty ProxyAddresses $null
        }

        if ($GetIds)
        {
            $propertyList += 'objectSid', 'objectGUID', 'userPrincipalName'

            $userTemplate | Add-Member NoteProperty Sid $null
            $userTemplate | Add-Member NoteProperty Guid $null
            $userTemplate | Add-Member NoteProperty UserPrincipalName $null
        }

        if ($ShowDN)
        {
            $userTemplate | Add-Member NoteProperty DistinguishedName ''
        }
        $userTemplate | Add-Member NoteProperty Domain $Domain


        $searcher = Get-LDADSearcher -Domain $Domain -Context $Context -Credential $Credential `
            -Filter $filterLdap -Properties $propertyList


        foreach ($result in $searcher.FindAll())
        {
            $userRecord = $userTemplate | Select-Object *
            $userRecord.CN = $result.Properties['cn'][0]
            $userRecord.OU = $result.Properties['distinguishedname'][0] -replace "(CN=.+?)(OU=|CN=)", '$2'
            
            if ($ShowDN)
            {
                $userRecord.DistinguishedName = $result.Properties['distinguishedname'][0]
            }
            
            $userRecord.IsEnabled = !(($result.Properties['useraccountcontrol'][0] -bor 2) -eq $result.Properties['useraccountcontrol'][0])
            $userRecord.SamAccountName = $result.Properties['samaccountname'] | Select-Object -First 1

            if ($GetNames)
            {
                $userRecord.DisplayName = $result.Properties['displayname'] | Select-Object -First 1
                $userRecord.GivenName = $result.Properties['givenname'] | Select-Object -First 1
                $userRecord.Surname = $result.Properties['sn'] | Select-Object -First 1
            }

            if ($GetPwd)
            {
                $pwdLastSet = $result.Properties['pwdlastset'] | Select-Object -First 1
                if ($pwdLastSet)
                {
                    $userRecord.PasswordLastSet = [DateTime]::FromFileTimeUtc($pwdLastSet)
                }
                $userRecord.PasswordNeverExpires = (($result.Properties['useraccountcontrol'][0] -bor 65536) -eq $result.propertyList['useraccountcontrol'][0])
            }

            if ($GetOrg)
            {
                $userRecord.Title = $result.Properties['title'] | Select-Object -First 1
                $userRecord.Department = $result.Properties['department'] | Select-Object -First 1
                $userRecord.ManagerDN = $result.Properties['manager'] | Select-Object -First 1
            }

            if ($GetMail)
            {
                $userRecord.Email = $result.Properties['mail'] | Select-Object -First 1
                $userRecord.ProxyAddresses = $result.Properties['proxyaddresses'] | Select-Object
            }

            if ($GetIds)
            {
                $userRecord.Sid = & $script:ConvertLdapSidToString ($result.Properties['objectsid'] | Select-Object -First 1)
                $userRecord.Guid = & $script:ConvertLdapGuidToGuid @($result.Properties['objectguid'] | Select-Object -First 1)
                $userRecord.UserPrincipalName = $result.Properties['userprincipalname'] | Select-Object -First 1
            }

            $userRecord
        }
    }
}

Function Get-LDADGroup
{
    Param
    (
        [Parameter(ValueFromPipeline=$true)] [object] $InputObject,
        [Parameter(ValueFromPipelineByPropertyName=$true, Position=0)]
            [Alias('Group')] [string] $GroupName,
        [Parameter(ValueFromPipelineByPropertyName=$true)] [string] $DistinguishedName,
        [Parameter(ValueFromPipelineByPropertyName=$true)] [string] $CN,
        [Parameter(ValueFromPipelineByPropertyName=$true)] [string] $OU,
        [Parameter(ValueFromPipelineByPropertyName=$true)] [string] $Domain,
        [Parameter()] [string]$Context,
        [Parameter()] [System.Management.Automation.PSCredential]$Credential,
        [Parameter()] [switch] $ShowDN,
        [Parameter()] [switch] $GetType,
        [Parameter()] [switch] $GetIds,
        [Parameter()] [switch] $GetMemberOf,
        [Parameter()] [switch] $GetMembers
    )
    Begin
    {
        $groupNameList = @{}
        $distinguishedNameList = @{}
        $domainNameList = @{}
        $inputObjectList = New-Object System.Collections.Generic.List[object]
    }
    Process
    {
        if ($InputObject -is [string]) { $groupNameList.$InputObject = $null }
        elseif ($GroupName) { $groupNameList.$GroupName = $null }
        elseif ($DistinguishedName) { $distinguishedNameList.$DistinguishedName = $null }
        elseif ($CN -and $OU) { $distinguishedNameList."CN=$CN,$OU" = $null }
        if ($Domain) { $domainNameList.$Domain = $null }
        $inputObjectList.Add($InputObject)
    }
    End
    {
        if ($domainNameList.Keys.Count -gt 1)
        {
            [void]$PSBoundParameters.Remove('InputObject')
            [void]$PSBoundParameters.Remove('Domain')
            [void]$PSBoundParameters.Remove('CN')
            [void]$PSBoundParameters.Remove('OU')
            [void]$PSBoundParameters.Remove('DistinguishedName')
            [void]$PSBoundParameters.Remove('GroupName')

            $inputObjectList | Group-Object Domain | ForEach-Object {
                $_.Group | Get-LDADGroup @PSBoundParameters
            }
            return
        }

        $inputCount = 0 + $groupNameList.Keys.Count + $distinguishedNameList.Keys.Count
        if ($PSCmdlet.MyInvocation.ExpectingInput -and -not $inputCount) { return }

        if (!$Domain) { $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name }
        if ($Domain -notlike $env:USERDNSDOMAIN -and -not $Credential) { $Credential = Get-WFCredential $Domain Server }
        if (!$Context) { $Context = Get-LDADDefaultContext $Domain $Credential }

        $properties = 'cn', 'description', 'distinguishedName', 'sAMAccountName'

        $groupTemplate = New-Object System.Object
        $groupTemplate | Add-Member NoteProperty CN ''
        $groupTemplate | Add-Member NoteProperty OU ''
        $groupTemplate | Add-Member NoteProperty Description ''
        $groupTemplate | Add-Member NoteProperty SamAccountName ''
        if ($GetType)
        {
            $properties += 'groupType'

            $groupTemplate | Add-Member NoteProperty GroupType 'Distribution'
            $groupTemplate | Add-Member NoteProperty GroupScope 'Global'
        }
        if ($GetMemberOf)
        {
            $properties += 'memberOf'
            $groupTemplate | Add-Member NoteProperty MemberOf @()
        }
        if ($GetMembers)
        {
            $properties += 'member'
            $groupTemplate | Add-Member NoteProperty Members @()
            $groupTemplate | Add-Member NoteProperty MemberCount @()
        }

        if ($GetIds)
        {
            $properties += 'objectSid', 'objectGUID'

            $groupTemplate | Add-Member NoteProperty Sid $null
            $groupTemplate | Add-Member NoteProperty Guid $null
        }

        if ($ShowDN)
        {
            $groupTemplate | Add-Member NoteProperty DistinguishedName ''
        }

        $filterList = @()

        $filterList += ($groupNameList.Keys | Get-LdapFilter 'samAccountName')
        $filterList += ($distinguishedNameList.Keys | Get-LdapFilter 'member')

        $filterLdap = $filterList | Where-Object { $_ }
        $filterLdap = $filterLdap -join ""
        $filterLdap = "(&(objectCategory=group)$filterLdap)"

        $searcher = Get-LDADSearcher -Domain $Domain -Context $Context -Credential $Credential `
            -Filter $filterLdap -Properties $properties

        $groupTemplate | Add-Member NoteProperty Domain $Domain
        foreach ($result in $searcher.FindAll())
        {
            $groupRecord = $groupTemplate | Select-Object *
            $groupRecord.CN = $result.Properties['cn'][0]
            $groupRecord.OU = $result.Properties['distinguishedname'][0] -replace "(CN=.+?)(OU=|CN=)", '$2'
            $groupRecord.Description = $result.Properties['description'] | Select-Object -First 1
            $groupRecord.SamAccountName = $result.Properties['samaccountname'][0]

            if ($ShowDN)
            {
                $groupRecord.DistinguishedName = $result.Properties['distinguishedname'][0]
            }

            if ($GetMemberOf)
            {
                $groupRecord.MemberOf = $result.Properties['memberof'] | Select-Object
            }

            if ($GetMembers)
            {
                $groupRecord.Members = $result.Properties['member'] | Select-Object
                $groupRecord.MemberCount = $groupRecord.Members | Measure-Object |
                    Select-Object -ExpandProperty Count
            }

            if ($GetType)
            {
                $isSecurity = (($result.Properties['grouptype'][0] -bor 2147483648) -eq $result.Properties['grouptype'][0])
                if ($isSecurity) { $groupRecord.GroupType = 'Security' }

                if (($result.Properties['grouptype'][0] -bor 4) -eq $result.Properties['grouptype'][0])
                {
                    $groupRecord.GroupScope = 'DomainLocal'
                }
                elseif (($result.Properties['grouptype'][0] -bor 8) -eq $result.Properties['grouptype'][0])
                {
                    $groupRecord.GroupScope = 'Universal'
                }
            }

            if ($GetIds)
            {
                $groupRecord.Sid = & $script:ConvertLdapSidToString ($result.Properties['objectsid'] | Select-Object -First 1)
                $groupRecord.Guid = & $script:ConvertLdapGuidToGuid @($result.Properties['objectguid'] | Select-Object -First 1)
            }

            $groupRecord
        }



    }
}

Function Join-LDADGroup
{
    Param
    (
        [Parameter(ValueFromPipeline=$true)] [object] $InputObject,
        [Parameter()] [switch] $GetType,
        [Parameter()] [switch] $GetIds,
        [Parameter()] [switch] $GetMemberOf,
        [Parameter()] [switch] $GetMembers
    )
    Begin
    {
        $inputList = New-Object System.Collections.Generic.List[object]
    }
    Process
    {
        $inputList.Add($InputObject)
    }
    End
    {
        $getArgs = @{}
        if ($GetType.IsPresent) { $getArgs.GetType = $true }
        if ($GetIds.IsPresent) { $getArgs.GetIds = $true }
        if ($GetMemberOf.IsPresent) { $getArgs.GetMemberOf = $true }
        if ($GetMembers.IsPresent) { $getArgs.GetMembers = $true }

        $propertyList = $inputList | Select-Object -First 1 | Get-PropertyName

        if ('GroupName' -iin $propertyList -or 'Group' -iin $propertyList)
        {
            $property = $propertyList | Where-Object { $_ -in 'GroupName', 'Group' } |
                Select-Object -First 1
            $rightList = $inputList | Get-LDADGroup @getArgs
            $inputList | Join-List $property $rightList SamAccountName -NoOverwrite
        }
        elseif ('CN' -iin $propertyList -and 'OU' -iin $propertyList)
        {
            $groupRenames = @{
                CN = 'GroupCN'
                OU = 'GroupOU'
                DistinguishedName = 'GroupDistinguishedName'
                SamAccountName = 'GroupSamAccountName'
            }
            $getArgs.GetMembers = $true
            $rightList = $inputList | Get-LDADGroup @getArgs | Rename-Property $groupRenames |
                Expand-Normalized Members
            $inputList |
                Select-Object *, @{Name='DistinguishedName'; Expression={"CN=$($_.CN),$($_.OU)"}} -ErrorAction Ignore |
                Join-List DistinguishedName $rightList Members -NoOverwrite
        }
        else
        {
            Write-Warning "Unrecognized InputObject type for Join-LDADGroup. Passing input."
            $inputList
        }
    }
}

Function Get-LDADComputer
{
    Param
    (
        [Parameter(ValueFromPipeline=$true, Position=0)] [object] $InputObject,
        [Parameter(ValueFromPipelineByPropertyName=$true)] [Alias('Server')] [string] $ComputerName,
        [Parameter(ValueFromPipelineByPropertyName=$true)] [Alias('ServerDomain', 'DomainName')] [string] $Domain,
        [Parameter()] [string] $Context,
        [Parameter()] [System.Management.Automation.PSCredential] $Credential,
        [Parameter()] [switch] $ListAll,
        [Parameter()] [switch] $GetIds,
        [Parameter()] [switch] $ShowDN
    )
    Begin
    {
        $computerNameList = @{}
        $domainNameList = @{}
    }
    Process
    {
        if ($InputObject -is [string])
        {
            $computerNameList.$InputObject = $null
        }
        elseif ($ComputerName)
        {
            $computerNameList.$ComputerName = $null
            if ($Domain)
            {
                if (-not $domainNameList.ContainsKey($Domain)) { $domainNameList.$Domain = @{} }
                $domainNameList.$Domain.$ComputerName = $null
            }
        }
    }
    End
    {
        $count = 0 + $computerNameList.Keys.Count

        if ($count -eq 0 -and -not $ListAll.IsPresent) { throw "One or more input must be provided." }

        if ($domainNameList.Keys.Count -gt 1)
        {
            foreach ($domainName in $domainNameList.Keys)
            {
                $args = @{} + $PSBoundParameters
                if ($args.ContainsKey('InputObject')) { $args.Remove('InputObject') }
                if ($args.ContainsKey('Domain')) { $args.Remove('Domain') }

                $domainNameList.$domainName.Keys | Get-LDADComputer -Domain $domainName @args
            }
            return
        }

        if (!$Domain) { $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name }
        if ($Domain -notlike $env:USERDNSDOMAIN -and -not $Credential) { $Credential = Get-WFCredential $Domain Server }
        if (!$Context) { $Context = Get-LDADDefaultContext $Domain $Credential }

        $filterList = @()

        $filterList += ($computerNameList.Keys | Get-LdapFilter 'cn')

        $filterLdap = $filterList | Where-Object { $_ }
        $filterLdap = $filterLdap -join ""
        $filterLdap = "(&(objectCategory=computer)$filterLdap)"

        $propertyList = 'cn', 'distinguishedName', 'userAccountControl'

        if ($GetIds)
        {
            $propertyList += 'objectSid', 'objectGUID'
        }

        $searcher = Get-LDADSearcher -Domain $Domain -Context $Context -Credential $Credential `
            -Filter $filterLdap -Properties $propertyList

        foreach ($result in $searcher.FindAll())
        {
            $objectRecord = [ordered]@{}
            $objectRecord.CN = $result.Properties['cn'][0]
            $objectRecord.OU = $result.Properties['distinguishedname'][0] -replace "(CN=.+?)(OU=|CN=)", '$2'
            
            if ($ShowDN)
            {
                $objectRecord.DistinguishedName = $result.Properties['distinguishedname'][0]
            }
            
            $objectRecord.IsEnabled = !(($result.Properties['useraccountcontrol'][0] -bor 2) -eq $result.Properties['useraccountcontrol'][0])

            if ($GetIds)
            {
                $objectRecord.Sid = & $script:ConvertLdapSidToString ($result.Properties['objectsid'] | Select-Object -First 1)
                $objectRecord.Guid = & $script:ConvertLdapGuidToGuid @($result.Properties['objectguid'] | Select-Object -First 1)
            }

            $objectRecord.Domain = $Domain

            [pscustomobject]$objectRecord
        }
    }
}

Function Get-LDADContainer
{
    Param
    (
        [Parameter(Position=0)] [string] $Name,
        [Parameter()] [string] $Domain,
        [Parameter()] [string] $Context,
        [Parameter()] [System.Management.Automation.PSCredential] $Credential,
        [Parameter()] [switch] $ShowDN,
        [Parameter()] [switch] $ShowShortPath,
        [Parameter()] [switch] $PassDN,
        [Parameter()] [switch] $IncludeSystem
    )
    End
    {
        if (!$Domain) { $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name }
        if ($Domain -notlike $env:USERDNSDOMAIN -and -not $Credential) { $Credential = Get-WFCredential $Domain Server }
        if (!$Context) { $Context = Get-LDADDefaultContext $Domain $Credential }

        $systemOu = "*CN=System,$Context"

        $filterList = @()
        $filterList += ($Name | Get-LdapFilter 'name')
        $filterLdap = $filterList | Where-Object { $_ }
        $filterLdap = $filterLdap -join ""
        $filterLdap = "(&(|(objectClass=container)(objectClass=organizationalUnit))$filterLdap)"

        $searcher = Get-LDADSearcher -Domain $Domain -Context $Context -Credential $Credential `
            -Filter $filterLdap -Properties 'name', 'distinguishedName', 'objectClass', 'whenCreated'

        foreach ($result in $searcher.FindAll())
        {
            $dn = $result.Properties['distinguishedname'][0]
            if (-not $IncludeSystem.IsPresent -and $dn -like $systemOu) { continue }
            if ($PassDN.IsPresent) { $dn; continue }
            $containerRecord = [ordered]@{}
            $containerRecord.ContainerCN = $result.Properties['name'][0]
            $containerRecord.ContainerOU = $dn -replace "((?:OU|CN)=.+?)(OU=|CN=)", '$2'
            $containerRecord.ContainerType = if ($result.Properties['objectclass'] -contains 'organizationalUnit') { 'OU' } else { 'CN' }
            if ($ShowShortPath.IsPresent) { $containerRecord.ContainerShortPath = ConvertTo-LDADShortPath $dn }
            if ($ShowDN.IsPresent) { $containerRecord.ContainerDN = $dn }
            $containerRecord.Domain = $Domain
            [pscustomobject]$containerRecord
        }
    }
}

Function Get-LDADDomainController
{
    Param
    (
        [Parameter()] [string] $Domain,
        [Parameter()] [string] $Context,
        [Parameter()] [System.Management.Automation.PSCredential] $Credential,
        [Parameter()] [switch] $ShowDN
    )
    End
    {
        if (!$Domain) { $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name }
        if ($Domain -notlike $env:USERDNSDOMAIN -and -not $Credential) { $Credential = Get-WFCredential $Domain Server }
        if (!$Context) { $Context = Get-LDADDefaultContext $Domain $Credential }

        $searcher = Get-LDADSearcher -Domain $Domain -Context $Context -Credential $Credential `
            -Filter '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' `
            -Properties 'cn', 'distinguishedName', 'description'

        foreach ($result in $searcher.FindAll())
        {
            $dcRecord = [ordered]@{}
            $dcRecord.CN = $result.Properties['cn'][0]
            $dcRecord.OU = $result.Properties['distinguishedname'][0] -replace "(CN=.+?)(OU=|CN=)", '$2'
            if ($ShowDN.IsPresent) { $dcRecord.DistinguishedName = $result.Properties['distinguishedname'][0] }
            $dcRecord.Description = $result.Properties['description'] | select -First 1
            $dcRecord.Domain = $Domain
            [pscustomobject]$dcRecord

        }
    }
}

Function Get-LdapFilter
{
    Param
    (
        [Parameter(ValueFromPipeline=$true)] [string] $Value,
        [Parameter(Mandatory=$true, Position=0)] [string] $Field
    )
    Begin
    {
        $valueList = New-Object System.Collections.Generic.List[string]
    }
    Process
    {
        if (-not [string]::IsNullOrWhiteSpace($value)) { $valueList.Add("($Field=$Value)") }
    }
    End
    {
        if ($valueList.Count)
        {
            $filterLdap = $valueList -join ""
            "(|$filterLdap)"
        }
    }
}

Function Get-LDADDefaultContext
{
    Param
    (
        [Parameter(Mandatory=$true)] [string] $Domain,
        [Parameter()] [System.Management.Automation.PSCredential] $Credential,
        [Parameter()] [ValidateSet('defaultnamingcontext', 'configurationnamingcontext', 'schemanamingcontext')]
            [string] $ContextName = 'defaultnamingcontext'
    )
    End
    {
        $defaultNamingContextEntry = $null
        if (!$Domain) { $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name }
        if ($Credential)
        {
            $defaultNamingContextEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain/RootDSE", $Credential.UserName, $Credential.GetNetworkCredential().Password)
        }
        else
        {
            $defaultNamingContextEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain/RootDSE")
        }
        
        $contextValue = $defaultNamingContextEntry.Properties[$ContextName].Value.ToString()
        $contextValue
    }
}

Function Get-LDADSearcher
{
    Param
    (
        [Parameter(Mandatory=$true)] [string] $Domain,
        [Parameter(Mandatory=$true)] [string] $Context,
        [Parameter(Mandatory=$true)] [string] $Filter,
        [Parameter(Mandatory=$true)] [string[]] $Properties,
        [Parameter()] [System.Management.Automation.PSCredential] $Credential
    )
    End
    {
        $ldap = "LDAP://$Domain/$Context"
        $domainEntry = $null
        if ($Credential)
        {
            $domainEntry = New-Object System.DirectoryServices.DirectoryEntry($ldap, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        }
        else
        {
            $domainEntry = New-Object System.DirectoryServices.DirectoryEntry($ldap)
        }
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($domainEntry)
        $searcher.PageSize = 1000
        $searcher.Filter = $Filter
        $Properties | % { [void]$searcher.PropertiesToLoad.Add($_) }

        $searcher
    }
}

Function ConvertTo-LDADShortPath
{
    Param
    (
        [Parameter(Position=0)] [string] $Path
    )
    End
    {
        $splitList = $Path -split ','
        $orgPathList = New-Object System.Collections.Generic.List[string]
        $newSplitList = foreach ($item in $splitList)
        {
            if ($item -match "DC=(.+)")
            {
                $orgPathList.Add($Matches[1])
            }
            elseif ($item -match "OU=(.+)")
            {
                $Matches[1]
            }
            else
            {
                $item
            }
        }

        $orgPath = $orgPathList -join '.'
        [Array]::Reverse($newSplitList)
        @($orgPath) + $newSplitList -join '/'
    }
}
