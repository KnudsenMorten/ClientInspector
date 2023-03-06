$LogFile = [System.Environment]::GetEnvironmentVariable('TEMP','Machine') + "\ClientInspector.txt"
Start-Transcript -Path $LogFile -IncludeInvocationHeader

$VerbosePreference = "SilentlyContinue"  # Stop, Inquire, Continue, SilentlyContinue

Write-Output ""
Write-Output "***********************************************************************************************"
Write-Output "CLIENT INSPECTOR | SYSTEM | COLLECTION"
Write-Output ""
Write-Output "Support: Morten Knudsen - mok@2linkit.net | 40 178 179"
Write-Output "***********************************************************************************************"
Write-Output ""

<#
    Install-module Az
    Install-module Az.ResourceGraph
#>

##########################################
# VARIABLES (Reference Client)
##########################################

    $TableDcrSchemaCreateUpdateAppId            = "7602a1ec-6234-4275-ac96-ce5fa4589d1a"
    $TableDcrSchemaCreateUpdateAppSecret        = "UWY8Q~5JXY2xmWAoWBYDm_.eKOdVzgJRt6fXpaDY"
    $TenantId                                   = "f0fa27a0-8e7c-4f63-9a77-ec94786b7c9e"

    $ClientLogAnalyticsWorkspaceResourceId      = "/subscriptions/fce4f282-fcc6-43fb-94d8-bf1701b862c3/resourcegroups/rg-logworkspaces/providers/microsoft.operationalinsights/workspaces/log-platform-management-client-p"
    $AzDcrPrefixClient                          = "clt"
    $AzDcrSetLogIngestApiAppPermissionsDcrLevel = $true
    $AzDcrLogIngestServicePrincipalObjectId     = "c093d765-4330-4573-b74e-bc57b5528fa8"
    $AzDcrDceTableCreateFromReferenceMachine    = @("STRV-MOK-DT-02")
    $AzDcrDceTableCreateFromAnyMachine          = $true
    
##########################################
# VARIABLES (normal client)
##########################################

    $LogIngestAppId                             = "41690f07-7646-4ee3-949e-8d810e652d97"
    $LogIngestAppSecret                         = "jLB8Q~0kuRoIs6CLkpzCz5puaIucyYHciPigIcy7"
    $TenantId                                   = "f0fa27a0-8e7c-4f63-9a77-ec94786b7c9e"

    $DceName                                    = "dce-platform-management-client-p"

    $LastRun_RegPath                            = "HKLM:\SOFTWARE\2LINKIT"
    $LastRun_RegKey                             = "ClientInspector_System"

    [datetime]$CollectionTime                   = ( Get-date ([datetime]::Now.ToUniversalTime()) -format "yyyy-MM-ddTHH:mm:ssK" )
    $DNSName                                    = (Get-WmiObject win32_computersystem).DNSHostName +"." + (Get-WmiObject win32_computersystem).Domain
    $ComputerName                               = (Get-WmiObject win32_computersystem).DNSHostName

    $UserLoggedOnRaw = Get-Process -IncludeUserName -Name explorer | Select-Object UserName -Unique
    $UserLoggedOn    = $UserLoggedOnRaw.UserName


############################################################################################################################################
# Help
############################################################################################################################################

<#
    Search for "# MAIN PROGRAM" (without quotation marks) to find the main program
#>

############################################################################################################################################
# FUNCTIONS
############################################################################################################################################

Function CreateUpdate-AzLogAnalyticsCustomLogTableDcr ($TableName, $SchemaSourceObject, $AzLogWorkspaceResourceId, $AzAppId, $AzAppSecret, $TenantId)
{

        <#  TESTING !!

            $AzLogWorkspaceResourceId = $global:MainLogAnalyticsWorkspaceResourceId
            $SchemaSourceObject       = $DataVariable[0]
            $TableName                = $TableName


            # ClientInspector
            $AzLogWorkspaceResourceId = $ClientLogAnalyticsWorkspaceResourceId
            $SchemaSourceObject       = $Schema
            $TableName                = $TableName 
            $AzAppId                  = $TableDcrSchemaCreateUpdateAppId
            $AzAppSecret              = $TableDcrSchemaCreateUpdateAppSecret
            $TenantId                 = $TenantId
        #>

    #--------------------------------------------------------------------------
    # Connection
    #--------------------------------------------------------------------------
        If ( ($AzAppId) -and ($AzAppSecret) -and ($TenantId) )
            {
                $AccessTokenUri = 'https://management.azure.com/'
                $oAuthUri       = "https://login.microsoftonline.com/$($TenantId)/oauth2/token"
                $authBody       = [Ordered] @{
                                               resource = "$AccessTokenUri"
                                               client_id = "$($LogIngestAppId)"
                                               client_secret = "$($LogIngestAppSecret)"
                                               grant_type = 'client_credentials'
                                             }
                $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
                $token = $authResponse.access_token

                # Set the WebRequest headers
                $Headers = @{
                                'Content-Type' = 'application/json'
                                'Accept' = 'application/json'
                                'Authorization' = "Bearer $token"
                            }
            }

    #--------------------------------------------------------------------------
    # LogAnalytics Table check
    #--------------------------------------------------------------------------

        $Table         = $TableName  + "_CL"    # TableName with _CL (CustomLog)

        If ($Table.Length -gt 45)
            {
                write-host "ERROR - Reduce length of tablename, as it has a maximum of 45 characters (current length: $($Table.Length))"
                pause
            }

    #--------------------------------------------------------------------------
    # Creating LogAnalytics Table based upon data source schema
    #--------------------------------------------------------------------------


                $tableBody = @{
                                    properties = @{
                                                    schema = @{
                                                                    name    = $Table
                                                                    columns = @($SchemaSourceObject)
                                                                }
                                                }
                              } | ConvertTo-Json -Depth 10

                # create/update table schema using REST
                $TableUrl = "https://management.azure.com" + $AzLogWorkspaceResourceId + "/tables/$($Table)?api-version=2021-12-01-preview"

                Try
                    {
                        Write-Host ""
                        Write-host "Trying to update existing LogAnalytics table schema for table [ $($Table) ] in "
                        Write-host $AzLogWorkspaceResourceId

                        Invoke-WebRequest -Uri $TableUrl -Method PATCH -Headers $Headers -Body $Tablebody
                    }
                Catch
                    {
                        Try
                            {
                                Write-Host ""
                                Write-Host "LogAnalytics Table doesn't exist .... creating table [ $($Table) ] in"
                                Write-host $AzLogWorkspaceResourceId

                                Invoke-WebRequest -Uri $TableUrl -Method PUT -Headers $Headers -Body $Tablebody
                            }
                        Catch
                            {
                                Write-Host ""
                                Write-Host "Something went wrong .... resetting table [ $($Table) ] in"
                                Write-host $AzLogWorkspaceResourceId

                                Invoke-WebRequest -Uri $TableUrl -Method DELETE -Headers $Headers
                                
                                Start-Sleep -Seconds 10
                                
                                Invoke-WebRequest -Uri $TableUrl -Method PUT -Headers $Headers -Body $Tablebody
                            }
                    }
        
        return
}


Function CreateUpdate-AzDataCollectionRuleLogIngestCustomLog ($SchemaSourceObject, $AzLogWorkspaceResourceId, $DceName, $DcrName, $TableName, $TablePrefix, $AzDcrSetLogIngestApiAppPermissionsDcrLevel, `
                                                              $LogIngestServicePricipleObjectId, $AzAppId, $AzAppSecret, $TenantId)
{

<#   TROUBLESHOOTING

        # Function variables
        $AzLogWorkspaceResourceId                   = $global:MainLogAnalyticsWorkspaceResourceId
        
        # $DceName                                    = $Global:AzDceNameSrvNetworkCloud

        $SchemaSourceObject                         = $DataVariable[0]

        # $TablePrefix                                = $Global:AzDcrPrefixSrvNetworkCloud
        $TablePrefix                                = $AzDcrPrefixClient

        $LogIngestServicePricipleObjectId           = $Global:AzDcrLogIngestServicePrincipalObjectId
        $AzDcrSetLogIngestApiAppPermissionsDcrLevel = $Global:AzDcrSetLogIngestApiAppPermissionsDcrLevel
        $AzAppId                                    = $TableDcrSchemaCreateUpdateAppId
        $AzAppSecret                                = $TableDcrSchemaCreateUpdateAppSecret

        # ClientInspector testing
        $AzLogWorkspaceResourceId                   = $ClientLogAnalyticsWorkspaceResourceId
        $SchemaSourceObject                         = $Schema
        $LogIngestServicePricipleObjectId           = $Global:AzDcrLogIngestServicePrincipalObjectId
        $AzDcrSetLogIngestApiAppPermissionsDcrLevel = $Global:AzDcrSetLogIngestApiAppPermissionsDcrLevel
        $TablePrefix                                = $AzDcrPrefixClient

        $AzAppId                                    = $TableDcrSchemaCreateUpdateAppId
        $AzAppSecret                                = $TableDcrSchemaCreateUpdateAppSecret
        # $DceName 
        # $TenantId
#>

    #--------------------------------------------------------------------------
    # Connection
    #--------------------------------------------------------------------------
        If ( ($AzAppId) -and ($AzAppSecret) -and ($TenantId) )
            {
                $AccessTokenUri = 'https://management.azure.com/'
                $oAuthUri       = "https://login.microsoftonline.com/$($TenantId)/oauth2/token"
                $authBody       = [Ordered] @{
                                               resource = "$AccessTokenUri"
                                               client_id = "$($LogIngestAppId)"
                                               client_secret = "$($LogIngestAppSecret)"
                                               grant_type = 'client_credentials'
                                             }
                $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
                $token = $authResponse.access_token

                # Set the WebRequest headers
                $Headers = @{
                                'Content-Type' = 'application/json'
                                'Accept' = 'application/json'
                                'Authorization' = "Bearer $token"
                            }
            }

    #--------------------------------------------------------------------------
    # Get DCEs from Azure Resource Graph
    #--------------------------------------------------------------------------
        
        If ($DceName)
            {
                If ($global:AzDceDetails)   # global variables was defined. Used to mitigate throttling in Azure Resource Graph (free service)
                    {
                        # Retrieve DCE in scope
                        $DceInfo = $global:AzDceDetails | Where-Object { $_.name -eq $DceName }
                            If (!($DceInfo))
                                {
                                    Write-Output "Could not find DCE with name [ $($DceName) ]"
                                }
                    }
                Else
                    {
                        $AzGraphQuery = @{
                                            'query' = 'Resources | where type =~ "microsoft.insights/datacollectionendpoints" '
                                         } | ConvertTo-Json -Depth 20

                        $ResponseData = @()

                        $AzGraphUri          = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"
                        $ResponseRaw         = Invoke-WebRequest -Method POST -Uri $AzGraphUri -Headers $Headers -Body $AzGraphQuery
                        $ResponseData       += $ResponseRaw.content
                        $ResponseNextLink    = $ResponseRaw."@odata.nextLink"

                        While ($ResponseNextLink -ne $null)
                            {
                                $ResponseRaw         = Invoke-WebRequest -Method POST -Uri $AzGraphUri -Headers $Headers -Body $AzGraphQuery
                                $ResponseData       += $ResponseRaw.content
                                $ResponseNextLink    = $ResponseRaw."@odata.nextLink"
                            }
                        $DataJson = $ResponseData | ConvertFrom-Json
                        $Data     = $DataJson.data

                        # Retrieve DCE in scope
                        $DceInfo = $Data | Where-Object { $_.name -eq $DceName }
                            If (!($DceInfo))
                                {
                                    Write-Output "Could not find DCE with name [ $($DceName) ]"
                                }
                    }
            }

        # DCE ResourceId (target for DCR ingestion)
        $DceResourceId  = $DceInfo.id
        If ($DceInfo)
            {
                Write-Verbose "Found required DCE info using Azure Resource Graph"
                Write-Verbose ""
            }

    #------------------------------------------------------------------------------------------------
    # Getting LogAnalytics Info
    #------------------------------------------------------------------------------------------------
                
        $LogWorkspaceUrl = "https://management.azure.com" + $AzLogWorkspaceResourceId + "?api-version=2021-12-01-preview"
        $LogWorkspaceId = (Invoke-RestMethod -Uri $LogWorkspaceUrl -Method GET -Headers $Headers).properties.customerId
        If ($LogWorkspaceId)
            {
                Write-Verbose "Found required LogAnalytics info"
                Write-Verbose ""
            }
                
    #------------------------------------------------------------------------------------------------
    # Build variables
    #------------------------------------------------------------------------------------------------
        # build variables
        $KustoDefault                               = "source | extend TimeGenerated = now()"
        $StreamNameFull                             = "Custom-" + $TableName + "_CL"

        # streamname must be 52 characters or less
        If ($StreamNameFull.length -gt 52)
            {
                $StreamName                         = $StreamNameFull.Substring(0,52)
            }
        Else
            {
                $StreamName                         = $StreamNameFull
            }

        $DceLocation                                = $DceInfo.location

        # default naming convention, if not specificed
        If ($Dcrname -eq $null)
            {
                $DcrName                            = "dcr-" + $TablePrefix + "-" + $TableName + "_CL"
            }

        $DcrSubscription                            = ($AzLogWorkspaceResourceId -split "/")[2]
        $DcrLogWorkspaceName                        = ($AzLogWorkspaceResourceId -split "/")[-1]
        $DcrResourceGroup                           = "rg-dcr-" + $DcrLogWorkspaceName
        $DcrResourceId                              = "/subscriptions/$($DcrSubscription)/resourceGroups/$($DcrResourceGroup)/providers/microsoft.insights/dataCollectionRules/$($DcrName)"

    #--------------------------------------------------------------------------
    # Create resource group, if missing
    #--------------------------------------------------------------------------

        $Uri = "https://management.azure.com" + "/subscriptions/" + $DcrSubscription + "/resourcegroups/" + $DcrResourceGroup + "?api-version=2021-04-01"

        $CheckRG = Invoke-WebRequest -Uri $Uri -Method GET -Headers $Headers
        If ($CheckRG -eq $null)
            {
                $Body = @{
                            "location" = $DceLocation
                         } | ConvertTo-Json -Depth 5   

                Write-Host "Creating Resource group $($DcrResourceGroup) ... Please Wait !"
                $Uri = "https://management.azure.com" + "/subscriptions/" + $DcrSubscription + "/resourcegroups/" + $DcrResourceGroup + "?api-version=2021-04-01"
                $CreateRG = Invoke-WebRequest -Uri $Uri -Method PUT -Body $Body -Headers $Headers
            }

    #--------------------------------------------------------------------------
    # build initial payload to create DCR for log ingest (api) to custom logs
    #--------------------------------------------------------------------------

        If ($SchemaSourceObject.count -gt 10)
            {
                $SchemaSourceObjectLimited = $SchemaSourceObject[0..10]
            }
        Else
            {
                $SchemaSourceObjectLimited = $SchemaSourceObject
            }


        $DcrObject = [pscustomobject][ordered]@{
                        properties = @{
                                        dataCollectionEndpointId = $DceResourceId
                                        streamDeclarations = @{
                                                                $StreamName = @{
	  				                                                                columns = @(
                                                                                                $SchemaSourceObjectLimited
                                                                                               )
                                                                               }
                                                              }
                                        destinations = @{
                                                            logAnalytics = @(
                                                                                @{ 
                                                                                    workspaceResourceId = $AzLogWorkspaceResourceId
                                                                                    workspaceId = $LogWorkspaceId
                                                                                    name = $DcrLogWorkspaceName
                                                                                 }
                                                                            ) 

                                                        }
                                        dataFlows = @(
                                                        @{
                                                            streams = @(
                                                                            $StreamName
                                                                       )
                                                            destinations = @(
                                                                                $DcrLogWorkspaceName
                                                                            )
                                                            transformKql = $KustoDefault
                                                            outputStream = $StreamName
                                                         }
                                                     )
                                        }
                        location = $DceLocation
                        name = $DcrName
                        type = "Microsoft.Insights/dataCollectionRules"
                    }

    #--------------------------------------------------------------------------
    # create initial DCR using payload
    #--------------------------------------------------------------------------

        Write-Host ""
        Write-host "Creating/updating DCR [ $($DcrName) ] with limited payload"
        Write-host $DcrResourceId

        $DcrPayload = $DcrObject | ConvertTo-Json -Depth 20

        $Uri = "https://management.azure.com" + "$DcrResourceId" + "?api-version=2022-06-01"
        Invoke-WebRequest -Uri $Uri -Method PUT -Body $DcrPayload -Headers $Headers

    #--------------------------------------------------------------------------
    # build full payload to create DCR for log ingest (api) to custom logs
    #--------------------------------------------------------------------------

        $DcrObject = [pscustomobject][ordered]@{
                        properties = @{
                                        dataCollectionEndpointId = $DceResourceId
                                        streamDeclarations = @{
                                                                $StreamName = @{
	  				                                                                columns = @(
                                                                                                $SchemaSourceObject
                                                                                               )
                                                                               }
                                                              }
                                        destinations = @{
                                                            logAnalytics = @(
                                                                                @{ 
                                                                                    workspaceResourceId = $AzLogWorkspaceResourceId
                                                                                    workspaceId = $LogWorkspaceId
                                                                                    name = $DcrLogWorkspaceName
                                                                                 }
                                                                            ) 

                                                        }
                                        dataFlows = @(
                                                        @{
                                                            streams = @(
                                                                            $StreamName
                                                                       )
                                                            destinations = @(
                                                                                $DcrLogWorkspaceName
                                                                            )
                                                            transformKql = $KustoDefault
                                                            outputStream = $StreamName
                                                         }
                                                     )
                                        }
                        location = $DceLocation
                        name = $DcrName
                        type = "Microsoft.Insights/dataCollectionRules"
                    }

    #--------------------------------------------------------------------------
    # create DCR using payload
    #--------------------------------------------------------------------------

        Write-Host ""
        Write-host "Updating DCR [ $($DcrName) ] with full schema"
        Write-host $DcrResourceId

        $DcrPayload = $DcrObject | ConvertTo-Json -Depth 20

        $Uri = "https://management.azure.com" + "$DcrResourceId" + "?api-version=2022-06-01"
        Invoke-WebRequest -Uri $Uri -Method PUT -Body $DcrPayload -Headers $Headers

    #--------------------------------------------------------------------------
    # sleep 10 sec to let Azure Resource Graph pick up the new DCR
    #--------------------------------------------------------------------------

        Write-Host ""
        Write-host "Waiting 10 sec to let Azure sync up so DCR rule can be retrieved from Azure Resource Graph"
        Start-Sleep -Seconds 10

    #--------------------------------------------------------------------------
    # get DCR information using Azure Resource Graph
    #--------------------------------------------------------------------------

        $global:AzDcrDetails = Get-AzDcrListAll -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId

        $DcrRule = $global:AzDcrDetails | where-Object { $_.name -eq $DcrName }
        $DcrRuleId = $DcrRule.id

    #--------------------------------------------------------------------------
    # delegating Monitor Metrics Publisher Rolepermission to Log Ingest App
    #--------------------------------------------------------------------------

        If ($AzDcrSetLogIngestApiAppPermissionsDcrLevel -eq $true)
            {
                Write-Host ""
                Write-host "Setting Monitor Metrics Publisher Role permissions on DCR [ $($DcrName) ]"

                $guid = (new-guid).guid
                $monitorMetricsPublisherRoleId = "3913510d-42f4-4e42-8a64-420c390055eb"
                $roleDefinitionId = "/subscriptions/$($DcrSubscription)/providers/Microsoft.Authorization/roleDefinitions/$($monitorMetricsPublisherRoleId)"
                $roleUrl = "https://management.azure.com" + $DcrRuleId + "/providers/Microsoft.Authorization/roleAssignments/$($Guid)?api-version=2018-07-01"
                $roleBody = @{
                    properties = @{
                        roleDefinitionId = $roleDefinitionId
                        principalId      = $LogIngestServicePricipleObjectId
                        scope            = $DcrRuleId
                    }
                }
                $jsonRoleBody = $roleBody | ConvertTo-Json -Depth 6

                $result = try
                    {
                        Invoke-RestMethod -Uri $roleUrl -Method PUT -Body $jsonRoleBody -headers $Headers -ErrorAction SilentlyContinue
                    }
                catch
                    {
                    }

                $StatusCode = $result.StatusCode
                If ($StatusCode -eq "204")
                    {
                        Write-host "  SUCCESS - data uploaded to LogAnalytics"
                    }
                ElseIf ($StatusCode -eq "RequestEntityTooLarge")
                    {
                        Write-Host "  Error 513 - You are sending too large data - make the dataset smaller"
                    }
                Else
                    {
                        Write-host $result
                    }
            }

        # Sleep 10 sec to let Azure sync up
        Write-Host ""
        Write-host "Waiting 10 sec to let Azure sync up for permissions to replicate"
        Start-Sleep -Seconds 10
        Write-Host ""
}

           
Function Update-AzDataCollectionRuleResetTransformKqlDefault ($DcrResourceId)
{
    #--------------------------------------------------------------------------
    # Variables
    #--------------------------------------------------------------------------

        $DefaultTransformKqlDcrLogIngestCustomLog = "source | extend TimeGenerated = now()"

    #--------------------------------------------------------------------------
    # Connection
    #--------------------------------------------------------------------------
        If ( ($AzAppId) -and ($AzAppSecret) -and ($TenantId) )
            {
                $AccessTokenUri = 'https://management.azure.com/'
                $oAuthUri       = "https://login.microsoftonline.com/$($TenantId)/oauth2/token"
                $authBody       = [Ordered] @{
                                               resource = "$AccessTokenUri"
                                               client_id = "$($LogIngestAppId)"
                                               client_secret = "$($LogIngestAppSecret)"
                                               grant_type = 'client_credentials'
                                             }
                $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
                $token = $authResponse.access_token

                # Set the WebRequest headers
                $Headers = @{
                                'Content-Type' = 'application/json'
                                'Accept' = 'application/json'
                                'Authorization' = "Bearer $token"
                            }
            }

    #--------------------------------------------------------------------------
    # get existing DCR
    #--------------------------------------------------------------------------

        $DcrUri = "https://management.azure.com" + $DcrResourceId + "?api-version=2022-06-01"
        $DCR = Invoke-RestMethod -Uri $DcrUri -Method GET
        $DcrObj = $DCR.Content | ConvertFrom-Json

    #--------------------------------------------------------------------------
    # update payload object
    #--------------------------------------------------------------------------

        $DCRObj.properties.dataFlows[0].transformKql = $DefaultTransformKqlDcrLogIngestCustomLog

    #--------------------------------------------------------------------------
    # update existing DCR
    #--------------------------------------------------------------------------

        Write-host "  Resetting transformKql to default for DCR"
        Write-host $DcrResourceId

        # convert modified payload to JSON-format
        $DcrPayload = $DcrObj | ConvertTo-Json -Depth 20

        # update changes to existing DCR
        $DcrUri = "https://management.azure.com" + $DcrResourceId + "?api-version=2022-06-01"
        $DCR = Invoke-RestMethod -Uri $DcrUri -Method PUT -Body $DcrPayload -Headers $Headers
}

Function Update-AzDataCollectionRuleTransformKql ($DcrResourceId, $transformKql)
{
    #--------------------------------------------------------------------------
    # Connection
    #--------------------------------------------------------------------------
        If ( ($AzAppId) -and ($AzAppSecret) -and ($TenantId) )
            {
                $AccessTokenUri = 'https://management.azure.com/'
                $oAuthUri       = "https://login.microsoftonline.com/$($TenantId)/oauth2/token"
                $authBody       = [Ordered] @{
                                               resource = "$AccessTokenUri"
                                               client_id = "$($LogIngestAppId)"
                                               client_secret = "$($LogIngestAppSecret)"
                                               grant_type = 'client_credentials'
                                             }
                $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
                $token = $authResponse.access_token

                # Set the WebRequest headers
                $Headers = @{
                                'Content-Type' = 'application/json'
                                'Accept' = 'application/json'
                                'Authorization' = "Bearer $token"
                            }
            }

    #--------------------------------------------------------------------------
    # get existing DCR
    #--------------------------------------------------------------------------

        $DcrUri = "https://management.azure.com" + $DcrResourceId + "?api-version=2022-06-01"
        $DCR = Invoke-RestMethod -Uri $DcrUri -Method GET
        $DcrObj = $DCR.Content | ConvertFrom-Json

    #--------------------------------------------------------------------------
    # update payload object
    #--------------------------------------------------------------------------

        $DCRObj.properties.dataFlows[0].transformKql = $transformKql

    #--------------------------------------------------------------------------
    # update existing DCR
    #--------------------------------------------------------------------------

        Write-host "  Updating transformKql for DCR"
        Write-host $DcrResourceId

        # convert modified payload to JSON-format
        $DcrPayload = $DcrObj | ConvertTo-Json -Depth 20

        # update changes to existing DCR
        $DcrUri = "https://management.azure.com" + $DcrResourceId + "?api-version=2022-06-01"
        $DCR = Invoke-RestMethod -Uri $DcrUri -Method PUT -Body $DcrPayload -Headers $Headers
}

Function Update-AzDataCollectionRuleLogAnalyticsCustomLogTableSchema ($SchemaSourceObject, $TableName, $DcrResourceId, $AzLogWorkspaceResourceId)
{

<#

    $SchemaSourceObject         = $DataVariable[0]
    $TableName                  = $CreateUpdateAzLACustomLogTable[0]
    $DcrResourceId              = $DcrResourceId
    $AzLogWorkspaceResourceId   = $global:MainLogAnalyticsWorkspaceResourceId

#>

    #--------------------------------------------------------------------------
    # Connection
    #--------------------------------------------------------------------------
        If ( ($AzAppId) -and ($AzAppSecret) -and ($TenantId) )
            {
                $AccessTokenUri = 'https://management.azure.com/'
                $oAuthUri       = "https://login.microsoftonline.com/$($TenantId)/oauth2/token"
                $authBody       = [Ordered] @{
                                               resource = "$AccessTokenUri"
                                               client_id = "$($LogIngestAppId)"
                                               client_secret = "$($LogIngestAppSecret)"
                                               grant_type = 'client_credentials'
                                             }
                $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
                $token = $authResponse.access_token

                # Set the WebRequest headers
                $Headers = @{
                                'Content-Type' = 'application/json'
                                'Accept' = 'application/json'
                                'Authorization' = "Bearer $token"
                            }
            }

    #--------------------------------------------------------------------------
    # build LogAnalytics Table schema based upon data source
    #--------------------------------------------------------------------------

        $Table         = $TableName  + "_CL"    # TableName with _CL (CustomLog)

        # Build initial hash used for columns for table schema
        $TableSchemaHash = @()

        # Requirement - Add TimeGenerated to array
        $TableSchemaObjHash = @{
                                    name        = "TimeGenerated"
                                    type        = "datetime"
                                    description = ""
                               }
        $TableSchemaHash    += $TableSchemaObjHash

        # Loop source object and build hash for table schema
        $ObjColumns = $SchemaSourceObject[0] | ConvertTo-Json -Depth 100 | ConvertFrom-Json | Get-Member -MemberType NoteProperty
        ForEach ($Column in $ObjColumns)
            {
                $ObjDefinitionStr = $Column.Definition
                        If ($ObjDefinitionStr -like "int*")                                            { $ObjType = "int" }
                    ElseIf ($ObjDefinitionStr -like "real*")                                           { $ObjType = "int" }
                    ElseIf ($ObjDefinitionStr -like "long*")                                           { $ObjType = "long" }
                    ElseIf ($ObjDefinitionStr -like "guid*")                                           { $ObjType = "dynamic" }
                    ElseIf ($ObjDefinitionStr -like "string*")                                         { $ObjType = "string" }
                    ElseIf ($ObjDefinitionStr -like "datetime*")                                       { $ObjType = "datetime" }
                    ElseIf ($ObjDefinitionStr -like "bool*")                                           { $ObjType = "boolean" }
                    ElseIf ($ObjDefinitionStr -like "object*")                                         { $ObjType = "dynamic" }
                    ElseIf ($ObjDefinitionStr -like "System.Management.Automation.PSCustomObject*")    { $ObjType = "dynamic" }

                $TableSchemaObjHash = @{
                                            name        = $Column.Name
                                            type        = $ObjType
                                            description = ""
                                        }
                $TableSchemaHash    += $TableSchemaObjHash
            }

        # build table schema
        $tableBody = @{
                            properties = @{
                                            schema = @{
                                                            name    = $Table
                                                            columns = $TableSchemaHash
                                                        }
                                        }
                      } | ConvertTo-Json -Depth 10


    #--------------------------------------------------------------------------
    # update existing LogAnalytics Table based upon data source schema
    #--------------------------------------------------------------------------

        Write-host "  Updating LogAnalytics table schema for table [ $($Table) ]"
        Write-host ""

        # create/update table schema using REST
        $TableUrl = "https://management.azure.com" + $AzLogWorkspaceResourceId + "/tables/$($Table)?api-version=2021-12-01-preview"
        Invoke-RestMethod -Uri $TableUrl -Method PUT -Headers $Headers -Body $Tablebody

    #--------------------------------------------------------------------------
    # build Dcr schema based upon data source
    #--------------------------------------------------------------------------

        $DcrObjColumns = $SchemaSourceObject[0] | ConvertTo-Json -Depth 100 | ConvertFrom-Json | Get-Member -MemberType NoteProperty
        
        $TableSchemaObject = @()

        # Requirement - Add TimeGenerated to array
        $TableSchemaObj = @{
                                    name        = "TimeGenerated"
                                    type        = "datetime"
                               }
        $TableSchemaObject   += $TableSchemaObj

        
        ForEach ($Column in $DcrObjColumns)
            {
                $ObjDefinitionStr = $Column.Definition
                        If ($ObjDefinitionStr -like "int*")                                            { $ObjType = "int" }
                    ElseIf ($ObjDefinitionStr -like "real*")                                           { $ObjType = "int" }
                    ElseIf ($ObjDefinitionStr -like "long*")                                           { $ObjType = "long" }
                    ElseIf ($ObjDefinitionStr -like "guid*")                                           { $ObjType = "dynamic" }
                    ElseIf ($ObjDefinitionStr -like "string*")                                         { $ObjType = "string" }
                    ElseIf ($ObjDefinitionStr -like "datetime*")                                       { $ObjType = "datetime" }
                    ElseIf ($ObjDefinitionStr -like "bool*")                                           { $ObjType = "boolean" }
                    ElseIf ($ObjDefinitionStr -like "object*")                                         { $ObjType = "dynamic" }
                    ElseIf ($ObjDefinitionStr -like "System.Management.Automation.PSCustomObject*")    { $ObjType = "dynamic" }

                $TableSchemaObj = @{
                                        "name"         = $Column.Name
                                        "type"         = $ObjType
                                    }
                $TableSchemaObject    += $TableSchemaObj
            }

    #--------------------------------------------------------------------------
    # get existing DCR
    #--------------------------------------------------------------------------

        $DcrUri = "https://management.azure.com" + $DcrResourceId + "?api-version=2022-06-01"
        $DCR = Invoke-RestMethod -Uri $DcrUri -Method GET
        $DcrObj = $DCR.Content | ConvertFrom-Json

    #--------------------------------------------------------------------------
    # update schema declaration in Dcr payload object
    #--------------------------------------------------------------------------

        $StreamName = "Custom-" + $TableName + "_CL"
        $DcrObj.properties.streamDeclarations.$StreamName.columns = $TableSchemaObject

    #--------------------------------------------------------------------------
    # update existing DCR
    #--------------------------------------------------------------------------

        # convert modified payload to JSON-format
        $DcrPayload = $DcrObj | ConvertTo-Json -Depth 20

        Write-host "  Updating declaration schema [ $($StreamName) ] for DCR"
        Write-host $DcrResourceId

        # update changes to existing DCR
        $DcrUri = "https://management.azure.com" + $DcrResourceId + "?api-version=2022-06-01"
        $DCR = Invoke-RestMethod -Uri $DcrUri -Method PUT -Body $DcrPayload -Headers $Headers
}


Function Update-AzDataCollectionRuleDceEndpoint ($DcrResourceId, $DceResourceId, $AzAppId, $AzAppSecret, $TenantId)
{
    #--------------------------------------------------------------------------
    # Connection
    #--------------------------------------------------------------------------
        If ( ($AzAppId) -and ($AzAppSecret) -and ($TenantId) )
            {
                $AccessTokenUri = 'https://management.azure.com/'
                $oAuthUri       = "https://login.microsoftonline.com/$($TenantId)/oauth2/token"
                $authBody       = [Ordered] @{
                                               resource = "$AccessTokenUri"
                                               client_id = "$($LogIngestAppId)"
                                               client_secret = "$($LogIngestAppSecret)"
                                               grant_type = 'client_credentials'
                                             }
                $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
                $token = $authResponse.access_token

                # Set the WebRequest headers
                $Headers = @{
                                'Content-Type' = 'application/json'
                                'Accept' = 'application/json'
                                'Authorization' = "Bearer $token"
                            }
            }

    #--------------------------------------------------------------------------
    # get existing DCR
    #--------------------------------------------------------------------------

        $DcrUri = "https://management.azure.com" + $DcrResourceId + "?api-version=2022-06-01"
        $DCR = Invoke-RestMethod -Uri $DcrUri -Method GET
        $DcrObj = $DCR.Content | ConvertFrom-Json

    #--------------------------------------------------------------------------
    # update payload object
    #--------------------------------------------------------------------------

        $DCRObj.properties.dataCollectionEndpointId = $DceResourceId

    #--------------------------------------------------------------------------
    # update existing DCR
    #--------------------------------------------------------------------------

        Write-host "  Updating DCE EndpointId for DCR"
        Write-host $DcrResourceId

        # convert modified payload to JSON-format
        $DcrPayload = $DcrObj | ConvertTo-Json -Depth 20

        # update changes to existing DCR
        $DcrUri = "https://management.azure.com" + $DcrResourceId + "?api-version=2022-06-01"
        $DCR = Invoke-RestMethod -Uri $DcrUri -Method PUT -Body $DcrPayload -Headers $Headers
}

Function Delete-AzLogAnalyticsCustomLogTables ($TableNameLike, $AzLogWorkspaceResourceId, $AzAppId, $AzAppSecret, $TenantId)
{
    #--------------------------------------------------------------------------
    # Connection
    #--------------------------------------------------------------------------
        If ( ($AzAppId) -and ($AzAppSecret) -and ($TenantId) )
            {
                $AccessTokenUri = 'https://management.azure.com/'
                $oAuthUri       = "https://login.microsoftonline.com/$($TenantId)/oauth2/token"
                $authBody       = [Ordered] @{
                                               resource = "$AccessTokenUri"
                                               client_id = "$($LogIngestAppId)"
                                               client_secret = "$($LogIngestAppSecret)"
                                               grant_type = 'client_credentials'
                                             }
                $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
                $token = $authResponse.access_token

                # Set the WebRequest headers
                $Headers = @{
                                'Content-Type' = 'application/json'
                                'Accept' = 'application/json'
                                'Authorization' = "Bearer $token"
                            }
            }


    #--------------------------------------------------------------------------
    # Getting list of Azure LogAnalytics tables
    #--------------------------------------------------------------------------

        Write-host "Getting list of tables in "
        Write-host $AzLogWorkspaceResourceId

        # create/update table schema using REST
        $TableUrl   = "https://management.azure.com" + $AzLogWorkspaceResourceId + "/tables?api-version=2021-12-01-preview"
        $TablesRaw  = Invoke-RestMethod -Uri $TableUrl -Method GET -Headers $Headers
        $Tables     = $TablesRaw.value


    #--------------------------------------------------------------------------
    # Building list of tables to delete
    #--------------------------------------------------------------------------

        # custom Logs only
        $TablesScope = $Tables | where-object { $_.properties.schema.tableType -eq "CustomLog" }
        $TablesScope = $TablesScope  | where-object { $_.properties.schema.name -like $TableNameLike }

    #--------------------------------------------------------------------------
    # Deleting tables
    #--------------------------------------------------------------------------

        If ($TablesScope)
            {
                Write-host "LogAnalytics Resource Id"
                Write-host $AzLogWorkspaceResourceId
                Write-host ""
                Write-host "Table deletions in scope:"
                $TablesScope.properties.schema.name

                $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes","Delete"
                $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No","Cancel"
                $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                $heading = "Delete Azure Loganalytics tables"
                $message = "Do you want to continue with the deletion of the shown tables?"
                $Prompt = $host.ui.PromptForChoice($heading, $message, $options, 1)
                switch ($prompt) {
                                    0
                                        {
                                            ForEach ($TableInfo in $TablesScope)
                                                { 
                                                    $Table = $TableInfo.properties.schema.name
                                                    Write-host "Deleting LogAnalytics table [ $($Table) ] ... Please Wait !"

                                                    $TableUrl = "https://management.azure.com" + $AzLogWorkspaceResourceId + "/tables/$($Table)?api-version=2021-12-01-preview"
                                                    Invoke-RestMethod -Uri $TableUrl -Method DELETE -Headers $Headers
                                                }
                                        }
                                    1
                                        {
                                            Write-Host "No" -ForegroundColor Red
                                        }
                                }
            }
}


Function Delete-AzDataCollectionRules ($DcrNameLike, $AzAppId, $AzAppSecret, $TenantId)
{
    #--------------------------------------------------------------------------
    # Connection
    #--------------------------------------------------------------------------
        If ( ($AzAppId) -and ($AzAppSecret) -and ($TenantId) )
            {
                $AccessTokenUri = 'https://management.azure.com/'
                $oAuthUri       = "https://login.microsoftonline.com/$($TenantId)/oauth2/token"
                $authBody       = [Ordered] @{
                                               resource = "$AccessTokenUri"
                                               client_id = "$($LogIngestAppId)"
                                               client_secret = "$($LogIngestAppSecret)"
                                               grant_type = 'client_credentials'
                                             }
                $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
                $token = $authResponse.access_token

                # Set the WebRequest headers
                $Headers = @{
                                'Content-Type' = 'application/json'
                                'Accept' = 'application/json'
                                'Authorization' = "Bearer $token"
                            }
            }

    #--------------------------------------------------------------------------
    # Getting list of Azure Data Collection Rules using ARG
    #--------------------------------------------------------------------------

        $DCR_Rules_All = @()
        $pageSize = 1000
        $iteration = 0
        $searchParams = @{
                            Query = "Resources `
                                    | where type =~ 'microsoft.insights/datacollectionrules' "
                            First = $pageSize
                            }

        $results = do {
            $iteration += 1
            $pageResults = Search-AzGraph -UseTenantScope @searchParams
            $searchParams.Skip += $pageResults.Count
            $DCR_Rules_All += $pageResults
        } while ($pageResults.Count -eq $pageSize)

    #--------------------------------------------------------------------------
    # Building list of DCRs to delete
    #--------------------------------------------------------------------------

        $DcrScope = $DCR_Rules_All | Where-Object { $_.name -like $DcrNameLike }

    #--------------------------------------------------------------------------
    # Deleting DCRs
    #--------------------------------------------------------------------------

        If ($DcrScope)
            {
                Write-host "Data Collection Rules deletions in scope:"
                $DcrScope.name

                $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes","Delete"
                $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No","Cancel"
                $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                $heading = "Delete Azure Data Collection Rules"
                $message = "Do you want to continue with the deletion of the shown data collection rules?"
                $Prompt = $host.ui.PromptForChoice($heading, $message, $options, 1)
                switch ($prompt) {
                                    0
                                        {
                                            ForEach ($DcrInfo in $DcrScope)
                                                { 
                                                    $DcrResourceId = $DcrInfo.id
                                                    Write-host "  Deleting Data Collection Rules [ $($DcrInfo.name) ] ... Please Wait !"
                                                    Invoke-AzRestMethod -Path ("$DcrResourceId"+"?api-version=2022-06-01") -Method DELETE
                                                }
                                        }
                                    1
                                        {
                                            Write-Host "No" -ForegroundColor Red
                                        }
                                }
            }
}


Function Get-AzDcrDceDetails ($DceName, $DcrName, $AzAppId, $AzAppSecret, $TenantId)
{
    <#  TROUBLESHOOTING

        $DcrName  = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"
        $DceName  = "dce-platform-management-client-p"
    #>

    #--------------------------------------------------------------------------
    # Connection
    #--------------------------------------------------------------------------
        If ( ($AzAppId) -and ($AzAppSecret) -and ($TenantId) )
            {
                $AccessTokenUri = 'https://management.azure.com/'
                $oAuthUri       = "https://login.microsoftonline.com/$($TenantId)/oauth2/token"
                $authBody       = [Ordered] @{
                                               resource = "$AccessTokenUri"
                                               client_id = "$($LogIngestAppId)"
                                               client_secret = "$($LogIngestAppSecret)"
                                               grant_type = 'client_credentials'
                                             }
                $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
                $token = $authResponse.access_token

                # Set the WebRequest headers
                $Headers = @{
                                'Content-Type' = 'application/json'
                                'Accept' = 'application/json'
                                'Authorization' = "Bearer $token"
                            }
            }

    #--------------------------------------------------------------------------
    # Get DCEs from Azure Resource Graph
    #--------------------------------------------------------------------------
        
        If ($DceName)
            {
                If ($global:AzDceDetails)   # global variables was defined. Used to mitigate throttling in Azure Resource Graph (free service)
                    {
                        # Retrieve DCE in scope
                        $DceInfo = $global:AzDceDetails | Where-Object { $_.name -eq $DceName }
                            If (!($DceInfo))
                                {
                                    Write-Output "Could not find DCE with name [ $($DceName) ]"
                                }
                    }
                Else
                    {
                        $AzGraphQuery = @{
                                            'query' = 'Resources | where type =~ "microsoft.insights/datacollectionendpoints" '
                                         } | ConvertTo-Json -Depth 20

                        $ResponseData = @()

                        $AzGraphUri          = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"
                        $ResponseRaw         = Invoke-WebRequest -Method POST -Uri $AzGraphUri -Headers $Headers -Body $AzGraphQuery
                        $ResponseData       += $ResponseRaw.content
                        $ResponseNextLink    = $ResponseRaw."@odata.nextLink"

                        While ($ResponseNextLink -ne $null)
                            {
                                $ResponseRaw         = Invoke-WebRequest -Method POST -Uri $AzGraphUri -Headers $Headers -Body $AzGraphQuery
                                $ResponseData       += $ResponseRaw.content
                                $ResponseNextLink    = $ResponseRaw."@odata.nextLink"
                            }
                        $DataJson = $ResponseData | ConvertFrom-Json
                        $Data     = $DataJson.data

                        # Retrieve DCE in scope
                        $DceInfo = $Data | Where-Object { $_.name -eq $DceName }
                            If (!($DceInfo))
                                {
                                    Write-Output "Could not find DCE with name [ $($DceName) ]"
                                }
                    }
            }

    #--------------------------------------------------------------------------
    # Get DCRs from Azure Resource Graph
    #--------------------------------------------------------------------------

        If ($DcrName)
            {
                If ($global:AzDcrDetails)   # global variables was defined. Used to mitigate throttling in Azure Resource Graph (free service)
                    {
                        # Retrieve DCR in scope
                        $DcrInfo = $global:AzDcrDetails | Where-Object { $_.name -eq $DcrName }
                            If (!($DcrInfo))
                                {
                                    Write-Output "Could not find DCR with name [ $($DcrName) ]"
                                }
                    }
                Else
                    {
                        $AzGraphQuery = @{
                                            'query' = 'Resources | where type =~ "microsoft.insights/datacollectionrules" '
                                         } | ConvertTo-Json -Depth 20

                        $ResponseData = @()

                        $AzGraphUri          = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"
                        $ResponseRaw         = Invoke-WebRequest -Method POST -Uri $AzGraphUri -Headers $Headers -Body $AzGraphQuery
                        $ResponseData       += $ResponseRaw.content
                        $ResponseNextLink    = $ResponseRaw."@odata.nextLink"

                        While ($ResponseNextLink -ne $null)
                            {
                                $ResponseRaw         = Invoke-WebRequest -Method POST -Uri $AzGraphUri -Headers $Headers -Body $AzGraphQuery
                                $ResponseData       += $ResponseRaw.content
                                $ResponseNextLink    = $ResponseRaw."@odata.nextLink"
                            }
                        $DataJson = $ResponseData | ConvertFrom-Json
                        $Data     = $DataJson.data

                        $DcrInfo = $Data | Where-Object { $_.name -eq $DcrName }
                            If (!($DcrInfo))
                                {
                                    Write-Output "Could not find DCR with name [ $($DcrName) ]"
                                }
                    }
            }

    #--------------------------------------------------------------------------
    # values
    #--------------------------------------------------------------------------
        If ( ($DceName) -and ($DceInfo) )
            {
                $DceResourceId                                  = $DceInfo.id
                $DceLocation                                    = $DceInfo.location
                $DceURI                                         = $DceInfo.properties.logsIngestion.endpoint
                $DceImmutableId                                 = $DceInfo.properties.immutableId

                # return / output
                $DceResourceId
                $DceLocation
                $DceURI
                $DceImmutableId
            }

        If ( ($DcrName) -and ($DcrInfo) )
            {
                $DcrResourceId                                  = $DcrInfo.id
                $DcrLocation                                    = $DcrInfo.location
                $DcrImmutableId                                 = $DcrInfo.properties.immutableId
                $DcrStream                                      = $DcrInfo.properties.dataflows.outputStream
                $DcrDestinationsLogAnalyticsWorkSpaceName       = $DcrInfo.properties.destinations.logAnalytics.name
                $DcrDestinationsLogAnalyticsWorkSpaceId         = $DcrInfo.properties.destinations.logAnalytics.workspaceId
                $DcrDestinationsLogAnalyticsWorkSpaceResourceId = $DcrInfo.properties.destinations.logAnalytics.workspaceResourceId
                $DcrTransformKql                                = $DcrInfo.properties.dataFlows[0].transformKql


                # return / output
                $DcrResourceId
                $DcrLocation
                $DcrImmutableId
                $DcrStream
                $DcrDestinationsLogAnalyticsWorkSpaceName
                $DcrDestinationsLogAnalyticsWorkSpaceId
                $DcrDestinationsLogAnalyticsWorkSpaceResourceId
                $DcrTransformKql
            }

        return
}


Function Post-AzLogAnalyticsLogIngestCustomLogDcrDce ($DceURI, $DcrImmutableId, $DcrStream, $Data, $AzAppId, $AzAppSecret, $TenantId)
{

        <#  TROUBLESHOOTING

        $DceUri              = $AzLogAnalyticsCustomLogDetails[0]
        $DcrImmutableId      = $AzLogAnalyticsCustomLogDetails[1]
        $DcrStream           = $AzLogAnalyticsCustomLogDetails[2]
        $Data                = $DataVariable
        $AzAppId             = $Global:AzDcrLogIngestAppId
        $AzAppSecret         = $Global:AzDcrLogIngestAppSecret
        $TenantId            = $Global:TenantId

        # ClientInspector
        $DceUri              = $AzDcrDceDetails[2]
        $DcrImmutableId      = $AzDcrDceDetails[6]
        $DcrStream           = $AzDcrDceDetails[7]
        $Data                = $DataVariable
        $AzAppId             = $LogIngestAppId
        $AzAppSecret         = $LogIngestAppSecret
        $TenantId            = $TenantId
        
        #>

    #--------------------------------------------------------------------------
    # Data check
    #--------------------------------------------------------------------------
        If ($DceURI -and $DcrImmutableId -and $DcrStream -and $Data)
            {
                # Add assembly to upload using http
                Add-Type -AssemblyName System.Web

                #--------------------------------------------------------------------------
                # Obtain a bearer token used to authenticate against the data collection endpoint using Azure App & Secret
                #--------------------------------------------------------------------------

                    $scope       = [System.Web.HttpUtility]::UrlEncode("https://monitor.azure.com//.default")   
                    $bodytoken   = "client_id=$AzAppId&scope=$scope&client_secret=$AzAppSecret&grant_type=client_credentials";
                    $headers     = @{"Content-Type"="application/x-www-form-urlencoded"};
                    $uri         = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
                    $bearerToken = (Invoke-RestMethod -Uri $uri -Method "Post" -Body $bodytoken -Headers $headers).access_token

                    $headers = @{
                                    "Authorization" = "Bearer $bearerToken";
                                    "Content-Type" = "application/json";
                                }

                #--------------------------------------------------------------------------
                # Upload the data using Log Ingesion API using DCE/DCR
                #--------------------------------------------------------------------------
                    
                    # initial variable
                    $indexLoopFrom = 0

                    # calculate size of data (entries)
                    $TotalDataLines = ($Data | Measure-Object).count

                    # calculate number of entries to send during each transfer - log ingestion api limits to max 1 mb per transfer
                    If ($TotalDataLines -gt 1)
                        {
                            $SizeDataSingleEntryJson  = (ConvertTo-Json -Depth 100 -InputObject @($Data[0]) -Compress).length
                            $DataSendAmountDecimal    = (( 1mb - 300Kb) / $SizeDataSingleEntryJson)   # 300 Kb is overhead (my experience !)
                            $DataSendAmount           = [math]::Floor($DataSendAmountDecimal)
                        }
                    Else
                        {
                            $DataSendAmount           = 1
                        }

                    # loop - upload data in batches, depending on possible size & Azure limits 
                    Do
                        {
                            $DataSendRemaining = $TotalDataLines - $indexLoopFrom

                            If ($DataSendRemaining -le $DataSendAmount)
                                {
                                    # send last batch - or whole batch
                                    $indexLoopTo    = $TotalDataLines - 1   # cause we start at 0 (zero) as first record
                                    $DataScopedSize = $Data   # no need to split up in batches
                                }
                            ElseIf ($DataSendRemaining -gt $DataSendAmount)
                                {
                                    # data must be splitted in batches
                                    $indexLoopTo    = $indexLoopFrom + $DataSendAmount
                                    $DataScopedSize = $Data[$indexLoopFrom..$indexLoopTo]
                                }

                            # Convert data into JSON-format
                            $JSON = ConvertTo-Json -Depth 100 -InputObject @($DataScopedSize) -Compress

                            If ($DataSendRemaining -gt 1)    # batch
                                {
                                    write-Output ""
                                    
                                    # we are showing as first record is 1, but actually is is in record 0 - but we change it for gui purpose
                                    Write-Output "  [ $($indexLoopFrom + 1)..$($indexLoopTo + 1) / $($TotalDataLines) ] - Posting data to Loganalytics table [ $($TableName)_CL ] .... Please Wait !"
                                }
                            ElseIf ($DataSendRemaining -eq 1)   # single record
                                {
                                    write-Output ""
                                    Write-Output "  [ $($indexLoopFrom + 1) / $($TotalDataLines) ] - Posting data to Loganalytics table [ $($TableName)_CL ] .... Please Wait !"
                                }

                            $uri = "$DceURI/dataCollectionRules/$DcrImmutableId/streams/$DcrStream"+"?api-version=2021-11-01-preview"

                            $Result = Invoke-WebRequest -Uri $uri -Method POST -Body $JSON -Headers $headers -ErrorAction SilentlyContinue
                            $StatusCode = $Result.StatusCode

                            If ($StatusCode -eq "204")
                                {
                                    Write-host "  SUCCESS - data uploaded to LogAnalytics"
                                }
                            ElseIf ($StatusCode -eq "RequestEntityTooLarge")
                                {
                                    Write-Host "  Error 513 - You are sending too large data - make the dataset smaller"
                                }
                            Else
                                {
                                    Write-host $result
                                }

                            # Set new Fom number, based on last record sent
                            $indexLoopFrom = $indexLoopTo

                        }
                    Until ($IndexLoopTo -ge ($TotalDataLines - 1 ))
            
              # return $result
        }
        Write-host ""
}


Function ValidateFix-AzLogAnalyticsTableSchemaColumnNames ($Data)
{
    <#  TROUBLESHOOTING
        
        $Data = $DataVariable

    #>


    $ProhibitedColumnNames = @("_ResourceId","id","_ResourceId","_SubscriptionId","TenantId","Type","UniqueId","Title")

    Write-host "  Validating schema structure of source data ... Please Wait !"

    #-----------------------------------------------------------------------    
    # Initial check
    $IssuesFound = $false

        # loop through data
        ForEach ($Entry in $Data)
            {
                $ObjColumns = $Entry | Get-Member -MemberType NoteProperty

                ForEach ($Column in $ObjColumns)
                    {
                        # get column name
                        $ColumnName = $Column.Name

                        If ($ColumnName -in $ProhibitedColumnNames)   # phohibited column names
                            {
                                $IssuesFound = $true
                                write-host "  ISSUE - Column name is prohibited [ $($ColumnName) ]"
                            }

                        ElseIf ($ColumnName -like "_*")   # remove any leading underscores - column in DCR/LA must start with a character
                            {
                                $IssuesFound = $true
                                write-host "  ISSUE - Column name must start with character [ $($ColumnName) ]"
                            }
                        ElseIf ($ColumnName -like "*.*")   # includes . (period)
                            {
                                $IssuesFound = $true
                                write-host "  ISSUE - Column name include . (period) - must be removed [ $($ColumnName) ]"
                            }
                        ElseIf ($ColumnName -like "* *")   # includes whitespace " "
                            {
                                $IssuesFound = $true
                                write-host "  ISSUE - Column name include whitespace - must be removed [ $($ColumnName) ]"
                            }
                        ElseIf ($ColumnName.Length -gt 45)   # trim the length to maximum 45 characters
                            {
                                $IssuesFound = $true
                                write-host "  ISSUE - Column length is greater than 45 characters (trimming column name is neccessary)  [ $($ColumnName) ]"
                            }
                    }
            }

    If ($IssuesFound)
        {
            Write-host "  Issues found .... fixing schema structure of source data ... Please Wait !"

            $DataCount  = ($Data | Measure-Object).Count

            $DataVariableQA = @()

            $Data | ForEach-Object -Begin  {
                    $i = 0
            } -Process {

                    # get column names
                    $ObjColumns = $_ | Get-Member -MemberType NoteProperty

                    ForEach ($Column in $ObjColumns)
                        {
                            # get column name
                            $ColumnName = $Column.Name

                            If ($ColumnName -in $ProhibitedColumnNames)   # phohibited column names
                                {
                                    $UpdColumn  = $ColumnName + "_"
                                    $ColumnData = $_.$ColumnName
                                    $_ | Add-Member -MemberType NoteProperty -Name $UpdColumn -Value $ColumnData -Force
                                    $_.PSObject.Properties.Remove($ColumnName)
                                }
                            ElseIf ($ColumnName -like "*.*")   # remove any . (period)
                                {
                                    $UpdColumn = $ColumnName.Replace(".","")
                                    $ColumnData = $Entry.$Column
                                    $_ | Add-Member -MemberType NoteProperty -Name $UpdColumn -Value $ColumnData -Force
                                    $_.PSObject.Properties.Remove($ColumnName)
                                }
                            ElseIf ($ColumnName -like "_*")   # remove any leading underscores - column in DCR/LA must start with a character
                                {
                                    $UpdColumn = $ColumnName.TrimStart("_")
                                    $ColumnData = $Entry.$Column
                                    $_ | Add-Member -MemberType NoteProperty -Name $UpdColumn -Value $ColumnData -Force
                                    $_.PSObject.Properties.Remove($ColumnName)
                                }
                            ElseIf ($ColumnName -like "* *")   # remove any whitespaces
                                {
                                    $UpdColumn = $ColumnName.TrimStart()
                                    $ColumnData = $Entry.$Column
                                    $_ | Add-Member -MemberType NoteProperty -Name $UpdColumn -Value $ColumnData -Force
                                    $_.PSObject.Properties.Remove($ColumnName)
                                }
                            ElseIf ($ColumnName.Length -gt 45)   # trim the length to maximum 45 characters
                                {
                                    $UpdColumn = $ColumnName.Substring(0,45)
                                    $ColumnData = $_.$Column
                                    $_ | Add-Member -MemberType NoteProperty -Name $UpdColumn -Value $ColumnData -Force
                                    $_.PSObject.Properties.Remove($ColumnName)
                                }
                            Else    # write column name and data (OK)
                                {
                                    $ColumnData = $_.$ColumnName
                                    $_ | Add-Member -MemberType NoteProperty -Name $ColumnName -Value $ColumnData -Force
                                }
                        }
                    $DataVariableQA += $_

                    # Increment the $i counter variable which is used to create the progress bar.
                    $i = $i+1

                    # Determine the completion percentage
                    $Completed = ($i/$DataCount) * 100
                    Write-Progress -Activity "Validating/fixing schema structure of source object" -Status "Progress:" -PercentComplete $Completed
            } -End {
                $Data = $DataVariableQA
            }
        }
    Else
        {
            Write-host "  SUCCESS - No issues found in schema structure"
        }
    Return $Data
}


Function Build-DataArrayToAlignWithSchema ($Data)
{
    <#  TROUBLESHOOTING
        
        $Data = $DataVariable
    #>

    Write-host "  Aligning source object structure with schema ... Please Wait !"
    
    # Get schema
    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnFormat Array

    $DataCount  = ($Data | Measure-Object).Count

    $DataVariableQA = @()

    $Data | ForEach-Object -Begin  {
            $i = 0
    } -Process {
                    # get column names
                  #  $ObjColumns = $_ | Get-Member -MemberType NoteProperty

                    # enum schema
                    ForEach ($Column in $Schema)
                        {
                            # get column name & data
                            $ColumnName = $Column.Name
                            $ColumnData = $_.$ColumnName

                            $_ | Add-Member -MemberType NoteProperty -Name $ColumnName -Value $ColumnData -Force
                        }
                    $DataVariableQA += $_

                    # Increment the $i counter variable which is used to create the progress bar.
                    $i = $i+1

                    # Determine the completion percentage
                    $Completed = ($i/$DataCount) * 100
                    Write-Progress -Activity "Aligning source object structure with schema" -Status "Progress:" -PercentComplete $Completed
            } -End {
                
                # return data from temporary array to original $Data
                $Data = $DataVariableQA
            }
        Return $Data
}



Function Get-AzDataCollectionRuleNamingConventionSrv ($TableName)
    {
        # variables to be used for upload of data using DCR/log ingest api
        $DcrName    = "dcr-" + $Global:AzDcrPrefixSrvNetworkCloud + "-" + $TableName + "_CL"
        $DceName    = $Global:AzDceNameSrvNetworkCloud
        Return $DcrName, $DceName
    }

Function Get-AzDataCollectionRuleNamingConventionClt ($TableName)
    {
        # variables to be used for upload of data using DCR/log ingest api
        $DcrName    = "dcr-" + $Global:AzDcrPrefixClient + "-" + $TableName + "_CL"
        $DceName    = $Global:AzDceNameClient
        Return $DcrName, $DceName
    }

Function Get-AzLogAnalyticsTableAzDataCollectionRuleStatus ($AzLogWorkspaceResourceId, $TableName, $DcrName, $SchemaSourceObject, $AzAppId, $AzAppSecret, $TenantId)
    {

<#  TROUBLESHOOTING

    # ClientInspector
    $AzLogWorkspaceResourceId             = $ClientLogAnalyticsWorkspaceResourceId
    $ableName                             = $TableName
    $DcrName                              = $DcrName
    $SchemaSourceObject                   = $Schema
    $AzAppId                              = $TableDcrSchemaCreateUpdateAppId
    $AzAppSecret                          = $TableDcrSchemaCreateUpdateAppSecret
    $TenantId                             = $TenantId

#>

        Write-host "  Checking LogAnalytics table and Data Collection Rule configuration .... Please Wait !"

        # by default ($false)
        $AzDcrDceTableCustomLogCreateUpdate = $false     # $True/$False - typically used when updates to schema detected

    #--------------------------------------------------------------------------
    # Connection
    #--------------------------------------------------------------------------
        If ( ($AzAppId) -and ($AzAppSecret) -and ($TenantId) )
            {
                $AccessTokenUri = 'https://management.azure.com/'
                $oAuthUri       = "https://login.microsoftonline.com/$($TenantId)/oauth2/token"
                $authBody       = [Ordered] @{
                                               resource = "$AccessTokenUri"
                                               client_id = "$($LogIngestAppId)"
                                               client_secret = "$($LogIngestAppSecret)"
                                               grant_type = 'client_credentials'
                                             }
                $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
                $token = $authResponse.access_token

                # Set the WebRequest headers
                $Headers = @{
                                'Content-Type' = 'application/json'
                                'Accept' = 'application/json'
                                'Authorization' = "Bearer $token"
                            }
            }

        #--------------------------------------------------------------------------
        # Check if Azure LogAnalytics Table exist
        #--------------------------------------------------------------------------

            $TableUrl = "https://management.azure.com" + $AzLogWorkspaceResourceId + "/tables/$($TableName)_CL?api-version=2021-12-01-preview"
            $TableStatus = Try
                                {
                                    Invoke-RestMethod -Uri $TableUrl -Method GET -Headers $Headers
                                }
                           Catch
                                {
                                    # initial setup - force to auto-create structure
                                    $AzDcrDceTableCustomLogCreateUpdate = $true     # $True/$False - typically used when updates to schema detected
                                }

        #--------------------------------------------------------------------------
        # Compare schema between source object schema and Azure LogAnalytics Table
        #--------------------------------------------------------------------------

            If ($TableStatus)
                {
                    $CurrentTableSchema = $TableStatus.properties.schema.columns

                    # Checking number of objects in schema
                        $CurrentTableSchemaCount = $CurrentTableSchema.count
                        $SchemaSourceObjectCount = ($SchemaSourceObject.count) + 1  # add 1 because TimeGenerated will automatically be added

                        If ($SchemaSourceObjectCount -gt $CurrentTableSchemaCount)
                            {
                               $AzDcrDceTableCustomLogCreateUpdate = $true     # $True/$False - typically used when updates to schema detected
                            }

                    # Verify LogAnalytics table schema matches source object ($SchemaSourceObject) - otherwise set flag to update schema in LA/DCR
                        ForEach ($Entry in $SchemaSourceObject)
                            {
                                $ChkSchema = $CurrentTableSchema | Where-Object { ($_.name -eq $Entry.name) -and ($_.type -eq $Entry.type) }

                                If ($ChkSchema -eq $null)
                                    {
                                        # Set flag to update schema
                                        $AzDcrDceTableCustomLogCreateUpdate = $true     # $True/$False - typically used when updates to schema detected
                                    }
                            }
                }

        #--------------------------------------------------------------------------
        # Check if Azure Data Collection Rule exist
        #--------------------------------------------------------------------------

            # Check in global variable
            $DcrInfo = $global:AzDcrDetails | Where-Object { $_.name -eq $DcrName }
                If (!($DcrInfo))
                    {
                        # initial setup - force to auto-create structure
                        $AzDcrDceTableCustomLogCreateUpdate = $true     # $True/$False - typically used when updates to schema detected
                    }

        Return $AzDcrDceTableCustomLogCreateUpdate
    }


Function Add-ColumnDataToAllEntriesInArray ($Column1Name, $Column1Data, $Column2Name, $Column2Data, $Column3Name, $Column3Data, $Data)
    {
        Write-host "  Adding columns to all entries in array .... please wait !"
        $IntermediateObj = @()
        ForEach ($Entry in $Data)
            {
                If ($Column1Name)
                    {
                        $Entry | Add-Member -MemberType NoteProperty -Name $Column1Name -Value $Column1Data -Force
                    }

                If ($Column2Name)
                    {
                        $Entry | Add-Member -MemberType NoteProperty -Name $Column2Name -Value $Column2Data -Force
                    }

                If ($Column3Name)
                    {
                        $Entry | Add-Member -MemberType NoteProperty -Name $Column3Name -Value $Column3Data -Force
                    }

                $IntermediateObj += $Entry
            }
        return $IntermediateObj
    }

Function Add-CollectionTimeToAllEntriesInArray ($Data)
    {
        [datetime]$CollectionTime = ( Get-date ([datetime]::Now.ToUniversalTime()) -format "yyyy-MM-ddTHH:mm:ssK" )

        Write-host "  Adding CollectionTime to all entries in array .... please wait !"
        $IntermediateObj = @()
        ForEach ($Entry in $Data)
            {
                $Entry | Add-Member -MemberType NoteProperty -Name CollectionTime -Value $CollectionTime -Force

                $IntermediateObj += $Entry
            }
        return $IntermediateObj
    }


Function Convert-CimArrayToObjectFixStructure ($Data)
    {
        Write-host "  Converting CIM array to Object & removing CIM class data in array .... please wait !"

        # Convert from array to object
        $Object = $Data | ConvertTo-Json | ConvertFrom-Json 

        # remove CIM info columns from object
        $ObjectModified = $Object | Select-Object -Property * -ExcludeProperty CimClass, CimInstanceProperties, CimSystemProperties

        return $ObjectModified
    }

Function Convert-PSArrayToObjectFixStructure ($Data)
    {
        Write-host "  Converting PS array to Object & removing PS class data in array .... please wait !"

        # Convert from array to object
        $Object = $Data | ConvertTo-Json | ConvertFrom-Json 

        # remove CIM info columns from object
        $ObjectModified = $Object | Select-Object -Property * -ExcludeProperty PSPath, PSProvider, PSParentPath, PSDrive, PSChildName, PSSnapIn

        return $ObjectModified
    }


Function Collect_MDE_Data_Upload_LogAnalytics ($CustomTable, $CollectionType, $Url, $AzLogWorkspaceResourceId, $TablePrefix, $DceName)
    { 

        <#  TROUBLESHOOTING

            $CollectionType            = $CollectionType
            $Url                       = $Url
            $CustomTable               = $CustomTable
            $AzLogWorkspaceResourceId  = $global:MainLogAnalyticsWorkspaceResourceId
            $TablePrefix               = $Global:AzDcrPrefixSrvNetworkCloud
            $DceName                   = $Global:AzDceNameSrvNetworkCloud

        #>

        ##########################################
        # COLLECTION OF DATA
        ##########################################
            Write-Output ""
            Write-Output "Collecting $($CollectionType) .... Please Wait !"

            $ResponseAllRecords = @()
            while ($Url -ne $null)
                {
                    # Connect to MDE API
                    Write-Output ""
                    Write-Output "  Retrieving data-set from Microsoft Defender Security Center API ... Please Wait !"
                    Connect_MDE_API

                        try 
                            {
                                # todo: verify that the bearer token is still good -- hasn't expired yet -- if it has, then get a new token before making the request
                                $ResponseRaw = Invoke-WebRequest -Method 'Get' -Uri $Url -Headers $global:Headers
                                $ResponseAllRecords += $ResponseRaw.content
                                $ResponseRawJSON = ($ResponseRaw | ConvertFrom-Json)

                                if($ResponseRawJSON.'@odata.nextLink')
                                    {
                                        $Url = $ResponseRawJSON.'@odata.nextLink'
                                    } 
                                else 
                                    {
                                        $Url = $null
                                    }
  
                            }
                        catch 
                            {
                                Write-output ""
                                Write-Output "StatusCode: " $_.Exception.Response.StatusCode.value__
                                Write-Output "StatusDescription:" $_.Exception.Response.StatusDescription
                                Write-output ""
  
                                if($_.ErrorDetails.Message)
                                    {
                                        Write-Output ""
                                        Write-Output "Inner Error: $_.ErrorDetails.Message"
                                        Write-output ""
                                    }
  
                                # check for a specific error so that we can retry the request otherwise, set the url to null so that we fall out of the loop
                                if ($_.Exception.Response.StatusCode.value__ -eq 403 )
                                    {
                                        # just ignore, leave the url the same to retry but pause first
                                        if($retryCount -ge $maxRetries)
                                            {
                                                # not going to retry again
                                                $global:Url = $null
                                                Write-Output 'Not going to retry...'
                                            }
                                        else 
                                            {
                                                $retryCount += 1
                                                write-Output ""
                                                Write-Output "Retry attempt $retryCount after a $pauseDuration second pause..."
                                                Write-output ""
                                                Start-Sleep -Seconds $pauseDuration
                                            }
                                    }
                                    else
                                        {
                                            # not going to retry -- set the url to null to fall back out of the while loop
                                            $Url = $null
                                        }
                            }
                }

        ##########################################
        # UPLOAD OF DATA
        ##########################################

            ##################################################################################################################
            # LogAnalytics upload
            ##################################################################################################################

            $DataVariable     =  ( $ResponseAllRecords  | ConvertFrom-Json).value

            Write-Output ""
            Write-Output "  Retrieved $($DataVariable.count) records from Security Center API"

            # SCOPE - Use only devices in $MachineLine
            $DataVariable     = $DataVariable | Where-Object { $_.deviceName -in $global:MachineList.computerDnsName }

            Write-Output ""
            Write-Output "  Filtered records to $($DataVariable.count) due to $($global:TargetTable) scoping"
            Write-Output ""

            #-------------------------------------------------------
            # Add Collection Time to array for each line
                    
            If ($DataVariable -eq $null)
                {
                    Write-Output "No data to upload"
                }
            Else
                {
                    $CountDataVariable = $DataVariable.count
                    $PosDataVariable   = 0
                        Do
                            {
                                $DataVariable[$PosDataVariable] | Add-Member -Type NoteProperty -Name 'CollectionTime' -Value $CollectionTime -force
                                $PosDataVariable = 1 + $PosDataVariable
                            }
                        Until ($PosDataVariable -eq $CountDataVariable)

                    #----------------------------------------------------------------------------------------------------------------------------------------------------
                    # Post to LogAnalytics - Methods supported: Legacy = HTTP Log Collector, DCR = Log Ingest API with DCRs/DCEs, Legacy_DCR = send using both methods
                    #----------------------------------------------------------------------------------------------------------------------------------------------------

                        # Legacy
                        If ( ($Global:AzLogAnalyticsAPI -eq "Legacy") -or ($Global:AzLogAnalyticsAPI -eq $null) -or ($Global:AzLogAnalyticsAPI -eq "Legacy_DCR") )
                            {    
                                $indexLoopFrom = 0

                                Do
                                    {
                                        $indexLoopTo = $indexLoopFrom + 25000

                                        Write-Output "  [$($indexLoopFrom)..$($indexLoopTo)] - Converting array-data to JSON ... Please Wait"
                                        $json = $DataVariable[$indexLoopFrom..$indexLoopTo] | ConvertTo-Json -Compress

                                        write-Output ""
                                        Write-Output "  [$($indexLoopFrom)..$($indexLoopTo)] - Posting data to Loganalytics table $($global:CustomTable) .... Please Wait !"
                                        Post-LogAnalyticsData -customerId $global:LAWS_Id -sharedKey $global:LAWS_AccessKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $CustomTable
                                        $indexLoopFrom = $indexLoopTo
                                    }

                                Until ($IndexLoopTo -ge $CountDataVariable)
                            }

                        # Modern (DCR)        
                        If ( ($Global:AzLogAnalyticsAPI -eq "DCR") -or ($Global:AzLogAnalyticsAPI -eq "Legacy_DCR") )
                            {    
                                #-------------------------------------------------------------------------------------------
                                # Variables
                                #-------------------------------------------------------------------------------------------
                
                                    $TableName    = $CustomTable + $Global:AzDcrTableNamePostfix
                                    $DataVariable = $DataVariable
                                    $VerbosePreference = "SilentlyContinue"  # Stop, Inquire, Continue, SilentlyContinue

                                #-------------------------------------------------------------------------------------------
                                # Validating/fixing schema data structure of source data
                                #-------------------------------------------------------------------------------------------

                                    $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

                                #-------------------------------------------------------------------------------------------
                                # Check if table and DCR exist, otherwise set flag to do initial setup
                                #-------------------------------------------------------------------------------------------

                                    $Status = Get-AzLogAnalyticsTableAzDataCollectionRuleExistStatus -AzLogWorkspaceResourceId $global:MainLogAnalyticsWorkspaceResourceId -TableName $TableName -TablePrefix $Global:AzDcrPrefixSrvNetworkCloud

                                #-------------------------------------------------------------------------------------------
                                # PreReq - Create/update table (DCR) in LogAnalytics to be used for upload of data via DCR/log ingestion api
                                #-------------------------------------------------------------------------------------------

                                    If ($Global:AzDcrDceTableCustomLogCreateUpdate -eq $true)
                                        {
                                            If ( $env:COMPUTERNAME -in $Global:AzDcrDceTableCustomLogCreateMasterServer)
                                                {
                                                    Create-AzLogAnalyticsCustomLogTableDcr -AzLogWorkspaceResourceId $global:MainLogAnalyticsWorkspaceResourceId -SchemaSourceObject $DataVariable -TableName $TableName `
                                                                                           -AzAppId $global:HighPriv_Modern_ApplicationID_Azure -AzAppSecret $global:HighPriv_Modern_Secret_Azure -TenantId $Global:TenantId


                                                    Create-AzDataCollectionRuleLogIngestCustomLog -AzLogWorkspaceResourceId $global:MainLogAnalyticsWorkspaceResourceId -SchemaSourceObject $DataVariable `
                                                                                                  -DceName $Global:AzDceNameSrvNetworkCloud -TableName $TableName -TablePrefix $Global:AzDcrPrefixSrvNetworkCloud `
                                                                                                  -LogIngestServicePricipleObjectId $Global:AzDcrLogIngestServicePrincipalObjectId `
                                                                                                  -AzDcrSetLogIngestApiAppPermissionsDcrLevel $Global:AzDcrSetLogIngestApiAppPermissionsDcrLevel `
                                                                                                  -AzAppId $global:HighPriv_Modern_ApplicationID_Azure -AzAppSecret $global:HighPriv_Modern_Secret_Azure -TenantId $Global:TenantId
                                                }
                                        }

                                #-------------------------------------------------------------------------------------------
                                # Upload data to LogAnalytics using DCR / DCE / Log Ingestion API
                                #-------------------------------------------------------------------------------------------

                                    # Get DCE/DCR naming convention for prefix SRV
                                    $DcrDceNaming = Get-AzDataCollectionRuleNamingConventionSrv -TableName $TableName

                                    # Get details about DCR/DCE using Azure Resource Graph
                                    $AzDcrDceDetails = Get-AzDcrDceDetails -DcrName $DcrDceNaming[0] -DceName $DcrDceNaming[1]
                                                                                                                 
                                    # Post deta into LogAnalytics custom log using log ingest api
                                    Post-AzLogAnalyticsLogIngestCustomLogDcrDce  -DceUri $AzDcrDceDetails[2] -DcrImmutableId $AzDcrDceDetails[6] `
                                                                                 -DcrStream $AzDcrDceDetails[7] -Data $DataVariable `
                                                                                 -AzAppId $global:HighPriv_Modern_ApplicationID_LogIngestion_DCR -AzAppSecret $global:HighPriv_Modern_Secret_LogIngestion_DCR -TenantId $Global:TenantId
                            }    # Post to LogAnalytics (DCR)
            }
    }

Function Get-ObjectSchema ($Data, $ReturnType, $ReturnFormat)
{
        <#  Troubleshooting
            $Data = $DataVariable
        #>

        $SchemaArrayLogAnalyticsTableFormat = @()
        $SchemaArrayDcrFormat = @()
        $SchemaArrayLogAnalyticsTableFormatHash = @()
        $SchemaArrayDcrFormatHash = @()

        # Requirement - Add TimeGenerated to array
        $SchemaArrayLogAnalyticsTableFormatHash += @{
                                                     name        = "TimeGenerated"
                                                     type        = "datetime"
                                                     description = ""
                                                    }

        $SchemaArrayLogAnalyticsTableFormat += [PSCustomObject]@{
                                                     name        = "TimeGenerated"
                                                     type        = "datetime"
                                                     description = ""
                                               }

        # Loop source object and build hash for table schema
        ForEach ($Entry in $Data)
            {
                $ObjColumns = $Entry | ConvertTo-Json -Depth 100 | ConvertFrom-Json | Get-Member -MemberType NoteProperty
                ForEach ($Column in $ObjColumns)
                    {
                        $ObjDefinitionStr = $Column.Definition
                                If ($ObjDefinitionStr -like "int*")                                            { $ObjType = "int" }
                            ElseIf ($ObjDefinitionStr -like "real*")                                           { $ObjType = "int" }
                            ElseIf ($ObjDefinitionStr -like "long*")                                           { $ObjType = "long" }
                            ElseIf ($ObjDefinitionStr -like "guid*")                                           { $ObjType = "dynamic" }
                            ElseIf ($ObjDefinitionStr -like "string*")                                         { $ObjType = "string" }
                            ElseIf ($ObjDefinitionStr -like "datetime*")                                       { $ObjType = "datetime" }
                            ElseIf ($ObjDefinitionStr -like "bool*")                                           { $ObjType = "boolean" }
                            ElseIf ($ObjDefinitionStr -like "object*")                                         { $ObjType = "dynamic" }
                            ElseIf ($ObjDefinitionStr -like "System.Management.Automation.PSCustomObject*")    { $ObjType = "dynamic" }

                        # build for array check
                        $SchemaLogAnalyticsTableFormatObjHash = @{
                                                                   name        = $Column.Name
                                                                   type        = $ObjType
                                                                   description = ""
                                                                 }

                        $SchemaLogAnalyticsTableFormatObj     = [PSCustomObject]@{
                                                                   name        = $Column.Name
                                                                   type        = $ObjType
                                                                   description = ""
                                                                }
                        $SchemaDcrFormatObjHash = @{
                                                      name        = $Column.Name
                                                      type        = $ObjType
                                                   }

                        $SchemaDcrFormatObj     = [PSCustomObject]@{
                                                      name        = $Column.Name
                                                      type        = $ObjType
                                                  }


                        If ($Column.Name -notin $SchemaArrayLogAnalyticsTableFormat.name)
                            {
                                $SchemaArrayLogAnalyticsTableFormat       += $SchemaLogAnalyticsTableFormatObj
                                $SchemaArrayDcrFormat                     += $SchemaDcrFormatObj

                                $SchemaArrayLogAnalyticsTableFormatHash   += $SchemaLogAnalyticsTableFormatObjHash
                                $SchemaArrayDcrFormatHash                 += $SchemaDcrFormatObjHash
                            }
                    }
            }

            If ( ($ReturnType -eq "Table") -and ($ReturnFormat -eq "Array") )
            {
                # Return schema format for LogAnalytics table
                Return $SchemaArrayLogAnalyticsTableFormat
            }
        ElseIf ( ($ReturnType -eq "Table") -and ($ReturnFormat -eq "Hash") )
            {
                # Return schema format for DCR
                Return $SchemaArrayLogAnalyticsTableFormatHash
            }
        ElseIf ( ($ReturnType -eq "DCR") -and ($ReturnFormat -eq "Array") )
            {
                # Return schema format for DCR
                Return $SchemaArrayDcrFormat
            }
        ElseIf ( ($ReturnType -eq "DCR") -and ($ReturnFormat -eq "Hash") )
            {
                # Return schema format for DCR
                Return $SchemaArrayDcrFormatHash
            }
        ElseIf ( ($ReturnType -eq $null) -and ($ReturnFormat -eq "Hash") )
            {
                # Return schema format for DCR
                Return $SchemaArrayDcrFormatHash
            }
        ElseIf ( ($ReturnType -eq $null) -and ($ReturnFormat -eq "Array") )
            {
                # Return schema format for DCR
                Return $SchemaArrayDcrFormat
            }
}


Function Filter-ObjectExcludeProperty ($Data, $ExcludeProperty)
{
        $Data = $Data | Select-Object * -ExcludeProperty $ExcludeProperty
        Return $Data
}


Function Get-AzDcrListAll ($AzAppId, $AzAppSecret, $TenantId)
{
    Write-host ""
    Write-host "Getting Data Collection Rules from Azure Resource Graph .... Please Wait !"

    #--------------------------------------------------------------------------
    # Connection
    #--------------------------------------------------------------------------
        If ( ($AzAppId) -and ($AzAppSecret) -and ($TenantId) )
            {
                $AccessTokenUri = 'https://management.azure.com/'
                $oAuthUri       = "https://login.microsoftonline.com/$($TenantId)/oauth2/token"
                $authBody       = [Ordered] @{
                                               resource = "$AccessTokenUri"
                                               client_id = "$($LogIngestAppId)"
                                               client_secret = "$($LogIngestAppSecret)"
                                               grant_type = 'client_credentials'
                                             }
                $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
                $token = $authResponse.access_token

                # Set the WebRequest headers
                $Headers = @{
                                'Content-Type' = 'application/json'
                                'Accept' = 'application/json'
                                'Authorization' = "Bearer $token"
                            }
            }

    #--------------------------------------------------------------------------
    # Get DCRs from Azure Resource Graph
    #--------------------------------------------------------------------------

        $AzGraphQuery = @{
                            'query' = 'Resources | where type =~ "microsoft.insights/datacollectionrules" '
                            } | ConvertTo-Json -Depth 20

        $ResponseData = @()

        $AzGraphUri          = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"
        $ResponseRaw         = Invoke-WebRequest -Method POST -Uri $AzGraphUri -Headers $Headers -Body $AzGraphQuery
        $ResponseData       += $ResponseRaw.content
        $ResponseNextLink    = $ResponseRaw."@odata.nextLink"

        While ($ResponseNextLink -ne $null)
            {
                $ResponseRaw         = Invoke-WebRequest -Method POST -Uri $AzGraphUri -Headers $Headers -Body $AzGraphQuery
                $ResponseData       += $ResponseRaw.content
                $ResponseNextLink    = $ResponseRaw."@odata.nextLink"
            }
        $DataJson = $ResponseData | ConvertFrom-Json
        $Data     = $DataJson.data

        Return $Data
}


Function Get-AzDceListAll ($AzAppId, $AzAppSecret, $TenantId)
{
    Write-host ""
    Write-host "Getting Data Collection Endpoints from Azure Resource Graph .... Please Wait !"

    #--------------------------------------------------------------------------
    # Connection
    #--------------------------------------------------------------------------
        If ( ($AzAppId) -and ($AzAppSecret) -and ($TenantId) )
            {
                $AccessTokenUri = 'https://management.azure.com/'
                $oAuthUri       = "https://login.microsoftonline.com/$($TenantId)/oauth2/token"
                $authBody       = [Ordered] @{
                                               resource = "$AccessTokenUri"
                                               client_id = "$($LogIngestAppId)"
                                               client_secret = "$($LogIngestAppSecret)"
                                               grant_type = 'client_credentials'
                                             }
                $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
                $token = $authResponse.access_token

                # Set the WebRequest headers
                $Headers = @{
                                'Content-Type' = 'application/json'
                                'Accept' = 'application/json'
                                'Authorization' = "Bearer $token"
                            }
            }

    #--------------------------------------------------------------------------
    # Get DCEs from Azure Resource Graph
    #--------------------------------------------------------------------------

        $AzGraphQuery = @{
                            'query' = 'Resources | where type =~ "microsoft.insights/datacollectionendpoints" '
                            } | ConvertTo-Json -Depth 20

        $ResponseData = @()

        $AzGraphUri          = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"
        $ResponseRaw         = Invoke-WebRequest -Method POST -Uri $AzGraphUri -Headers $Headers -Body $AzGraphQuery
        $ResponseData       += $ResponseRaw.content
        $ResponseNextLink    = $ResponseRaw."@odata.nextLink"

        While ($ResponseNextLink -ne $null)
            {
                $ResponseRaw         = Invoke-WebRequest -Method POST -Uri $AzGraphUri -Headers $Headers -Body $AzGraphQuery
                $ResponseData       += $ResponseRaw.content
                $ResponseNextLink    = $ResponseRaw."@odata.nextLink"
            }
        $DataJson = $ResponseData | ConvertFrom-Json
        $Data     = $DataJson.data

        Return $Data
}


############################################################################################################################################
# MAIN PROGRAM
############################################################################################################################################

    #-------------------------------------------------------------------------------------------------------------
    # Initial Powershell module check
    #-------------------------------------------------------------------------------------------------------------

        Try
            {
                Import-Module -Name PSWindowsUpdate
            }
        Catch
            {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

                Write-Output ""
                Write-Output "Checking Powershell PackageProvider NuGet ... Please Wait !"
                    if (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) 
                        {
                            Write-Host "  OK - PackageProvider NuGet is installed"
                        } 
                    else 
                        {
                            try {
                                Install-PackageProvider -Name NuGet -Scope AllUsers -Confirm:$false -Force
                            }
                            catch [Exception] {
                                $_.message 
                                exit
                            }
                        }

                Write-Output ""
                Write-Output "Checking Powershell Module PSWindowsUpdate ... Please Wait !"
                    if (Get-Module -ListAvailable -Name PSWindowsUpdate -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) 
                        {
                            Write-output "  OK - Powershell Modue PSWindowsUpdate is installed"
                        } 
                    else 
                        {
                            try {
                                Write-Output "  Installing Powershell Module PSWindowsUpdate .... Please Wait !"
                                Install-Module -Name PSWindowsUpdate -AllowClobber -Scope AllUsers -Confirm:$False -Force
                                Import-Module -Name PSWindowsUpdate
                            }
                            catch [Exception] {
                                $_.message 
                                exit
                            }
                        }
            }

###############################################################
# Global Variables
#
# Used to mitigate throttling in Azure Resource Graph
###############################################################

    # building global variable with all DCEs, which can be viewed by Log Ingestion app
    $global:AzDceDetails = Get-AzDceListAll -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId
    
    # building global variable with all DCRs, which can be viewed by Log Ingestion app
    $global:AzDcrDetails = Get-AzDcrListAll -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId


###############################################################
# USER [1]
###############################################################

    Write-output ""
    Write-output "#########################################################################################"
    Write-output "Collecting User information [1]"
    Write-output ""

    #-------------------------------------------------------------------------------------------
    # Variables
    #-------------------------------------------------------------------------------------------

        $TableName = 'InvClientComputerUserLoggedOnV2'
        $DcrName   = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"

    #-------------------------------------------------------------------------------------------
    # Collecting data (in)
    #-------------------------------------------------------------------------------------------

        $UserLoggedOnRaw = Get-Process -IncludeUserName -Name explorer | Select-Object UserName -Unique
        $UserLoggedOn    = $UserLoggedOnRaw.UserName

    #-------------------------------------------------------------------------------------------
    # Preparing data structure
    #-------------------------------------------------------------------------------------------

        # Build array
        $DataVariable = [pscustomobject]@{
                                            UserLoggedOn         = $UserLoggedOn
                                         }

        # add CollectionTime to existing array
        $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable

        # add Computer info to existing array
        $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName

        # Validating/fixing schema data structure of source data
        $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

        # Aligning data structure with schema (requirement for DCR)
        $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable

    #-------------------------------------------------------------------------------------------
    # Create/Update Schema for LogAnalytics Table & Data Collection Rule schema
    #-------------------------------------------------------------------------------------------

        If ( ($TableDcrSchemaCreateUpdateAppId) -and ($TableDcrSchemaCreateUpdateAppSecret) )
            {
                #-----------------------------------------------------------------------------------------------
                # Check if table and DCR exist - or schema must be updated due to source object schema changes
                #-----------------------------------------------------------------------------------------------

                    # Get insight about the schema structure
                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnFormat Array

                    $StructureCheck = Get-AzLogAnalyticsTableAzDataCollectionRuleStatus -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -TableName $TableName -DcrName $DcrName -SchemaSourceObject $Schema `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId

                #-----------------------------------------------------------------------------------------------
                # Structure check = $true -> Create/update table & DCR with necessary schema
                #-----------------------------------------------------------------------------------------------

                    If ($StructureCheck -eq $true)
                        {
                            If ( ( $env:COMPUTERNAME -in $AzDcrDceTableCreateFromReferenceMachine) -or ($AzDcrDceTableCreateFromAnyMachine -eq $true) )    # manage table creations
                                {
                                    # build schema to be used for LogAnalytics Table
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType Table -ReturnFormat Hash

                                    CreateUpdate-AzLogAnalyticsCustomLogTableDcr -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema -TableName $TableName `
                                                                                 -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId


                                    # build schema to be used for DCR
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType DCR -ReturnFormat Hash

                                    CreateUpdate-AzDataCollectionRuleLogIngestCustomLog -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema `
                                                                                        -DceName $DceName -DcrName $DcrName -TableName $TableName `
                                                                                        -LogIngestServicePricipleObjectId $AzDcrLogIngestServicePrincipalObjectId `
                                                                                        -AzDcrSetLogIngestApiAppPermissionsDcrLevel $AzDcrSetLogIngestApiAppPermissionsDcrLevel `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId
                                }
                        }

                } # create table/DCR

    #-----------------------------------------------------------------------------------------------
    # Upload data to LogAnalytics using DCR / DCE / Log Ingestion API
    #-----------------------------------------------------------------------------------------------

        $AzDcrDceDetails = Get-AzDcrDceDetails -DcrName $DcrName -DceName $DceName `
                                               -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId

        Post-AzLogAnalyticsLogIngestCustomLogDcrDce  -DceUri $AzDcrDceDetails[2] -DcrImmutableId $AzDcrDceDetails[6] `
                                                     -DcrStream $AzDcrDceDetails[7] -Data $DataVariable `
                                                     -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId
        
        # Write result to screen
        $DataVariable | Out-String | Write-Verbose 


###############################################################
# COMPUTER INFORMATION [2]
###############################################################

    Write-output ""
    Write-output "#########################################################################################"
    Write-output "COMPUTER INFORMATION [2]"
    Write-output ""

    ####################################
    # Bios
    ####################################

        #-------------------------------------------------------------------------------------------
        # Variables
        #-------------------------------------------------------------------------------------------
            
            $TableName  = 'InvClientComputerInfoBiosV2'   # must not contain _CL
            $DcrName    = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"

        #-------------------------------------------------------------------------------------------
        # Collecting data (in)
        #-------------------------------------------------------------------------------------------
            
            Write-Output ""
            Write-Output "Collecting Bios information"

            $DataVariable = Get-CimInstance -ClassName Win32_BIOS

        #-------------------------------------------------------------------------------------------
        # Preparing data structure
        #-------------------------------------------------------------------------------------------

            # convert CIM array to PSCustomObject and remove CIM class information
            $DataVariable = Convert-CimArrayToObjectFixStructure -data $DataVariable
    
            # add CollectionTime to existing array
            $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable

            # add Computer & UserLoggedOn info to existing array
            $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

            # Validating/fixing schema data structure of source data
            $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

            # Aligning data structure with schema (requirement for DCR)
            $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable

    #-------------------------------------------------------------------------------------------
    # Create/Update Schema for LogAnalytics Table & Data Collection Rule schema
    #-------------------------------------------------------------------------------------------

        If ( ($TableDcrSchemaCreateUpdateAppId) -and ($TableDcrSchemaCreateUpdateAppSecret) )
            {
                #-----------------------------------------------------------------------------------------------
                # Check if table and DCR exist - or schema must be updated due to source object schema changes
                #-----------------------------------------------------------------------------------------------

                    # Get insight about the schema structure
                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnFormat Array

                    $StructureCheck = Get-AzLogAnalyticsTableAzDataCollectionRuleStatus -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -TableName $TableName -DcrName $DcrName -SchemaSourceObject $Schema `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId

                #-----------------------------------------------------------------------------------------------
                # Structure check = $true -> Create/update table & DCR with necessary schema
                #-----------------------------------------------------------------------------------------------

                    If ($StructureCheck -eq $true)
                        {
                            If ( ( $env:COMPUTERNAME -in $AzDcrDceTableCreateFromReferenceMachine) -or ($AzDcrDceTableCreateFromAnyMachine -eq $true) )    # manage table creations
                                {
                                    # build schema to be used for LogAnalytics Table
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType Table -ReturnFormat Hash

                                    CreateUpdate-AzLogAnalyticsCustomLogTableDcr -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema -TableName $TableName `
                                                                                 -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId


                                    # build schema to be used for DCR
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType DCR -ReturnFormat Hash

                                    CreateUpdate-AzDataCollectionRuleLogIngestCustomLog -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema `
                                                                                        -DceName $DceName -DcrName $DcrName -TableName $TableName `
                                                                                        -LogIngestServicePricipleObjectId $AzDcrLogIngestServicePrincipalObjectId `
                                                                                        -AzDcrSetLogIngestApiAppPermissionsDcrLevel $AzDcrSetLogIngestApiAppPermissionsDcrLevel `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId
                                }
                        }

                } # create table/DCR

    #-----------------------------------------------------------------------------------------------
    # Upload data to LogAnalytics using DCR / DCE / Log Ingestion API
    #-----------------------------------------------------------------------------------------------

        $AzDcrDceDetails = Get-AzDcrDceDetails -DcrName $DcrName -DceName $DceName `
                                               -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId

        Post-AzLogAnalyticsLogIngestCustomLogDcrDce  -DceUri $AzDcrDceDetails[2] -DcrImmutableId $AzDcrDceDetails[6] `
                                                     -DcrStream $AzDcrDceDetails[7] -Data $DataVariable `
                                                     -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId
        
        # Write result to screen
        $DataVariable | Out-String | Write-Verbose 


    ####################################
    # Processor
    ####################################

        #-------------------------------------------------------------------------------------------
        # Variables
        #-------------------------------------------------------------------------------------------
            
            $TableName  = 'InvClientComputerInfoProcessorV2'   # must not contain _CL
            $DcrName    = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"

        #-------------------------------------------------------------------------------------------
        # Collecting data (in)
        #-------------------------------------------------------------------------------------------
            
            Write-Output ""
            Write-Output "Collecting Processor information"
            $DataVariable = Get-CimInstance -ClassName Win32_Processor | Select-Object -ExcludeProperty "CIM*"

        #-------------------------------------------------------------------------------------------
        # Preparing data structure
        #-------------------------------------------------------------------------------------------

            # convert CIM array to PSCustomObject and remove CIM class information
            $DataVariable = Convert-CimArrayToObjectFixStructure -data $DataVariable
    
            # add CollectionTime to existing array
            $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable

            # add Computer & UserLoggedOn info to existing array
            $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

            # Validating/fixing schema data structure of source data
            $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

            # Aligning data structure with schema (requirement for DCR)
            $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable

    #-------------------------------------------------------------------------------------------
    # Create/Update Schema for LogAnalytics Table & Data Collection Rule schema
    #-------------------------------------------------------------------------------------------

        If ( ($TableDcrSchemaCreateUpdateAppId) -and ($TableDcrSchemaCreateUpdateAppSecret) )
            {
                #-----------------------------------------------------------------------------------------------
                # Check if table and DCR exist - or schema must be updated due to source object schema changes
                #-----------------------------------------------------------------------------------------------

                    # Get insight about the schema structure
                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnFormat Array

                    $StructureCheck = Get-AzLogAnalyticsTableAzDataCollectionRuleStatus -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -TableName $TableName -DcrName $DcrName -SchemaSourceObject $Schema `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId

                #-----------------------------------------------------------------------------------------------
                # Structure check = $true -> Create/update table & DCR with necessary schema
                #-----------------------------------------------------------------------------------------------

                    If ($StructureCheck -eq $true)
                        {
                            If ( ( $env:COMPUTERNAME -in $AzDcrDceTableCreateFromReferenceMachine) -or ($AzDcrDceTableCreateFromAnyMachine -eq $true) )    # manage table creations
                                {
                                    # build schema to be used for LogAnalytics Table
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType Table -ReturnFormat Hash

                                    CreateUpdate-AzLogAnalyticsCustomLogTableDcr -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema -TableName $TableName `
                                                                                 -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId


                                    # build schema to be used for DCR
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType DCR -ReturnFormat Hash

                                    CreateUpdate-AzDataCollectionRuleLogIngestCustomLog -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema `
                                                                                        -DceName $DceName -DcrName $DcrName -TableName $TableName `
                                                                                        -LogIngestServicePricipleObjectId $AzDcrLogIngestServicePrincipalObjectId `
                                                                                        -AzDcrSetLogIngestApiAppPermissionsDcrLevel $AzDcrSetLogIngestApiAppPermissionsDcrLevel `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId
                                }
                        }

                } # create table/DCR

    #-----------------------------------------------------------------------------------------------
    # Upload data to LogAnalytics using DCR / DCE / Log Ingestion API
    #-----------------------------------------------------------------------------------------------

        $AzDcrDceDetails = Get-AzDcrDceDetails -DcrName $DcrName -DceName $DceName `
                                               -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId

        Post-AzLogAnalyticsLogIngestCustomLogDcrDce  -DceUri $AzDcrDceDetails[2] -DcrImmutableId $AzDcrDceDetails[6] `
                                                     -DcrStream $AzDcrDceDetails[7] -Data $DataVariable `
                                                     -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId
        
        # Write result to screen
        $DataVariable | Out-String | Write-Verbose 


    ####################################
    # Computer System
    ####################################

        #-------------------------------------------------------------------------------------------
        # Variables
        #-------------------------------------------------------------------------------------------
            
            $TableName  = 'InvClientComputerInfoSystemV2'   # must not contain _CL
            $DcrName    = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"

        #-------------------------------------------------------------------------------------------
        # Collecting data (in)
        #-------------------------------------------------------------------------------------------
            
            Write-Output ""
            Write-Output "Collecting Computer system information"

            $DataVariable = Get-CimInstance -ClassName Win32_ComputerSystem

        #-------------------------------------------------------------------------------------------
        # Preparing data structure
        #-------------------------------------------------------------------------------------------

            # convert CIM array to PSCustomObject and remove CIM class information
            $DataVariable = Convert-CimArrayToObjectFixStructure -data $DataVariable
    
            # add CollectionTime to existing array
            $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable

            # add Computer & UserLoggedOn info to existing array
            $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

        # Validating/fixing schema data structure of source data
        $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

        # Aligning data structure with schema (requirement for DCR)
        $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable

    #-------------------------------------------------------------------------------------------
    # Create/Update Schema for LogAnalytics Table & Data Collection Rule schema
    #-------------------------------------------------------------------------------------------

        If ( ($TableDcrSchemaCreateUpdateAppId) -and ($TableDcrSchemaCreateUpdateAppSecret) )
            {
                #-----------------------------------------------------------------------------------------------
                # Check if table and DCR exist - or schema must be updated due to source object schema changes
                #-----------------------------------------------------------------------------------------------

                    # Get insight about the schema structure
                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnFormat Array

                    $StructureCheck = Get-AzLogAnalyticsTableAzDataCollectionRuleStatus -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -TableName $TableName -DcrName $DcrName -SchemaSourceObject $Schema `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId

                #-----------------------------------------------------------------------------------------------
                # Structure check = $true -> Create/update table & DCR with necessary schema
                #-----------------------------------------------------------------------------------------------

                    If ($StructureCheck -eq $true)
                        {
                            If ( ( $env:COMPUTERNAME -in $AzDcrDceTableCreateFromReferenceMachine) -or ($AzDcrDceTableCreateFromAnyMachine -eq $true) )    # manage table creations
                                {
                                    # build schema to be used for LogAnalytics Table
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType Table -ReturnFormat Hash

                                    CreateUpdate-AzLogAnalyticsCustomLogTableDcr -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema -TableName $TableName `
                                                                                 -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId


                                    # build schema to be used for DCR
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType DCR -ReturnFormat Hash

                                    CreateUpdate-AzDataCollectionRuleLogIngestCustomLog -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema `
                                                                                        -DceName $DceName -DcrName $DcrName -TableName $TableName `
                                                                                        -LogIngestServicePricipleObjectId $AzDcrLogIngestServicePrincipalObjectId `
                                                                                        -AzDcrSetLogIngestApiAppPermissionsDcrLevel $AzDcrSetLogIngestApiAppPermissionsDcrLevel `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId
                                }
                        }

                } # create table/DCR

    #-----------------------------------------------------------------------------------------------
    # Upload data to LogAnalytics using DCR / DCE / Log Ingestion API
    #-----------------------------------------------------------------------------------------------

        $AzDcrDceDetails = Get-AzDcrDceDetails -DcrName $DcrName -DceName $DceName `
                                               -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId

        Post-AzLogAnalyticsLogIngestCustomLogDcrDce  -DceUri $AzDcrDceDetails[2] -DcrImmutableId $AzDcrDceDetails[6] `
                                                     -DcrStream $AzDcrDceDetails[7] -Data $DataVariable `
                                                     -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId
        
        # Write result to screen
        $DataVariable | Out-String | Write-Verbose 

    ####################################
    # Computer Info
    ####################################

        #-------------------------------------------------------------------------------------------
        # Variables
        #-------------------------------------------------------------------------------------------
            
            $TableName  = 'InvClientComputerInfoV2'   # must not contain _CL
            $DcrName    = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"

        #-------------------------------------------------------------------------------------------
        # Collecting data (in)
        #-------------------------------------------------------------------------------------------
            
            Write-Output ""
            Write-Output "Collecting computer information"

            $DataVariable = Get-ComputerInfo

        #-------------------------------------------------------------------------------------------
        # Preparing data structure
        #-------------------------------------------------------------------------------------------

            # convert CIM array to PSCustomObject and remove CIM class information
            $DataVariable = Convert-CimArrayToObjectFixStructure -data $DataVariable
    
            # add CollectionTime to existing array
            $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable

            # add Computer & UserLoggedOn info to existing array
            $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

        # Validating/fixing schema data structure of source data
        $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

        # Aligning data structure with schema (requirement for DCR)
        $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable

    #-------------------------------------------------------------------------------------------
    # Create/Update Schema for LogAnalytics Table & Data Collection Rule schema
    #-------------------------------------------------------------------------------------------

        If ( ($TableDcrSchemaCreateUpdateAppId) -and ($TableDcrSchemaCreateUpdateAppSecret) )
            {
                #-----------------------------------------------------------------------------------------------
                # Check if table and DCR exist - or schema must be updated due to source object schema changes
                #-----------------------------------------------------------------------------------------------

                    # Get insight about the schema structure
                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnFormat Array

                    $StructureCheck = Get-AzLogAnalyticsTableAzDataCollectionRuleStatus -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -TableName $TableName -DcrName $DcrName -SchemaSourceObject $Schema `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId

                #-----------------------------------------------------------------------------------------------
                # Structure check = $true -> Create/update table & DCR with necessary schema
                #-----------------------------------------------------------------------------------------------

                    If ($StructureCheck -eq $true)
                        {
                            If ( ( $env:COMPUTERNAME -in $AzDcrDceTableCreateFromReferenceMachine) -or ($AzDcrDceTableCreateFromAnyMachine -eq $true) )    # manage table creations
                                {
                                    # build schema to be used for LogAnalytics Table
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType Table -ReturnFormat Hash

                                    CreateUpdate-AzLogAnalyticsCustomLogTableDcr -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema -TableName $TableName `
                                                                                 -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId


                                    # build schema to be used for DCR
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType DCR -ReturnFormat Hash

                                    CreateUpdate-AzDataCollectionRuleLogIngestCustomLog -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema `
                                                                                        -DceName $DceName -DcrName $DcrName -TableName $TableName `
                                                                                        -LogIngestServicePricipleObjectId $AzDcrLogIngestServicePrincipalObjectId `
                                                                                        -AzDcrSetLogIngestApiAppPermissionsDcrLevel $AzDcrSetLogIngestApiAppPermissionsDcrLevel `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId
                                }
                        }

                } # create table/DCR

    #-----------------------------------------------------------------------------------------------
    # Upload data to LogAnalytics using DCR / DCE / Log Ingestion API
    #-----------------------------------------------------------------------------------------------

        $AzDcrDceDetails = Get-AzDcrDceDetails -DcrName $DcrName -DceName $DceName `
                                               -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId

        Post-AzLogAnalyticsLogIngestCustomLogDcrDce  -DceUri $AzDcrDceDetails[2] -DcrImmutableId $AzDcrDceDetails[6] `
                                                     -DcrStream $AzDcrDceDetails[7] -Data $DataVariable `
                                                     -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId
        
        # Write result to screen
        $DataVariable | Out-String | Write-Verbose 


    ####################################
    # OS Info
    ####################################

        #-------------------------------------------------------------------------------------------
        # Variables
        #-------------------------------------------------------------------------------------------
            
            $TableName  = 'InvClientComputerOSInfoV2'   # must not contain _CL
            $DcrName    = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"

        #-------------------------------------------------------------------------------------------
        # Collecting data (in)
        #-------------------------------------------------------------------------------------------
            
            Write-Output ""
            Write-Output "Collecting OS information"

            $DataVariable = Get-CimInstance -ClassName Win32_OperatingSystem

        #-------------------------------------------------------------------------------------------
        # Preparing data structure
        #-------------------------------------------------------------------------------------------

            # convert CIM array to PSCustomObject and remove CIM class information
            $DataVariable = Convert-CimArrayToObjectFixStructure -data $DataVariable
    
            # add CollectionTime to existing array
            $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable

            # add Computer & UserLoggedOn info to existing array
            $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

        # Validating/fixing schema data structure of source data
        $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

        # Aligning data structure with schema (requirement for DCR)
        $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable

    #-------------------------------------------------------------------------------------------
    # Create/Update Schema for LogAnalytics Table & Data Collection Rule schema
    #-------------------------------------------------------------------------------------------

        If ( ($TableDcrSchemaCreateUpdateAppId) -and ($TableDcrSchemaCreateUpdateAppSecret) )
            {
                #-----------------------------------------------------------------------------------------------
                # Check if table and DCR exist - or schema must be updated due to source object schema changes
                #-----------------------------------------------------------------------------------------------

                    # Get insight about the schema structure
                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnFormat Array

                    $StructureCheck = Get-AzLogAnalyticsTableAzDataCollectionRuleStatus -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -TableName $TableName -DcrName $DcrName -SchemaSourceObject $Schema `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId

                #-----------------------------------------------------------------------------------------------
                # Structure check = $true -> Create/update table & DCR with necessary schema
                #-----------------------------------------------------------------------------------------------

                    If ($StructureCheck -eq $true)
                        {
                            If ( ( $env:COMPUTERNAME -in $AzDcrDceTableCreateFromReferenceMachine) -or ($AzDcrDceTableCreateFromAnyMachine -eq $true) )    # manage table creations
                                {
                                    # build schema to be used for LogAnalytics Table
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType Table -ReturnFormat Hash

                                    CreateUpdate-AzLogAnalyticsCustomLogTableDcr -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema -TableName $TableName `
                                                                                 -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId


                                    # build schema to be used for DCR
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType DCR -ReturnFormat Hash

                                    CreateUpdate-AzDataCollectionRuleLogIngestCustomLog -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema `
                                                                                        -DceName $DceName -DcrName $DcrName -TableName $TableName `
                                                                                        -LogIngestServicePricipleObjectId $AzDcrLogIngestServicePrincipalObjectId `
                                                                                        -AzDcrSetLogIngestApiAppPermissionsDcrLevel $AzDcrSetLogIngestApiAppPermissionsDcrLevel `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId
                                }
                        }

                } # create table/DCR

    #-----------------------------------------------------------------------------------------------
    # Upload data to LogAnalytics using DCR / DCE / Log Ingestion API
    #-----------------------------------------------------------------------------------------------

        $AzDcrDceDetails = Get-AzDcrDceDetails -DcrName $DcrName -DceName $DceName `
                                               -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId

        Post-AzLogAnalyticsLogIngestCustomLogDcrDce  -DceUri $AzDcrDceDetails[2] -DcrImmutableId $AzDcrDceDetails[6] `
                                                     -DcrStream $AzDcrDceDetails[7] -Data $DataVariable `
                                                     -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId
        
        # Write result to screen
        $DataVariable | Out-String | Write-Verbose 


    ####################################
    # Last Restart
    ####################################

        #-------------------------------------------------------------------------------------------
        # Variables
        #-------------------------------------------------------------------------------------------
            
            $TableName  = 'InvClientComputerInfoLastRestartV2'   # must not contain _CL
            $DcrName    = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"

        #-------------------------------------------------------------------------------------------
        # Collecting data (in)
        #-------------------------------------------------------------------------------------------
            
            Write-Output ""
            Write-Output "Collecting Last restart information"

            $LastRestart = Get-CimInstance -ClassName win32_operatingsystem | Select lastbootuptime
            $LastRestart = (Get-date $LastRestart.LastBootUpTime)

            $Today = (GET-DATE)
            $TimeSinceLastReboot = NEW-TIMESPAN –Start $LastRestart –End $Today

        #-------------------------------------------------------------------------------------------
        # Preparing data structure
        #-------------------------------------------------------------------------------------------

            $DataVariable = [pscustomobject]@{
                                                LastRestart          = $LastRestart
                                                DaysSinceLastRestart = $TimeSinceLastReboot.Days
                                                }

            # add CollectionTime to existing array
            $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable

            # add Computer & UserLoggedOn info to existing array
            $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

        # Validating/fixing schema data structure of source data
        $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

        # Aligning data structure with schema (requirement for DCR)
        $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable

    #-------------------------------------------------------------------------------------------
    # Create/Update Schema for LogAnalytics Table & Data Collection Rule schema
    #-------------------------------------------------------------------------------------------

        If ( ($TableDcrSchemaCreateUpdateAppId) -and ($TableDcrSchemaCreateUpdateAppSecret) )
            {
                #-----------------------------------------------------------------------------------------------
                # Check if table and DCR exist - or schema must be updated due to source object schema changes
                #-----------------------------------------------------------------------------------------------

                    # Get insight about the schema structure
                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnFormat Array

                    $StructureCheck = Get-AzLogAnalyticsTableAzDataCollectionRuleStatus -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -TableName $TableName -DcrName $DcrName -SchemaSourceObject $Schema `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId

                #-----------------------------------------------------------------------------------------------
                # Structure check = $true -> Create/update table & DCR with necessary schema
                #-----------------------------------------------------------------------------------------------

                    If ($StructureCheck -eq $true)
                        {
                            If ( ( $env:COMPUTERNAME -in $AzDcrDceTableCreateFromReferenceMachine) -or ($AzDcrDceTableCreateFromAnyMachine -eq $true) )    # manage table creations
                                {
                                    # build schema to be used for LogAnalytics Table
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType Table -ReturnFormat Hash

                                    CreateUpdate-AzLogAnalyticsCustomLogTableDcr -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema -TableName $TableName `
                                                                                 -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId


                                    # build schema to be used for DCR
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType DCR -ReturnFormat Hash

                                    CreateUpdate-AzDataCollectionRuleLogIngestCustomLog -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema `
                                                                                        -DceName $DceName -DcrName $DcrName -TableName $TableName `
                                                                                        -LogIngestServicePricipleObjectId $AzDcrLogIngestServicePrincipalObjectId `
                                                                                        -AzDcrSetLogIngestApiAppPermissionsDcrLevel $AzDcrSetLogIngestApiAppPermissionsDcrLevel `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId
                                }
                        }

                } # create table/DCR

    #-----------------------------------------------------------------------------------------------
    # Upload data to LogAnalytics using DCR / DCE / Log Ingestion API
    #-----------------------------------------------------------------------------------------------

        $AzDcrDceDetails = Get-AzDcrDceDetails -DcrName $DcrName -DceName $DceName `
                                               -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId

        Post-AzLogAnalyticsLogIngestCustomLogDcrDce  -DceUri $AzDcrDceDetails[2] -DcrImmutableId $AzDcrDceDetails[6] `
                                                     -DcrStream $AzDcrDceDetails[7] -Data $DataVariable `
                                                     -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId
        
        # Write result to screen
        $DataVariable | Out-String | Write-Verbose 


<#   SLOW (!)

###############################################################
# APPLICATIONS (WMI) [3]
###############################################################

    Write-output ""
    Write-output "#########################################################################################"
    write-output "INSTALLED APPLICATIONS INFORMATION [3]"
    Write-output ""
    write-output "WMI information about installed applications"
    Write-output ""

    #------------------------------------------------
    # Installed Application (WMI)
    #------------------------------------------------

        #-------------------------------------------------------------------------------------------
        # Variables
        #-------------------------------------------------------------------------------------------
            
            $TableName  = 'InvClientApplicationsFromWMIV2'   # must not contain _CL
            $DcrName    = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"

        #-------------------------------------------------------------------------------------------
        # Collecting data (in)
        #-------------------------------------------------------------------------------------------
            
            Write-Output "Collecting installed application information via WMI"

            $DataVariable = Get-WmiObject -Class Win32_Product

        #-------------------------------------------------------------------------------------------
        # Preparing data structure
        #-------------------------------------------------------------------------------------------

            $DataArray = @()
            ForEach ($InstApplication in $DataVariable)
                { 
                    If ($InstApplication.Name -ne $null)
                        {
                            $DataArray   += [pscustomobject]@{
                                                                IdentifyingNumber    = $InstApplication.IdentifyingNumber
                                                                Name                 = $InstApplication.Name
                                                                Vendor               = $InstApplication.Vendor
                                                                Version              = $InstApplication.Version
                                                                Caption              = $InstApplication.Caption
                                                             }
                        }
                }
            $DataVariable = $DataArray
    
            # add CollectionTime to existing array
            $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable

            # add Computer & UserLoggedOn info to existing array
            $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

            # Validating/fixing schema data structure of source data
            $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

        #-------------------------------------------------------------------------------------------
        # Create/Update Table Schema & Data Collection Rule schema, if missing
        #-------------------------------------------------------------------------------------------

            If ( ($TableDcrSchemaCreateUpdateAppId) -and ($TableDcrSchemaCreateUpdateAppSecret) )
                {
                    #-------------------------------------------------------------------------------------------
                    # Check if table and DCR exist, otherwise set flag to do initial setup
                    #-------------------------------------------------------------------------------------------
                        $DoInitialSetup = Get-AzLogAnalyticsTableAzDataCollectionRuleStatus -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -TableName $TableName -DcrName $DcrName `
                                                                                            -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId

                    #-------------------------------------------------------------------------------------------
                    # Create/update table in LogAnaytics and DCR
                    #-------------------------------------------------------------------------------------------

                    If ($DoInitialSetup -eq $true)
                        {
                            If ( $env:COMPUTERNAME -in $AzDcrDceTableCustomLogCreateMasterServer)    # only do this on reference/master machine
                                {
                                    Create-AzLogAnalyticsCustomLogTableDcr -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $DataVariable -TableName $TableName `
                                                                           -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId


                                    Create-AzDataCollectionRuleLogIngestCustomLog -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $DataVariable `
                                                                                  -DceName $DceName -DcrName $DcrName -TableName $TableName `
                                                                                  -LogIngestServicePricipleObjectId $AzDcrLogIngestServicePrincipalObjectId `
                                                                                  -AzDcrSetLogIngestApiAppPermissionsDcrLevel $AzDcrSetLogIngestApiAppPermissionsDcrLevel `
                                                                                  -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId
                                }
                        }

                    } # create table/DCR

        #-------------------------------------------------------------------------------------------
        # Upload data to LogAnalytics using DCR / DCE / Log Ingestion API
        #-------------------------------------------------------------------------------------------

            $AzDcrDceDetails = Get-AzDcrDceDetails -DcrName $DcrName -DceName $DceName `
                                                   -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId

            Post-AzLogAnalyticsLogIngestCustomLogDcrDce  -DceUri $AzDcrDceDetails[2] -DcrImmutableId $AzDcrDceDetails[6] `
                                                         -DcrStream $AzDcrDceDetails[7] -Data $DataVariable `
                                                         -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId
            # Write result to screen
            $DataVariable | Out-String | Write-Verbose 

#>

###############################################################
# APPLICATIONS (REGISTRY) [3]
###############################################################

    Write-output ""
    Write-output "#########################################################################################"
    write-output "INSTALLED APPLICATIONS INFORMATION [3]"
    Write-output ""
    write-output "Registry information about installed applications"
    Write-output ""

    #-------------------------------------------------------------------------------------------
    # Variables
    #-------------------------------------------------------------------------------------------
            
        $TableName  = 'InvClientApplicationsFromRegistryV21'   # must not contain _CL
        $DcrName    = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"

    #-------------------------------------------------------------------------------------------
    # Collecting data (in)
    #-------------------------------------------------------------------------------------------
            
        Write-Output "Collecting installed applications information via registry"

        $UninstallValuesX86 = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue
        $UninstallValuesX64 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue

        $DataVariable       = $UninstallValuesX86
        $DataVariable      += $UninstallValuesX64

    #-------------------------------------------------------------------------------------------
    # Preparing data structure
    #-------------------------------------------------------------------------------------------

        # removing apps without DisplayName fx KBs
        $DataVariable = $DataVariable | Where-Object { $_.DisplayName -ne $null }

        # convert PS object and remove PS class information
        $DataVariable = Convert-PSArrayToObjectFixStructure -Data $DataVariable

        # add CollectionTime to existing array
        $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable

        # add Computer & UserLoggedOn info to existing array
        $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

        # Get insight about the schema structure of an object BEFORE changes. Command is only needed to verify columns in schema
        # $SchemaBefore = Get-ObjectSchema -Data $DataVariable -ReturnFormat Array
        
        # Remove unnecessary columns in schema
        $DataVariable = Filter-ObjectExcludeProperty -Data $DataVariable -ExcludeProperty Memento*,Inno*,'(default)',1033

        # Validating/fixing schema data structure of source data
        $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

        # Aligning data structure with schema (requirement for DCR)
        $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable

    #-------------------------------------------------------------------------------------------
    # Create/Update Schema for LogAnalytics Table & Data Collection Rule schema
    #-------------------------------------------------------------------------------------------

        If ( ($TableDcrSchemaCreateUpdateAppId) -and ($TableDcrSchemaCreateUpdateAppSecret) )
            {
                #-----------------------------------------------------------------------------------------------
                # Check if table and DCR exist - or schema must be updated due to source object schema changes
                #-----------------------------------------------------------------------------------------------

                    # Get insight about the schema structure
                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnFormat Array

                    $StructureCheck = Get-AzLogAnalyticsTableAzDataCollectionRuleStatus -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -TableName $TableName -DcrName $DcrName -SchemaSourceObject $Schema `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId

                #-----------------------------------------------------------------------------------------------
                # Structure check = $true -> Create/update table & DCR with necessary schema
                #-----------------------------------------------------------------------------------------------

                    If ($StructureCheck -eq $true)
                        {
                            If ( ( $env:COMPUTERNAME -in $AzDcrDceTableCreateFromReferenceMachine) -or ($AzDcrDceTableCreateFromAnyMachine -eq $true) )    # manage table creations
                                {
                                    # build schema to be used for LogAnalytics Table
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType Table -ReturnFormat Hash

                                    CreateUpdate-AzLogAnalyticsCustomLogTableDcr -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema -TableName $TableName `
                                                                                 -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId


                                    # build schema to be used for DCR
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType DCR -ReturnFormat Hash

                                    CreateUpdate-AzDataCollectionRuleLogIngestCustomLog -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema `
                                                                                        -DceName $DceName -DcrName $DcrName -TableName $TableName `
                                                                                        -LogIngestServicePricipleObjectId $AzDcrLogIngestServicePrincipalObjectId `
                                                                                        -AzDcrSetLogIngestApiAppPermissionsDcrLevel $AzDcrSetLogIngestApiAppPermissionsDcrLevel `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId
                                }
                        }

                } # create table/DCR

    #-----------------------------------------------------------------------------------------------
    # Upload data to LogAnalytics using DCR / DCE / Log Ingestion API
    #-----------------------------------------------------------------------------------------------

        $AzDcrDceDetails = Get-AzDcrDceDetails -DcrName $DcrName -DceName $DceName `
                                               -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId

        Post-AzLogAnalyticsLogIngestCustomLogDcrDce  -DceUri $AzDcrDceDetails[2] -DcrImmutableId $AzDcrDceDetails[6] `
                                                     -DcrStream $AzDcrDceDetails[7] -Data $DataVariable `
                                                     -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId
        
        # Write result to screen
        $DataVariable | Out-String | Write-Verbose 



###############################################################
# ANTIVIRUS SECURITY CENTER [4]
###############################################################

    Write-output ""
    Write-output "#########################################################################################"
    Write-output "ANTIVIRUS INFORMATION SECURITY CENTER [4]"
    Write-output ""

    #-------------------------------------------------------------------------------------------
    # Variables
    #-------------------------------------------------------------------------------------------
            
        $TableName  = 'InvClientAntivirusV2'   # must not contain _CL
        $DcrName    = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"

    #-------------------------------------------------------------------------------------------
    # Collecting data (in)
    #-------------------------------------------------------------------------------------------
            
        Write-Output "Collecting antivirus information"

        $PrimaryAntivirus                           = 'NOT FOUND'
        $Alternative1Antivirus                      = 'NOT FOUND'
        $Alternative2Antivirus                      = 'NOT FOUND'
        $PrimaryAntivirusProduct                    = ""
        $PrimaryAntivirusEXE                        = ""
        $PrimaryAntivirusProductStateCode           = ""
        $PrimaryAntivirusProductStateTimestamp      = ""
        $PrimaryAntivirusDefinitionStatus           = ""
        $PrimaryAntivirusRealTimeStatus             = ""
        $Alternative1AntivirusProduct               = ""
        $Alternative1AntivirusEXE                   = ""
        $Alternative1AntivirusProductStateCode      = ""
        $Alternative1AntivirusProductStateTimestamp = ""
        $Alternative1AntivirusDefinitionStatus      = ""
        $Alternative1AntivirusRealTimeStatus        = ""
        $Alternative2AntivirusProduct               = ""
        $Alternative2AntivirusEXE                   = ""
        $Alternative2AntivirusProductStateCode      = ""
        $Alternative2AntivirusProductStateTimestamp = ""
        $Alternative2AntivirusDefinitionStatus      = ""
        $Alternative2AntivirusRealTimeStatus        = ""

        $AntiVirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct

        $ret = @()
        foreach($AntiVirusProduct in $AntiVirusProducts)
            {
                switch ($AntiVirusProduct.productState) 
                    {
                        "262144" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
                        "262160" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
                        "266240" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
                        "266256" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
                        "393216" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
                        "393232" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
                        "393488" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
                        "397312" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
                        "397328" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
                        "397584" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
                        "397568" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}          # Windows Defender
                        "393472" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}         # Windows Defender
                        "397584" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}         # Windows Defender
                        default {$defstatus = "Unknown" ;$rtstatus = "Unknown"}
                    }

                    # Detect Primary
                    If ( ($rtstatus -eq 'Enabled') -and ($PrimaryAntivirus -eq 'NOT FOUND') )
                        {
                            $PrimaryAntivirusProduct = $AntiVirusProduct.displayName
                            $PrimaryAntivirusEXE = $AntiVirusProduct.pathToSignedReportingExe
                            $PrimaryAntivirusProductStateCode = $AntiVirusProduct.productState
                            $PrimaryAntivirusProductStateTimestamp = $AntiVirusProduct.timestamp
                            $PrimaryAntivirusDefinitionStatus = $DefStatus
                            $PrimaryAntivirusRealTimeStatus = $rtstatus
                            $PrimaryAntivirus = 'FOUND'
                        }
        
                    # Detect Alternative 1
                    If ( ($rtstatus -eq 'disabled') -and ($Alternative1Antivirus -eq 'NOT FOUND') )
                        {
                            $Alternative1AntivirusProduct = $AntiVirusProduct.displayName
                            $Alternative1AntivirusEXE = $AntiVirusProduct.pathToSignedReportingExe
                            $Alternative1AntivirusProductStateCode = $AntiVirusProduct.productState
                            $Alternative1AntivirusProductStateTimestamp = $AntiVirusProduct.timestamp
                            $Alternative1AntivirusDefinitionStatus = $DefStatus
                            $Alternative1AntivirusRealTimeStatus = $rtstatus
                            $Alternative1Antivirus = 'FOUND'
                        }

                    # Detect Alternative 2
                    If ( ($rtstatus -eq 'disabled') -and ($Alternative1Antivirus -eq 'FOUND') -eq ($Alternative2Antivirus -eq 'NOT FOUND') )
                        {
                            $Alternative1AntivirusProduct = $AntiVirusProduct.displayName
                            $Alternative1AntivirusEXE = $AntiVirusProduct.pathToSignedReportingExe
                            $Alternative1AntivirusProductStateCode = $AntiVirusProduct.productState
                            $Alternative1AntivirusProductStateTimestamp = $AntiVirusProduct.timestamp
                            $Alternative1AntivirusDefinitionStatus = $DefStatus
                            $Alternative1AntivirusRealTimeStatus = $rtstatus
                            $Alternative1Antivirus = 'FOUND'
                        }
            }

    #-------------------------------------------------------------------------------------------
    # Preparing data structure
    #-------------------------------------------------------------------------------------------

        $DataVariable  = [pscustomobject]@{
                                            PrimaryAntivirusProduct = $PrimaryAntivirusProduct
                                            PrimaryAntivirusEXE = $PrimaryAntivirusEXE
                                            PrimaryAntivirusProductStateCode = $PrimaryAntivirusProductStateCode
                                            PrimaryAntivirusProductStateTimestamp = $PrimaryAntivirusProductStateTimestamp
                                            PrimaryAntivirusDefinitionStatus = $PrimaryAntivirusDefinitionStatus
                                            PrimaryAntivirusRealTimeStatus = $PrimaryAntivirusRealTimeStatus
                                            Alternative1AntivirusProduct = $Alternative1AntivirusProduct
                                            Alternative1AntivirusEXE = $Alternative1AntivirusEXE
                                            Alternative1AntivirusProductStateCode = $Alternative1AntivirusProduct
                                            Alternative1AntivirusProductStateTimestamp = $Alternative1AntivirusProductStateTimestamp
                                            Alternative1AntivirusDefinitionStatus = $Alternative1AntivirusDefinitionStatus
                                            Alternative1AntivirusRealTimeStatus = $Alternative1AntivirusRealTimeStatus
                                            Alternative2AntivirusProduct = $Alternative2AntivirusProduct
                                            Alternative2AntivirusEXE = $Alternative2AntivirusEXE
                                            Alternative2AntivirusProductStateCode = $Alternative2AntivirusProduct
                                            Alternative2AntivirusProductStateTimestamp = $Alternative2AntivirusProductStateTimestamp
                                            Alternative2AntivirusDefinitionStatus = $Alternative2AntivirusDefinitionStatus
                                            Alternative2AntivirusRealTimeStatus = $Alternative2AntivirusRealTimeStatus
                                          }
    
        # add CollectionTime to existing array
        $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable

        # add Computer & UserLoggedOn info to existing array
        $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

        # Validating/fixing schema data structure of source data
        $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

        # Aligning data structure with schema (requirement for DCR)
        $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable

    #-------------------------------------------------------------------------------------------
    # Create/Update Schema for LogAnalytics Table & Data Collection Rule schema
    #-------------------------------------------------------------------------------------------

        If ( ($TableDcrSchemaCreateUpdateAppId) -and ($TableDcrSchemaCreateUpdateAppSecret) )
            {
                #-----------------------------------------------------------------------------------------------
                # Check if table and DCR exist - or schema must be updated due to source object schema changes
                #-----------------------------------------------------------------------------------------------

                    # Get insight about the schema structure
                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnFormat Array

                    $StructureCheck = Get-AzLogAnalyticsTableAzDataCollectionRuleStatus -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -TableName $TableName -DcrName $DcrName -SchemaSourceObject $Schema `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId

                #-----------------------------------------------------------------------------------------------
                # Structure check = $true -> Create/update table & DCR with necessary schema
                #-----------------------------------------------------------------------------------------------

                    If ($StructureCheck -eq $true)
                        {
                            If ( ( $env:COMPUTERNAME -in $AzDcrDceTableCreateFromReferenceMachine) -or ($AzDcrDceTableCreateFromAnyMachine -eq $true) )    # manage table creations
                                {
                                    # build schema to be used for LogAnalytics Table
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType Table -ReturnFormat Hash

                                    CreateUpdate-AzLogAnalyticsCustomLogTableDcr -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema -TableName $TableName `
                                                                                 -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId


                                    # build schema to be used for DCR
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType DCR -ReturnFormat Hash

                                    CreateUpdate-AzDataCollectionRuleLogIngestCustomLog -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema `
                                                                                        -DceName $DceName -DcrName $DcrName -TableName $TableName `
                                                                                        -LogIngestServicePricipleObjectId $AzDcrLogIngestServicePrincipalObjectId `
                                                                                        -AzDcrSetLogIngestApiAppPermissionsDcrLevel $AzDcrSetLogIngestApiAppPermissionsDcrLevel `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId
                                }
                        }

                } # create table/DCR

    #-----------------------------------------------------------------------------------------------
    # Upload data to LogAnalytics using DCR / DCE / Log Ingestion API
    #-----------------------------------------------------------------------------------------------

        $AzDcrDceDetails = Get-AzDcrDceDetails -DcrName $DcrName -DceName $DceName `
                                               -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId

        Post-AzLogAnalyticsLogIngestCustomLogDcrDce  -DceUri $AzDcrDceDetails[2] -DcrImmutableId $AzDcrDceDetails[6] `
                                                     -DcrStream $AzDcrDceDetails[7] -Data $DataVariable `
                                                     -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId
        
        # Write result to screen
        $DataVariable | Out-String | Write-Verbose 



###############################################################
# MICROSOFT DEFENDER ANTIVIRUS [5]
###############################################################

    Write-output ""
    Write-output "#########################################################################################"
    Write-output "MICROSOFT DEFENDER ANTIVIRUS INFORMATION [5]"
    Write-output ""

    #-------------------------------------------------------------------------------------------
    # Variables
    #-------------------------------------------------------------------------------------------
            
        $TableName  = 'InvClientDefenderAvV2'   # must not contain _CL
        $DcrName    = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"

    #-------------------------------------------------------------------------------------------
    # Collecting data (in)
    #-------------------------------------------------------------------------------------------
            
        Write-Output "Collecting Microsoft Defender Antivirus information"

        $MPComputerStatus = Get-MpComputerStatus
        $MPPreference = Get-MpPreference

    #-------------------------------------------------------------------------------------------
    # Preparing data structure
    #-------------------------------------------------------------------------------------------

        If ($MPComputerStatus) 
            {
                $MPComputerStatusObject = [PSCustomObject]@{
                                                                MPComputerStatusFound = $True
                                                            }
            }
        Else
            {
                $MPComputerStatusObject = [PSCustomObject]@{
                                                                MPComputerStatusFound = $false
                                                            }
            }

    # Collecting Defender AV MPPreference-settings
        $MPPreference = Get-MpPreference
        If ($MPPreference) 
            {
                $MPPreferenceObject = [PSCustomObject]@{
                                                            MPPreferenceFound = $True
                                                        }
            }
        Else
            {
                $MPPreferenceObject = [PSCustomObject]@{
                                                            MPPreferenceFound = $False
                                                        }
            }

    # Preparing data
        $DataVariable = [PSCustomObject]@{
            MPComputerStatusFound                         = $MPComputerStatusObject.MPComputerStatusFound
            MPPreferenceFound                             = $MPPreferenceObject.MPPreferenceFound
            AMEngineVersion                               = $MPComputerStatus.AMEngineVersion
            AMProductVersion                              = $MPComputerStatus.AMProductVersion
            AMRunningMode                                 = $MPComputerStatus.AMRunningMode
            AMServiceEnabled                              = $MPComputerStatus.AMServiceEnabled
            AMServiceVersion                              = $MPComputerStatus.AMServiceVersion
            AntispywareEnabled                            = $MPComputerStatus.AntispywareEnabled
            AntispywareSignatureAge                       = $MPComputerStatus.AntispywareSignatureAge
            AntispywareSignatureLastUpdated               = $MPComputerStatus.AntispywareSignatureLastUpdated
            AntispywareSignatureVersion                   = $MPComputerStatus.AntispywareSignatureVersion
            AntivirusEnabled                              = $MPComputerStatus.AntivirusEnabled
            AntivirusSignatureAge                         = $MPComputerStatus.AntivirusSignatureAge
            AntivirusSignatureLastUpdated                 = $MPComputerStatus.AntivirusSignatureLastUpdated
            AntivirusSignatureVersion                     = $MPComputerStatus.AntivirusSignatureVersion
            BehaviorMonitorEnabled                        = $MPComputerStatus.BehaviorMonitorEnabled
            DefenderSignaturesOutOfDate                   = $MPComputerStatus.DefenderSignaturesOutOfDate
            DeviceControlDefaultEnforcement               = $MPComputerStatus.DeviceControlDefaultEnforcement
            DeviceControlPoliciesLastUpdated              = $MPComputerStatus.DeviceControlPoliciesLastUpdated
            DeviceControlState                            = $MPComputerStatus.DeviceControlState
            FullScanAge                                   = $MPComputerStatus.FullScanAge
            FullScanEndTime                               = $MPComputerStatus.FullScanEndTime
            FullScanOverdue                               = $MPComputerStatus.FullScanOverdue
            FullScanRequired                              = $MPComputerStatus.FullScanRequired
            FullScanSignatureVersion                      = $MPComputerStatus.FullScanSignatureVersion
            FullScanStartTime                             = $MPComputerStatus.FullScanStartTime
            IoavProtectionEnabled                         = $MPComputerStatus.IoavProtectionEnabled
            IsTamperProtected                             = $MPComputerStatus.IsTamperProtected
            IsVirtualMachine                              = $MPComputerStatus.IsVirtualMachine
            LastFullScanSource                            = $MPComputerStatus.LastFullScanSource
            LastQuickScanSource                           = $MPComputerStatus.LastQuickScanSource
            NISEnabled                                    = $MPComputerStatus.NISEnabled
            NISEngineVersion                              = $MPComputerStatus.NISEngineVersion
            NISSignatureAge                               = $MPComputerStatus.NISSignatureAge
            NISSignatureLastUpdated                       = $MPComputerStatus.NISSignatureLastUpdated
            NISSignatureVersion                           = $MPComputerStatus.NISSignatureVersion
            OnAccessProtectionEnabled                     = $MPComputerStatus.OnAccessProtectionEnabled
            ProductStatus                                 = $MPComputerStatus.ProductStatus
            QuickScanAge                                  = $MPComputerStatus.QuickScanAge
            QuickScanEndTime                              = $MPComputerStatus.QuickScanEndTime
            QuickScanOverdue                              = $MPComputerStatus.QuickScanOverdue
            QuickScanSignatureVersion                     = $MPComputerStatus.QuickScanSignatureVersion
            QuickScanStartTime                            = $MPComputerStatus.QuickScanStartTime
            RealTimeProtectionEnabled                     = $MPComputerStatus.RealTimeProtectionEnabled
            RealTimeScanDirection                         = $MPComputerStatus.RealTimeScanDirection
            RebootRequired                                = $MPComputerStatus.RebootRequired
            TamperProtectionSource                        = $MPComputerStatus.TamperProtectionSource
            TDTMode                                       = $MPComputerStatus.TDTMode
            TDTStatus                                     = $MPComputerStatus.TDTStatus
            TDTTelemetry                                  = $MPComputerStatus.TDTTelemetry
            TroubleShootingDailyMaxQuota                  = $MPComputerStatus.TroubleShootingDailyMaxQuota
            TroubleShootingDailyQuotaLeft                 = $MPComputerStatus.TroubleShootingDailyQuotaLeft
            TroubleShootingEndTime                        = $MPComputerStatus.TroubleShootingEndTime
            TroubleShootingExpirationLeft                 = $MPComputerStatus.TroubleShootingExpirationLeft
            TroubleShootingMode                           = $MPComputerStatus.TroubleShootingMode
            TroubleShootingModeSource                     = $MPComputerStatus.TroubleShootingModeSource
            TroubleShootingQuotaResetTime                 = $MPComputerStatus.TroubleShootingQuotaResetTime
            TroubleShootingStartTime                      = $MPComputerStatus.TroubleShootingStartTime
            AllowDatagramProcessingOnWinServer            = $MPPreference.AllowDatagramProcessingOnWinServer
            AllowNetworkProtectionDownLevel               = $MPPreference.AllowNetworkProtectionDownLevel
            AllowNetworkProtectionOnWinServer             = $MPPreference.AllowNetworkProtectionOnWinServer
            AllowSwitchToAsyncInspection                  = $MPPreference.AllowSwitchToAsyncInspection
            AttackSurfaceReductionOnlyExclusions          = $MPPreference.AttackSurfaceReductionOnlyExclusions
            AttackSurfaceReductionRules_Actions           = $MPPreference.AttackSurfaceReductionRules_Actions
            AttackSurfaceReductionRules_Ids               = $MPPreference.AttackSurfaceReductionRules_Ids
            CheckForSignaturesBeforeRunningScan           = $MPPreference.CheckForSignaturesBeforeRunningScan 
            CloudBlockLevel                               = $MPPreference.CloudBlockLevel 
            CloudExtendedTimeout                          = $MPPreference.CloudExtendedTimeout
            ComputerID                                    = $MPPreference.ComputerID
            ControlledFolderAccessAllowedApplications     = $MPPreference.ControlledFolderAccessAllowedApplications
            ControlledFolderAccessProtectedFolders        = $MPPreference.ControlledFolderAccessProtectedFolders
            DefinitionUpdatesChannel                      = $MPPreference.DefinitionUpdatesChannel
            DisableArchiveScanning                        = $MPPreference.DisableArchiveScanning
            DisableAutoExclusions                         = $MPPreference.DisableAutoExclusions
            DisableBehaviorMonitoring                     = $MPPreference.DisableBehaviorMonitoring
            DisableBlockAtFirstSeen                       = $MPPreference.DisableBlockAtFirstSeen
            DisableCatchupFullScan                        = $MPPreference.DisableCatchupFullScan
            DisableCatchupQuickScan                       = $MPPreference.DisableCatchupQuickScan
            DisableCpuThrottleOnIdleScans                 = $MPPreference.DisableCpuThrottleOnIdleScans
            DisableDatagramProcessing                     = $MPPreference.DisableDatagramProcessing 
            DisableDnsOverTcpParsing                      = $MPPreference.DisableDnsOverTcpParsing
            DisableDnsParsing                             = $MPPreference.DisableDnsParsing
            DisableEmailScanning                          = $MPPreference.DisableEmailScanning
            DisableFtpParsing                             = $MPPreference.DisableFtpParsing
            DisableGradualRelease                         = $MPPreference.DisableGradualRelease 
            DisableHttpParsing                            = $MPPreference.DisableHttpParsing
            DisableInboundConnectionFiltering             = $MPPreference.DisableInboundConnectionFiltering 
            DisableIOAVProtection                         = $MPPreference.DisableIOAVProtection
            DisableNetworkProtectionPerfTelemetry         = $MPPreference.DisableNetworkProtectionPerfTelemetry
            DisablePrivacyMode                            = $MPPreference.DisablePrivacyMode
            DisableRdpParsing                             = $MPPreference.DisableRdpParsing
            DisableRealtimeMonitoring                     = $MPPreference.DisableRealtimeMonitoring
            DisableRemovableDriveScanning                 = $MPPreference.DisableRemovableDriveScanning
            DisableRestorePoint                           = $MPPreference.DisableRestorePoint
            DisableScanningMappedNetworkDrivesForFullScan = $MPPreference.DisableScanningMappedNetworkDrivesForFullScan
            DisableScanningNetworkFiles                   = $MPPreference.DisableScanningNetworkFiles
            DisableScriptScanning                         = $MPPreference.DisableScriptScanning
            DisableSshParsing                             = $MPPreference.DisableSshParsing
            DisableTDTFeature                             = $MPPreference.DisableTDTFeature
            DisableTlsParsing                             = $MPPreference.DisableTlsParsing
            EnableControlledFolderAccess                  = $MPPreference.EnableControlledFolderAccess
            EnableDnsSinkhole                             = $MPPreference.EnableDnsSinkhole
            EnableFileHashComputation                     = $MPPreference.EnableFileHashComputation 
            EnableFullScanOnBatteryPower                  = $MPPreference.EnableFullScanOnBatteryPower
            EnableLowCpuPriority                          = $MPPreference.EnableLowCpuPriority
            EnableNetworkProtection                       = $MPPreference.EnableNetworkProtection
            EngineUpdatesChannel                          = $MPPreference.EngineUpdatesChannel
            ExclusionExtension                            = $MPPreference.ExclusionExtension
            ExclusionIpAddress                            = $MPPreference.ExclusionIpAddress
            ExclusionPath                                 = $MPPreference.ExclusionPath
            ExclusionProcess                              = $MPPreference.ExclusionProcess
            ForceUseProxyOnly                             = $MPPreference.ForceUseProxyOnly
            HighThreatDefaultAction                       = $MPPreference.HighThreatDefaultAction
            LowThreatDefaultAction                        = $MPPreference.LowThreatDefaultAction
            MAPSReporting                                 = $MPPreference.MAPSReporting
            MeteredConnectionUpdates                      = $MPPreference.MeteredConnectionUpdates
            ModerateThreatDefaultAction                   = $MPPreference.ModerateThreatDefaultAction
            PlatformUpdatesChannel                        = $MPPreference.PlatformUpdatesChannel 
            ProxyBypass                                   = $MPPreference.ProxyBypass
            ProxyPacUrl                                   = $MPPreference.ProxyPacUrl
            ProxyServer                                   = $MPPreference.ProxyServer
            PUAProtection                                 = $MPPreference.PUAProtection 
            QuarantinePurgeItemsAfterDelay                = $MPPreference.QuarantinePurgeItemsAfterDelay
            RandomizeScheduleTaskTimes                    = $MPPreference.RandomizeScheduleTaskTimes
            RemediationScheduleDay                        = $MPPreference.RemediationScheduleDay
            RemediationScheduleTime                       = $MPPreference.RemediationScheduleTime
            ReportingAdditionalActionTimeOut              = $MPPreference.ReportingAdditionalActionTimeOut
            ReportingCriticalFailureTimeOut               = $MPPreference.ReportingCriticalFailureTimeOut
            ReportingNonCriticalTimeOut                   = $MPPreference.ReportingNonCriticalTimeOut
            ScanAvgCPULoadFactor                          = $MPPreference.ScanAvgCPULoadFactor 
            ScanOnlyIfIdleEnabled                         = $MPPreference.ScanOnlyIfIdleEnabled
            ScanParameters                                = $MPPreference.ScanParameters
            ScanPurgeItemsAfterDelay                      = $MPPreference.ScanPurgeItemsAfterDelay
            ScanScheduleDay                               = $MPPreference.ScanScheduleDay
            ScanScheduleOffset                            = $MPPreference.ScanScheduleOffset
            ScanScheduleQuickScanTime                     = $MPPreference.ScanScheduleQuickScanTime
            ScanScheduleTime                              = $MPPreference.ScanScheduleTime 
            SchedulerRandomizationTime                    = $MPPreference.SchedulerRandomizationTime
            ServiceHealthReportInterval                   = $MPPreference.ServiceHealthReportInterval
            SevereThreatDefaultAction                     = $MPPreference.SevereThreatDefaultAction
            SharedSignaturesPath                          = $MPPreference.SharedSignaturesPath
            SignatureAuGracePeriod                        = $MPPreference.SignatureAuGracePeriod
            SignatureBlobFileSharesSources                = $MPPreference.SignatureBlobFileSharesSources
            SignatureBlobUpdateInterval                   = $MPPreference.SignatureBlobUpdateInterval
            SignatureDefinitionUpdateFileSharesSources    = $MPPreference.SignatureDefinitionUpdateFileSharesSources
            SignatureDisableUpdateOnStartupWithoutEngine  = $MPPreference.SignatureDisableUpdateOnStartupWithoutEngine
            SignatureFallbackOrder                        = $MPPreference.SignatureFallbackOrder
            SignatureFirstAuGracePeriod                   = $MPPreference.SignatureFirstAuGracePeriod
            SignatureScheduleDay                          = $MPPreference.SignatureScheduleDay
            SignatureScheduleTime                         = $MPPreference.SignatureScheduleTime
            SignatureUpdateCatchupInterval                = $MPPreference.SignatureUpdateCatchupInterval
            SignatureUpdateInterval                       = $MPPreference.SignatureUpdateInterval
            SubmitSamplesConsent                          = $MPPreference.SubmitSamplesConsent
            ThreatIDDefaultAction_Actions                 = $MPPreference.ThreatIDDefaultAction_Actions
            ThreatIDDefaultAction_Ids                     = $MPPreference.ThreatIDDefaultAction_Ids
            ThrottleForScheduledScanOnly                  = $MPPreference.ThrottleForScheduledScanOnly
            TrustLabelProtectionStatus                    = $MPPreference.TrustLabelProtectionStatus
            UILockdown                                    = $MPPreference.UILockdown 
            UnknownThreatDefaultAction                    = $MPPreference.UnknownThreatDefaultAction
        }
    
        # add CollectionTime to existing array
        $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable

        # add Computer & UserLoggedOn info to existing array
        $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

        # Validating/fixing schema data structure of source data
        $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

        # Aligning data structure with schema (requirement for DCR)
        $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable

    #-------------------------------------------------------------------------------------------
    # Create/Update Schema for LogAnalytics Table & Data Collection Rule schema
    #-------------------------------------------------------------------------------------------

        If ( ($TableDcrSchemaCreateUpdateAppId) -and ($TableDcrSchemaCreateUpdateAppSecret) )
            {
                #-----------------------------------------------------------------------------------------------
                # Check if table and DCR exist - or schema must be updated due to source object schema changes
                #-----------------------------------------------------------------------------------------------

                    # Get insight about the schema structure
                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnFormat Array

                    $StructureCheck = Get-AzLogAnalyticsTableAzDataCollectionRuleStatus -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -TableName $TableName -DcrName $DcrName -SchemaSourceObject $Schema `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId

                #-----------------------------------------------------------------------------------------------
                # Structure check = $true -> Create/update table & DCR with necessary schema
                #-----------------------------------------------------------------------------------------------

                    If ($StructureCheck -eq $true)
                        {
                            If ( ( $env:COMPUTERNAME -in $AzDcrDceTableCreateFromReferenceMachine) -or ($AzDcrDceTableCreateFromAnyMachine -eq $true) )    # manage table creations
                                {
                                    # build schema to be used for LogAnalytics Table
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType Table -ReturnFormat Hash

                                    CreateUpdate-AzLogAnalyticsCustomLogTableDcr -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema -TableName $TableName `
                                                                                 -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId


                                    # build schema to be used for DCR
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType DCR -ReturnFormat Hash

                                    CreateUpdate-AzDataCollectionRuleLogIngestCustomLog -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema `
                                                                                        -DceName $DceName -DcrName $DcrName -TableName $TableName `
                                                                                        -LogIngestServicePricipleObjectId $AzDcrLogIngestServicePrincipalObjectId `
                                                                                        -AzDcrSetLogIngestApiAppPermissionsDcrLevel $AzDcrSetLogIngestApiAppPermissionsDcrLevel `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId
                                }
                        }

                } # create table/DCR

    #-----------------------------------------------------------------------------------------------
    # Upload data to LogAnalytics using DCR / DCE / Log Ingestion API
    #-----------------------------------------------------------------------------------------------

        $AzDcrDceDetails = Get-AzDcrDceDetails -DcrName $DcrName -DceName $DceName `
                                               -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId

        Post-AzLogAnalyticsLogIngestCustomLogDcrDce  -DceUri $AzDcrDceDetails[2] -DcrImmutableId $AzDcrDceDetails[6] `
                                                     -DcrStream $AzDcrDceDetails[7] -Data $DataVariable `
                                                     -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId
        
        # Write result to screen
        $DataVariable | Out-String | Write-Verbose 


###############################################################
# Office [6]
###############################################################

    Write-output ""
    Write-output "#########################################################################################"
    Write-output "OFFICE INFORMATION [6]"
    Write-output ""

    #-------------------------------------------------------------------------------------------
    # Variables
    #-------------------------------------------------------------------------------------------
            
        $TableName  = 'InvClientOfficeInfoV2'   # must not contain _CL
        $DcrName    = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"


    #-------------------------------------------------------------------------------------------
    # Collecting data (in)
    #-------------------------------------------------------------------------------------------
            
        # Default Values
        $OfficeDescription = ""
        $OfficeProductSKU = ""
        $OfficeVersionBuild = ""
        $OfficeInstallationPath = ""
        $OfficeUpdateEnabled = ""
        $OfficeUpdateChannel = ""
        $OfficeUpdateChannelName = ""
        $OneDriveInstalled = ""
        $TeamsInstalled = ""
        $FoundO365Office = $false

        #-----------------------------------------
        # Looking for Microsoft 365 Office
        #-----------------------------------------
            $OfficeVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration" -ErrorAction SilentlyContinue

                #-------------------------------------------------------------------------------------------
                # Preparing data structure
                #-------------------------------------------------------------------------------------------
                If ($OfficeVersion)
                    {
                        $FoundO365Office = $True

                        $DataVariable = $OfficeVersion

                        # convert PS array to PSCustomObject and remove PS class information
                        $DataVariable = Convert-PSArrayToObjectFixStructure -data $DataVariable

                        # add CollectionTime to existing array
                        $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable

                        # add Computer & UserLoggedOn info to existing array
                        $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

                        # Validating/fixing schema data structure of source data
                        $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

                        # Aligning data structure with schema (requirement for DCR)
                        $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable
                    }

        #-----------------------------------------
        # Looking for Office 2016 (standalone)
        #-----------------------------------------
            $OfficeInstallationPath = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Office\16.0\Word\InstallRoot" -Name Path -ErrorAction SilentlyContinue

                #-------------------------------------------------------------------------------------------
                # Preparing data structure
                #-------------------------------------------------------------------------------------------
                If ( ($OfficeInstallationPath) -and ($FoundO365Office -eq $false) )
                    {
                        $OfficeVersionBuild = $Application.Version

                        Switch -Wildcard ($OfficeVersionBuild)
                            {
                                "16.*"    {$OfficeDescription = "Office 2016"}
                            }
                        $OfficeInstallationPath = $OfficeInstallationPath
                        $OfficeUpdateEnabled = $Officeversion.UpdatesChannel
                        $OfficeProductSKU = $OfficeVersion.ProductReleaseIds

                        $DataArray = [pscustomobject]@{
                                                        OfficeDescription       = $OfficeDescription
                                                        OfficeProductSKU        = $OfficeProductSKU
                                                        OfficeVersionBuild      = $OfficeVersionBuild
                                                        OfficeInstallationPath  = $OfficeInstallationPath
                                                        OfficeUpdateEnabled     = $OfficeUpdateEnabled
                                                        OfficeUpdateChannel     = $OfficeUpdateChannel
                                                        OfficeUpdateChannelName = $OfficeUpdateChannelName
                                                      }

                        $DataVariable = $DataArray

                        # add CollectionTime to existing array
                        $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable

                        # add Computer & UserLoggedOn info to existing array
                        $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

                        # Validating/fixing schema data structure of source data
                        $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

                        # Aligning data structure with schema (requirement for DCR)
                        $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable
                    }

        #-----------------------------------------
        # Looking for Office 2013
        #-----------------------------------------

            $OfficeInstallationPath = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Office\15.0\Word\InstallRoot" -Name Path -ErrorAction SilentlyContinue

                #-------------------------------------------------------------------------------------------
                # Preparing data structure
                #-------------------------------------------------------------------------------------------

                If ($OfficeInstallationPath)
                    {
                        $OfficeVersionBuild = $Application.Version

                        Switch -Wildcard ($OfficeVersionBuild)
                            {
                                "15.*"    {$OfficeDescription = "Office 2013"}
                            }

                        $OfficeInstallationPath = $OfficeInstallationPath
                        $OfficeUpdateEnabled = "N/A"
                        $OfficeProductSKU = "N/A"

                        $DataArray = [pscustomobject]@{
                                                        OfficeDescription       = $OfficeDescription
                                                        OfficeProductSKU        = $OfficeProductSKU
                                                        OfficeVersionBuild      = $OfficeVersionBuild
                                                        OfficeInstallationPath  = $OfficeInstallationPath
                                                        OfficeUpdateEnabled     = $OfficeUpdateEnabled
                                                        OfficeUpdateChannel     = $OfficeUpdateChannel
                                                        OfficeUpdateChannelName = $OfficeUpdateChannelName
                                                      }

                        $DataVariable = $DataArray

                        # add CollectionTime to existing array
                        $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable

                        # add Computer & UserLoggedOn info to existing array
                        $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

                        # Validating/fixing schema data structure of source data
                        $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

                        # Aligning data structure with schema (requirement for DCR)
                        $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable
                    }

    #-------------------------------------------------------------------------------------------
    # Create/Update Schema for LogAnalytics Table & Data Collection Rule schema
    #-------------------------------------------------------------------------------------------

        If ( ($TableDcrSchemaCreateUpdateAppId) -and ($TableDcrSchemaCreateUpdateAppSecret) )
            {
                #-----------------------------------------------------------------------------------------------
                # Check if table and DCR exist - or schema must be updated due to source object schema changes
                #-----------------------------------------------------------------------------------------------

                    # Get insight about the schema structure
                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnFormat Array

                    $StructureCheck = Get-AzLogAnalyticsTableAzDataCollectionRuleStatus -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -TableName $TableName -DcrName $DcrName -SchemaSourceObject $Schema `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId

                #-----------------------------------------------------------------------------------------------
                # Structure check = $true -> Create/update table & DCR with necessary schema
                #-----------------------------------------------------------------------------------------------

                    If ($StructureCheck -eq $true)
                        {
                            If ( ( $env:COMPUTERNAME -in $AzDcrDceTableCreateFromReferenceMachine) -or ($AzDcrDceTableCreateFromAnyMachine -eq $true) )    # manage table creations
                                {
                                    # build schema to be used for LogAnalytics Table
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType Table -ReturnFormat Hash

                                    CreateUpdate-AzLogAnalyticsCustomLogTableDcr -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema -TableName $TableName `
                                                                                 -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId


                                    # build schema to be used for DCR
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType DCR -ReturnFormat Hash

                                    CreateUpdate-AzDataCollectionRuleLogIngestCustomLog -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema `
                                                                                        -DceName $DceName -DcrName $DcrName -TableName $TableName `
                                                                                        -LogIngestServicePricipleObjectId $AzDcrLogIngestServicePrincipalObjectId `
                                                                                        -AzDcrSetLogIngestApiAppPermissionsDcrLevel $AzDcrSetLogIngestApiAppPermissionsDcrLevel `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId
                                }
                        }

                } # create table/DCR

    #-----------------------------------------------------------------------------------------------
    # Upload data to LogAnalytics using DCR / DCE / Log Ingestion API
    #-----------------------------------------------------------------------------------------------

        $AzDcrDceDetails = Get-AzDcrDceDetails -DcrName $DcrName -DceName $DceName `
                                               -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId

        Post-AzLogAnalyticsLogIngestCustomLogDcrDce  -DceUri $AzDcrDceDetails[2] -DcrImmutableId $AzDcrDceDetails[6] `
                                                     -DcrStream $AzDcrDceDetails[7] -Data $DataVariable `
                                                     -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId
        
        # Write result to screen
        $DataVariable | Out-String | Write-Verbose 



###############################################################
# VPN CLIENT [7]
###############################################################

    Write-output ""
    Write-output "#########################################################################################"
    Write-output "VPN INFORMATION [7]"
    Write-output ""

    #-------------------------------------------------------------------------------------------
    # Variables
    #-------------------------------------------------------------------------------------------
            
        $TableName  = 'InvClientVpnV2'   # must not contain _CL
        $DcrName    = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"

    #-------------------------------------------------------------------------------------------
    # Collecting data (in)
    #-------------------------------------------------------------------------------------------
            
        Write-Output "Collecting VPN information"

        # Default Values
            $VPNSoftware = ""
            $VPNVersion = ""

        # Checking
            ForEach ($Application in $InstalledApplications)
                {
                    #-----------------------------------------
                    # Looking for Cisco AnyConnect
                    #-----------------------------------------
                    If ( ($Application.Vendor -like 'Cisco*') -and ($Application.name -like "*AnyConnect*") )
                        {
                            $VPNSoftware = $Application.Name
                            $VPNVersion = $Application.Version
                        }

                    #-----------------------------------------
                    # Looking for Palo Alto
                    #-----------------------------------------
                    If ( ($Application.Vendor -like 'Palo Alto*') -and ($Application.name -like "*Global*") )
                        {
                            $VPNSoftware = $Application.Name
                            $VPNVersion = $Application.Version
                        }
                }

    #-------------------------------------------------------------------------------------------
    # Preparing data structure
    #-------------------------------------------------------------------------------------------

        $DataVariable = [pscustomobject]@{
                                            VPNSoftware     = $VPNSoftware
                                            VPNVersion      = $VPNVersion
                                         }

            
        # add CollectionTime to existing array
        $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable

        # add Computer & UserLoggedOn info to existing array
        $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

        # Validating/fixing schema data structure of source data
        $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

        # Aligning data structure with schema (requirement for DCR)
        $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable

    #-------------------------------------------------------------------------------------------
    # Create/Update Schema for LogAnalytics Table & Data Collection Rule schema
    #-------------------------------------------------------------------------------------------

        If ( ($TableDcrSchemaCreateUpdateAppId) -and ($TableDcrSchemaCreateUpdateAppSecret) )
            {
                #-----------------------------------------------------------------------------------------------
                # Check if table and DCR exist - or schema must be updated due to source object schema changes
                #-----------------------------------------------------------------------------------------------

                    # Get insight about the schema structure
                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnFormat Array

                    $StructureCheck = Get-AzLogAnalyticsTableAzDataCollectionRuleStatus -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -TableName $TableName -DcrName $DcrName -SchemaSourceObject $Schema `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId

                #-----------------------------------------------------------------------------------------------
                # Structure check = $true -> Create/update table & DCR with necessary schema
                #-----------------------------------------------------------------------------------------------

                    If ($StructureCheck -eq $true)
                        {
                            If ( ( $env:COMPUTERNAME -in $AzDcrDceTableCreateFromReferenceMachine) -or ($AzDcrDceTableCreateFromAnyMachine -eq $true) )    # manage table creations
                                {
                                    # build schema to be used for LogAnalytics Table
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType Table -ReturnFormat Hash

                                    CreateUpdate-AzLogAnalyticsCustomLogTableDcr -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema -TableName $TableName `
                                                                                 -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId


                                    # build schema to be used for DCR
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType DCR -ReturnFormat Hash

                                    CreateUpdate-AzDataCollectionRuleLogIngestCustomLog -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema `
                                                                                        -DceName $DceName -DcrName $DcrName -TableName $TableName `
                                                                                        -LogIngestServicePricipleObjectId $AzDcrLogIngestServicePrincipalObjectId `
                                                                                        -AzDcrSetLogIngestApiAppPermissionsDcrLevel $AzDcrSetLogIngestApiAppPermissionsDcrLevel `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId
                                }
                        }

                } # create table/DCR

    #-----------------------------------------------------------------------------------------------
    # Upload data to LogAnalytics using DCR / DCE / Log Ingestion API
    #-----------------------------------------------------------------------------------------------

        $AzDcrDceDetails = Get-AzDcrDceDetails -DcrName $DcrName -DceName $DceName `
                                               -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId

        Post-AzLogAnalyticsLogIngestCustomLogDcrDce  -DceUri $AzDcrDceDetails[2] -DcrImmutableId $AzDcrDceDetails[6] `
                                                     -DcrStream $AzDcrDceDetails[7] -Data $DataVariable `
                                                     -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId
        
        # Write result to screen
        $DataVariable | Out-String | Write-Verbose 


###############################################################
# LAPS [8]
###############################################################

    Write-output ""
    Write-output "#########################################################################################"
    Write-output "LAPS INFORMATION [8]"
    Write-output ""

    #-------------------------------------------------------------------------------------------
    # Variables
    #-------------------------------------------------------------------------------------------
            
        $TableName  = 'InvClientLAPSInfoV2'   # must not contain _CL
        $DcrName    = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"

    #-------------------------------------------------------------------------------------------
    # Collecting data (in)
    #-------------------------------------------------------------------------------------------
            
        Write-Output "Collecting LAPS information"

        # Default Values
            $LAPSSoftware = ""
            $LAPSVersion = ""

        # Checking
            ForEach ($Application in $InstalledApplications)
                {
                    #-----------------------------------------
                    # Looking for LAPS
                    #-----------------------------------------
                    If ( ($Application.Vendor -like 'Microsoft*') -and ($Application.name -like "*Local Administrator Password*") )
                        {
                            $LAPSSoftware = $Application.Name
                            $LAPSVersion = $Application.Version
                        }
                }

    #-------------------------------------------------------------------------------------------
    # Preparing data structure
    #-------------------------------------------------------------------------------------------

        $DataVariable = [pscustomobject]@{
                                            LAPSSoftware    = $LAPSSoftware
                                            LAPSVersion     = $LAPSVersion
                                         }

        # add CollectionTime to existing array
        $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable

        # add Computer & UserLoggedOn info to existing array
        $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

        # Validating/fixing schema data structure of source data
        $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

        # Aligning data structure with schema (requirement for DCR)
        $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable

    #-------------------------------------------------------------------------------------------
    # Create/Update Schema for LogAnalytics Table & Data Collection Rule schema
    #-------------------------------------------------------------------------------------------

        If ( ($TableDcrSchemaCreateUpdateAppId) -and ($TableDcrSchemaCreateUpdateAppSecret) )
            {
                #-----------------------------------------------------------------------------------------------
                # Check if table and DCR exist - or schema must be updated due to source object schema changes
                #-----------------------------------------------------------------------------------------------

                    # Get insight about the schema structure
                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnFormat Array

                    $StructureCheck = Get-AzLogAnalyticsTableAzDataCollectionRuleStatus -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -TableName $TableName -DcrName $DcrName -SchemaSourceObject $Schema `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId

                #-----------------------------------------------------------------------------------------------
                # Structure check = $true -> Create/update table & DCR with necessary schema
                #-----------------------------------------------------------------------------------------------

                    If ($StructureCheck -eq $true)
                        {
                            If ( ( $env:COMPUTERNAME -in $AzDcrDceTableCreateFromReferenceMachine) -or ($AzDcrDceTableCreateFromAnyMachine -eq $true) )    # manage table creations
                                {
                                    # build schema to be used for LogAnalytics Table
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType Table -ReturnFormat Hash

                                    CreateUpdate-AzLogAnalyticsCustomLogTableDcr -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema -TableName $TableName `
                                                                                 -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId


                                    # build schema to be used for DCR
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType DCR -ReturnFormat Hash

                                    CreateUpdate-AzDataCollectionRuleLogIngestCustomLog -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema `
                                                                                        -DceName $DceName -DcrName $DcrName -TableName $TableName `
                                                                                        -LogIngestServicePricipleObjectId $AzDcrLogIngestServicePrincipalObjectId `
                                                                                        -AzDcrSetLogIngestApiAppPermissionsDcrLevel $AzDcrSetLogIngestApiAppPermissionsDcrLevel `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId
                                }
                        }

                } # create table/DCR

    #-----------------------------------------------------------------------------------------------
    # Upload data to LogAnalytics using DCR / DCE / Log Ingestion API
    #-----------------------------------------------------------------------------------------------

        $AzDcrDceDetails = Get-AzDcrDceDetails -DcrName $DcrName -DceName $DceName `
                                               -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId

        Post-AzLogAnalyticsLogIngestCustomLogDcrDce  -DceUri $AzDcrDceDetails[2] -DcrImmutableId $AzDcrDceDetails[6] `
                                                     -DcrStream $AzDcrDceDetails[7] -Data $DataVariable `
                                                     -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId
        
        # Write result to screen
        $DataVariable | Out-String | Write-Verbose 


###############################################################
# ADMIN BY REQUEST [9]
###############################################################

    Write-output ""
    Write-output "#########################################################################################"
    Write-output "ADMIN BY REQUEST [9]"
    Write-output ""

    #-------------------------------------------------------------------------------------------
    # Variables
    #-------------------------------------------------------------------------------------------
            
        $TableName  = 'InvClientAdminByRequestV2'   # must not contain _CL
        $DcrName    = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"

    #-------------------------------------------------------------------------------------------
    # Collecting data (in)
    #-------------------------------------------------------------------------------------------
            
        Write-Output "Collecting Admin By Request information"

        # Default Values
        $ABRSoftware = ""
        $ABRVersion = ""

        ForEach ($Application in $InstalledApplications)
            {
                #-----------------------------------------
                # Looking for Admin By Request
                #-----------------------------------------
                If ( ($Application.Vendor -like 'FastTrack*') -and ($Application.name -like "*Admin By Request*") )
                    {
                        $ABRSoftware = $Application.Name
                        $ABRVersion = $Application.Version
                    }
            }

    #-------------------------------------------------------------------------------------------
    # Preparing data structure
    #-------------------------------------------------------------------------------------------

        If ($ABRSoftware)
            {
                $DataVariable = [pscustomobject]@{
                                                    ABRSoftware     = $ABRSoftware
                                                    ABRVersion      = $ABRVersion
                                                 }
    
                # add CollectionTime to existing array
                $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable

                # add Computer & UserLoggedOn info to existing array
                $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

                # Validating/fixing schema data structure of source data
                $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

                # Aligning data structure with schema (requirement for DCR)
                $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable
            }

    #-------------------------------------------------------------------------------------------
    # Create/Update Schema for LogAnalytics Table & Data Collection Rule schema
    #-------------------------------------------------------------------------------------------

        If ( ($TableDcrSchemaCreateUpdateAppId) -and ($TableDcrSchemaCreateUpdateAppSecret) )
            {
                #-----------------------------------------------------------------------------------------------
                # Check if table and DCR exist - or schema must be updated due to source object schema changes
                #-----------------------------------------------------------------------------------------------

                    # Get insight about the schema structure
                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnFormat Array

                    $StructureCheck = Get-AzLogAnalyticsTableAzDataCollectionRuleStatus -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -TableName $TableName -DcrName $DcrName -SchemaSourceObject $Schema `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId

                #-----------------------------------------------------------------------------------------------
                # Structure check = $true -> Create/update table & DCR with necessary schema
                #-----------------------------------------------------------------------------------------------

                    If ($StructureCheck -eq $true)
                        {
                            If ( ( $env:COMPUTERNAME -in $AzDcrDceTableCreateFromReferenceMachine) -or ($AzDcrDceTableCreateFromAnyMachine -eq $true) )    # manage table creations
                                {
                                    # build schema to be used for LogAnalytics Table
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType Table -ReturnFormat Hash

                                    CreateUpdate-AzLogAnalyticsCustomLogTableDcr -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema -TableName $TableName `
                                                                                 -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId


                                    # build schema to be used for DCR
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType DCR -ReturnFormat Hash

                                    CreateUpdate-AzDataCollectionRuleLogIngestCustomLog -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema `
                                                                                        -DceName $DceName -DcrName $DcrName -TableName $TableName `
                                                                                        -LogIngestServicePricipleObjectId $AzDcrLogIngestServicePrincipalObjectId `
                                                                                        -AzDcrSetLogIngestApiAppPermissionsDcrLevel $AzDcrSetLogIngestApiAppPermissionsDcrLevel `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId
                                }
                        }

                } # create table/DCR

    #-----------------------------------------------------------------------------------------------
    # Upload data to LogAnalytics using DCR / DCE / Log Ingestion API
    #-----------------------------------------------------------------------------------------------

        $AzDcrDceDetails = Get-AzDcrDceDetails -DcrName $DcrName -DceName $DceName `
                                               -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId

        Post-AzLogAnalyticsLogIngestCustomLogDcrDce  -DceUri $AzDcrDceDetails[2] -DcrImmutableId $AzDcrDceDetails[6] `
                                                     -DcrStream $AzDcrDceDetails[7] -Data $DataVariable `
                                                     -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId
        
        # Write result to screen
        $DataVariable | Out-String | Write-Verbose 



###############################################################
# Windows Update [10]
###############################################################

    Write-output ""
    Write-output "#########################################################################################"
    Write-Output "WINDOWS UPDATE INFORMATION [10]"
    Write-Output ""


    #################################################
    # Windows Update Last Results
    #################################################

        #-------------------------------------------------------------------------------------------
        # Variables
        #-------------------------------------------------------------------------------------------
            
            $TableName  = 'InvClientWindowsUpdateLastResultsV2'   # must not contain _CL
            $DcrName    = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"

        #-------------------------------------------------------------------------------------------
        # Collecting data (in)
        #-------------------------------------------------------------------------------------------
            
            Write-Output "Collecting Windows Update Last Results information"

            $DataVariable = Get-WULastResults

        #-------------------------------------------------------------------------------------------
        # Preparing data structure
        #-------------------------------------------------------------------------------------------

            # convert CIM array to PSCustomObject and remove CIM class information
            $DataVariable = Convert-CimArrayToObjectFixStructure -data $DataVariable
    
            # add CollectionTime to existing array
            $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable

            # add Computer & UserLoggedOn info to existing array
            $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

        # Validating/fixing schema data structure of source data
        $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

        # Aligning data structure with schema (requirement for DCR)
        $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable

    #-------------------------------------------------------------------------------------------
    # Create/Update Schema for LogAnalytics Table & Data Collection Rule schema
    #-------------------------------------------------------------------------------------------

        If ( ($TableDcrSchemaCreateUpdateAppId) -and ($TableDcrSchemaCreateUpdateAppSecret) )
            {
                #-----------------------------------------------------------------------------------------------
                # Check if table and DCR exist - or schema must be updated due to source object schema changes
                #-----------------------------------------------------------------------------------------------

                    # Get insight about the schema structure
                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnFormat Array

                    $StructureCheck = Get-AzLogAnalyticsTableAzDataCollectionRuleStatus -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -TableName $TableName -DcrName $DcrName -SchemaSourceObject $Schema `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId

                #-----------------------------------------------------------------------------------------------
                # Structure check = $true -> Create/update table & DCR with necessary schema
                #-----------------------------------------------------------------------------------------------

                    If ($StructureCheck -eq $true)
                        {
                            If ( ( $env:COMPUTERNAME -in $AzDcrDceTableCreateFromReferenceMachine) -or ($AzDcrDceTableCreateFromAnyMachine -eq $true) )    # manage table creations
                                {
                                    # build schema to be used for LogAnalytics Table
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType Table -ReturnFormat Hash

                                    CreateUpdate-AzLogAnalyticsCustomLogTableDcr -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema -TableName $TableName `
                                                                                 -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId


                                    # build schema to be used for DCR
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType DCR -ReturnFormat Hash

                                    CreateUpdate-AzDataCollectionRuleLogIngestCustomLog -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema `
                                                                                        -DceName $DceName -DcrName $DcrName -TableName $TableName `
                                                                                        -LogIngestServicePricipleObjectId $AzDcrLogIngestServicePrincipalObjectId `
                                                                                        -AzDcrSetLogIngestApiAppPermissionsDcrLevel $AzDcrSetLogIngestApiAppPermissionsDcrLevel `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId
                                }
                        }

                } # create table/DCR

    #-----------------------------------------------------------------------------------------------
    # Upload data to LogAnalytics using DCR / DCE / Log Ingestion API
    #-----------------------------------------------------------------------------------------------

        $AzDcrDceDetails = Get-AzDcrDceDetails -DcrName $DcrName -DceName $DceName `
                                               -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId

        Post-AzLogAnalyticsLogIngestCustomLogDcrDce  -DceUri $AzDcrDceDetails[2] -DcrImmutableId $AzDcrDceDetails[6] `
                                                     -DcrStream $AzDcrDceDetails[7] -Data $DataVariable `
                                                     -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId
        
        # Write result to screen
        $DataVariable | Out-String | Write-Verbose 


    #################################################
    # Windows Update Source Information
    #################################################

        #-------------------------------------------------------------------------------------------
        # Variables
        #-------------------------------------------------------------------------------------------
            
            $TableName  = 'InvClientWindowsUpdateServiceManagerV2'   # must not contain _CL
            $DcrName    = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"

        #-------------------------------------------------------------------------------------------
        # Collecting data (in)
        #-------------------------------------------------------------------------------------------
            
            Write-Output "Collecting Windows Update Source Information"

            $DataVariable = Get-WUServiceManager | Where-Object { $_.IsDefaultAUService -eq $true }

        #-------------------------------------------------------------------------------------------
        # Preparing data structure
        #-------------------------------------------------------------------------------------------

            # convert CIM array to PSCustomObject and remove CIM class information
            $DataVariable = Convert-CimArrayToObjectFixStructure -data $DataVariable
    
            # add CollectionTime to existing array
            $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable

            # add Computer & UserLoggedOn info to existing array
            $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

        # Validating/fixing schema data structure of source data
        $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

        # Aligning data structure with schema (requirement for DCR)
        $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable

    #-------------------------------------------------------------------------------------------
    # Create/Update Schema for LogAnalytics Table & Data Collection Rule schema
    #-------------------------------------------------------------------------------------------

        If ( ($TableDcrSchemaCreateUpdateAppId) -and ($TableDcrSchemaCreateUpdateAppSecret) )
            {
                #-----------------------------------------------------------------------------------------------
                # Check if table and DCR exist - or schema must be updated due to source object schema changes
                #-----------------------------------------------------------------------------------------------

                    # Get insight about the schema structure
                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnFormat Array

                    $StructureCheck = Get-AzLogAnalyticsTableAzDataCollectionRuleStatus -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -TableName $TableName -DcrName $DcrName -SchemaSourceObject $Schema `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId

                #-----------------------------------------------------------------------------------------------
                # Structure check = $true -> Create/update table & DCR with necessary schema
                #-----------------------------------------------------------------------------------------------

                    If ($StructureCheck -eq $true)
                        {
                            If ( ( $env:COMPUTERNAME -in $AzDcrDceTableCreateFromReferenceMachine) -or ($AzDcrDceTableCreateFromAnyMachine -eq $true) )    # manage table creations
                                {
                                    # build schema to be used for LogAnalytics Table
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType Table -ReturnFormat Hash

                                    CreateUpdate-AzLogAnalyticsCustomLogTableDcr -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema -TableName $TableName `
                                                                                 -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId


                                    # build schema to be used for DCR
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType DCR -ReturnFormat Hash

                                    CreateUpdate-AzDataCollectionRuleLogIngestCustomLog -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema `
                                                                                        -DceName $DceName -DcrName $DcrName -TableName $TableName `
                                                                                        -LogIngestServicePricipleObjectId $AzDcrLogIngestServicePrincipalObjectId `
                                                                                        -AzDcrSetLogIngestApiAppPermissionsDcrLevel $AzDcrSetLogIngestApiAppPermissionsDcrLevel `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId
                                }
                        }

                } # create table/DCR

    #-----------------------------------------------------------------------------------------------
    # Upload data to LogAnalytics using DCR / DCE / Log Ingestion API
    #-----------------------------------------------------------------------------------------------

        $AzDcrDceDetails = Get-AzDcrDceDetails -DcrName $DcrName -DceName $DceName `
                                               -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId

        Post-AzLogAnalyticsLogIngestCustomLogDcrDce  -DceUri $AzDcrDceDetails[2] -DcrImmutableId $AzDcrDceDetails[6] `
                                                     -DcrStream $AzDcrDceDetails[7] -Data $DataVariable `
                                                     -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId
        
        # Write result to screen
        $DataVariable | Out-String | Write-Verbose 


    #################################################
    # Pending Windows Updates
    #################################################

        #-------------------------------------------------------------------------------------------
        # Variables
        #-------------------------------------------------------------------------------------------
            
            $TableName  = 'InvClientWindowsUpdatePendingUpdatesV2'   # must not contain _CL
            $DcrName    = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"

        #-------------------------------------------------------------------------------------------
        # Collecting data (in)
        #-------------------------------------------------------------------------------------------
            
            Write-Output "Collecting Pending Windows Updates Information"

            If ($WU_ServiceManager.ServiceID -eq "9482f4b4-e343-43b6-b170-9a65bc822c77")      # Windows Update
                {
                    Write-Output ""
                    Write-Output "Pending Windows Updates (source: Windows Update)"
                    $WU_PendingUpdates = Get-WindowsUpdate -WindowsUpdate
                }
            ElseIf ($WU_ServiceManager.ServiceID -eq "7971f918-a847-4430-9279-4a52d1efe18d")  # Microsoft Update
                {
                    Write-Output ""
                    Write-Output "Pending Windows Updates (source: Microsoft Update)"
                    $WU_PendingUpdates = Get-WindowsUpdate -MicrosoftUpdate
                }

        #-------------------------------------------------------------------------------------------
        # Preparing data structure
        #-------------------------------------------------------------------------------------------

            If ($WU_PendingUpdates)
                {
                    # convert CIM array to PSCustomObject and remove CIM class information
                    $WU_PendingUpdates = Convert-CimArrayToObjectFixStructure -data $WU_PendingUpdates

                        # Add information to array
                        If ($WU_PendingUpdates)
                            {
                                $CountDataVariable = ($WU_PendingUpdates | Measure-Object).Count
                                $PosDataVariable   = 0
                                Do
                                    {
                                        # CVEs
                                            $UpdateCVEs = $WU_PendingUpdates[$PosDataVariable].CveIDs -join ";"
                                            $WU_PendingUpdates[$PosDataVariable] | Add-Member -Type NoteProperty -Name 'UpdateCVEs' -Value $UpdateCVEs -force

                                        # Classification (e.g. Security Update)
                                            $UpdateClassification     = $WU_PendingUpdates[$PosDataVariable].Categories | Where-Object { $_.Type -eq "UpdateClassification" } | Select Name
                                            $UpdateClassificationName = $UpdateClassification.Name
                                            $WU_PendingUpdates[$PosDataVariable] | Add-Member -Type NoteProperty -Name 'UpdateClassification' -Value $UpdateClassificationName -force

                                        # Target (e.g. product, SQL)
                                            $UpdateTarget     = $WU_PendingUpdates[$PosDataVariable].Categories | Where-Object { $_.Type -ne "UpdateClassification" } | Select Name
                                            $UpdateTargetName = $UpdateTarget.Name
                                            $WU_PendingUpdates[$PosDataVariable] | Add-Member -Type NoteProperty -Name 'UpdateTarget' -Value $UpdateTargetName -force

                                        # KB
                                            $UpdateKB = $WU_PendingUpdates[$PosDataVariable].KBArticleIDs -join ";"
                                            $WU_PendingUpdates[$PosDataVariable] | Add-Member -Type NoteProperty -Name 'UpdateKB' -Value $UpdateKB -force

                                        # KB Published Date
                                            $UpdateKBPublished                 = $WU_PendingUpdates[$PosDataVariable].LastDeploymentChangeTime
                                            $WU_PendingUpdates[$PosDataVariable] | Add-Member -Type NoteProperty -Name 'UpdateKBPublished' -Value $UpdateKBPublished -force

                                        $PosDataVariable = 1 + $PosDataVariable
                                    }
                                Until ($PosDataVariable -eq $CountDataVariable)
                        }

    
                    # add CollectionTime to existing array
                    $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $WU_PendingUpdates

                    # add Computer & UserLoggedOn info to existing array
                    $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

                    # Validating/fixing schema data structure of source data
                    $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable
                }


        #-------------------------------------------------------------------------------------------
        # Create/Update Schema for LogAnalytics Table & Data Collection Rule schema
        #-------------------------------------------------------------------------------------------

            If ( ($TableDcrSchemaCreateUpdateAppId) -and ($TableDcrSchemaCreateUpdateAppSecret) )
                {
                    #-----------------------------------------------------------------------------------------------
                    # Check if table and DCR exist - or schema must be updated due to source object schema changes
                    #-----------------------------------------------------------------------------------------------

                        # Get insight about the schema structure
                        $Schema = Get-ObjectSchema -Data $DataVariable -ReturnFormat Array

                        $StructureCheck = Get-AzLogAnalyticsTableAzDataCollectionRuleStatus -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -TableName $TableName -DcrName $DcrName -SchemaSourceObject $Schema `
                                                                                            -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId

                    #-----------------------------------------------------------------------------------------------
                    # Structure check = $true -> Create/update table & DCR with necessary schema
                    #-----------------------------------------------------------------------------------------------

                        If ($StructureCheck -eq $true)
                            {
                                If ( ( $env:COMPUTERNAME -in $AzDcrDceTableCreateFromReferenceMachine) -or ($AzDcrDceTableCreateFromAnyMachine -eq $true) )    # manage table creations
                                    {
                                    <#
                                        If ($WU_PendingUpdates -eq $null)   # empty
                                            {
                                                # build default schema, if no pending windows update is available on reference machine
                                                $DataVariable = New-object PSCustomObject
                                                $DataVariable | Add-Member -Name AutoDownload -MemberType NoteProperty -Value 0
                                                $DataVariable | Add-Member -Name AutoSelection -MemberType NoteProperty -Value 0
                                                $DataVariable | Add-Member -Name AutoSelectOnWebSites -MemberType NoteProperty -Value $false
                                                $DataVariable | Add-Member -Name BrowseOnly -MemberType NoteProperty -Value $false
                                                $DataVariable | Add-Member -Name BundledUpdates -MemberType NoteProperty -Value ""
                                                $DataVariable | Add-Member -Name CanRequireSource -MemberType NoteProperty -Value $false
                                                $DataVariable | Add-Member -Name Categories -MemberType NoteProperty -Value ""
                                                $DataVariable | Add-Member -Name CollectionTime -MemberType NoteProperty -Value (Get-Date)
                                                $DataVariable | Add-Member -Name ComputerName -MemberType NoteProperty -Value ""
                                                $DataVariable | Add-Member -Name CveIDs -MemberType NoteProperty -Value ""
                                                $DataVariable | Add-Member -Name DeltaCompressedContentAvailable -MemberType NoteProperty -Value $false
                                                $DataVariable | Add-Member -Name DeltaCompressedContentPreferred -MemberType NoteProperty -Value $false
                                                $DataVariable | Add-Member -Name DeploymentAction -MemberType NoteProperty -Value 0
                                                $DataVariable | Add-Member -Name Description -MemberType NoteProperty -Value string
                                                $DataVariable | Add-Member -Name DeviceProblemNumber -MemberType NoteProperty -Value 0
                                                $DataVariable | Add-Member -Name DeviceStatus -MemberType NoteProperty -Value 0
                                                $DataVariable | Add-Member -Name DownloadContents -MemberType NoteProperty -Value ""
                                                $DataVariable | Add-Member -Name DownloadPriority -MemberType NoteProperty -Value 0
                                                $DataVariable | Add-Member -Name DriverClass -MemberType NoteProperty -Value ""
                                                $DataVariable | Add-Member -Name DriverHardwareID -MemberType NoteProperty -Value ""
                                                $DataVariable | Add-Member -Name DriverManufacturer -MemberType NoteProperty -Value ""
                                                $DataVariable | Add-Member -Name DriverModel -MemberType NoteProperty -Value ""
                                                $DataVariable | Add-Member -Name DriverProvider -MemberType NoteProperty -Value ""
                                                $DataVariable | Add-Member -Name DriverVerDate -MemberType NoteProperty -Value (Get-date)
                                                $DataVariable | Add-Member -Name EulaAccepted -MemberType NoteProperty -Value $false
                                                $DataVariable | Add-Member -Name EulaText -MemberType NoteProperty -Value ""
                                                $DataVariable | Add-Member -Name HandlerID -MemberType NoteProperty -Value ""
                                                $DataVariable | Add-Member -Name IsBeta -MemberType NoteProperty -Value $false
                                                $DataVariable | Add-Member -Name IsDownloaded -MemberType NoteProperty -Value $false
                                                $DataVariable | Add-Member -Name IsHidden -MemberType NoteProperty -Value $false
                                                $DataVariable | Add-Member -Name IsInstalled -MemberType NoteProperty -Value $false
                                                $DataVariable | Add-Member -Name IsMandatory -MemberType NoteProperty -Value $false
                                                $DataVariable | Add-Member -Name IsPresent -MemberType NoteProperty -Value $false
                                                $DataVariable | Add-Member -Name IsUninstallable -MemberType NoteProperty -Value $false
                                                $DataVariable | Add-Member -Name KB -MemberType NoteProperty -Value ""
                                                $DataVariable | Add-Member -Name KBArticleIDs -MemberType NoteProperty -Value ""
                                                $DataVariable | Add-Member -Name Languages -MemberType NoteProperty -Value ""
                                                $DataVariable | Add-Member -Name LastDeploymentChangeTime -MemberType NoteProperty -Value (get-date)
                                                $DataVariable | Add-Member -Name MaxDownloadSize -MemberType NoteProperty -Value 0
                                                $DataVariable | Add-Member -Name MinDownloadSize -MemberType NoteProperty -Value 0
                                                $DataVariable | Add-Member -Name MoreInfoUrls -MemberType NoteProperty -Value ""
                                                $DataVariable | Add-Member -Name MsrcSeverity -MemberType NoteProperty -Value ""
                                                $DataVariable | Add-Member -Name PerUser -MemberType NoteProperty -Value $false
                                                $DataVariable | Add-Member -Name RebootRequired -MemberType NoteProperty -Value $false
                                                $DataVariable | Add-Member -Name RecommendedCpuSpeed -MemberType NoteProperty -Value 0
                                                $DataVariable | Add-Member -Name RecommendedHardDiskSpace -MemberType NoteProperty -Value 0
                                                $DataVariable | Add-Member -Name RecommendedMemory -MemberType NoteProperty -Value 0
                                                $DataVariable | Add-Member -Name SecurityBulletinIDs -MemberType NoteProperty -Value ""
                                                $DataVariable | Add-Member -Name Size -MemberType NoteProperty -Value ""
                                                $DataVariable | Add-Member -Name Status -MemberType NoteProperty -Value ""
                                                $DataVariable | Add-Member -Name SupersededUpdateIDs -MemberType NoteProperty -Value ""
                                                $DataVariable | Add-Member -Name SupportUrl -MemberType NoteProperty -Value ""
                                                $DataVariable | Add-Member -Name Title_ -MemberType NoteProperty -Value ""
                                                $DataVariable | Add-Member -Name Type_ -MemberType NoteProperty -Value 0
                                                $DataVariable | Add-Member -Name UninstallationNotes -MemberType NoteProperty -Value ""
                                                $DataVariable | Add-Member -Name UninstallationSteps -MemberType NoteProperty -Value ""
                                                $DataVariable | Add-Member -Name UpdateClassification -MemberType NoteProperty -Value ""
                                                $DataVariable | Add-Member -Name UpdateCVEs -MemberType NoteProperty -Value ""
                                                $DataVariable | Add-Member -Name UpdateKB -MemberType NoteProperty -Value ""
                                                $DataVariable | Add-Member -Name UpdateKBPublished -MemberType NoteProperty -Value (get-date)
                                                $DataVariable | Add-Member -Name UpdateTarget -MemberType NoteProperty -Value ""
                                                $DataVariable | Add-Member -Name UserLoggedOn -MemberType NoteProperty -Value ""
                                                $DataVariable | Add-Member -Name WindowsDriverUpdateEntries -MemberType NoteProperty -Value ""
                                                # $DataVariable | Get-Member -MemberType NoteProperty
                                            }
                                        Else
                                            {
#>
                                                # build schema to be used for LogAnalytics Table
                                                $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType Table -ReturnFormat Hash

                                                CreateUpdate-AzLogAnalyticsCustomLogTableDcr -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema -TableName $TableName `
                                                                                             -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId


                                                # build schema to be used for DCR
                                                $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType DCR -ReturnFormat Hash

                                                CreateUpdate-AzDataCollectionRuleLogIngestCustomLog -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema `
                                                                                                    -DceName $DceName -DcrName $DcrName -TableName $TableName `
                                                                                                    -LogIngestServicePricipleObjectId $AzDcrLogIngestServicePrincipalObjectId `
                                                                                                    -AzDcrSetLogIngestApiAppPermissionsDcrLevel $AzDcrSetLogIngestApiAppPermissionsDcrLevel `
                                                                                                    -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId
                                           # }
                                }
                        }

                    } # create table/DCR

    #-----------------------------------------------------------------------------------------------
    # Upload data to LogAnalytics using DCR / DCE / Log Ingestion API
    #-----------------------------------------------------------------------------------------------

        $AzDcrDceDetails = Get-AzDcrDceDetails -DcrName $DcrName -DceName $DceName `
                                               -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId

        Post-AzLogAnalyticsLogIngestCustomLogDcrDce  -DceUri $AzDcrDceDetails[2] -DcrImmutableId $AzDcrDceDetails[6] `
                                                     -DcrStream $AzDcrDceDetails[7] -Data $DataVariable `
                                                     -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId
        
        # Write result to screen
        $DataVariable | Out-String | Write-Verbose 


    #############################################################
    # Status of Windows Update installations during last 31 days
    #############################################################

        #-------------------------------------------------------------------------------------------
        # Variables
        #-------------------------------------------------------------------------------------------
            
            $TableName  = 'InvClientWindowsUpdateLastInstallationsV2'   # must not contain _CL
            $DcrName    = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"

        #-------------------------------------------------------------------------------------------
        # Collecting data (in)
        #-------------------------------------------------------------------------------------------
            
            Write-Output "Collecting Last Installations of Windows Updates information"

            $UpdateSession                     = New-Object -ComObject 'Microsoft.Update.Session'
            $UpdateSession.WebProxy.AutoDetect = $false
            $UpdateSearcher                    = $UpdateSession.CreateUpdateSearcher()
            $SearchResult                      = $UpdateSearcher.Search('IsInstalled=1 and IsHidden=0')
            $SearchResultFiltered              = $SearchResult | Where-Object { ($_.LastDeploymentChangeTime -le (Get-Date).AddDays(-31)) }
            $WU_LastInstallations              = $searchResultFiltered.Updates

        #-------------------------------------------------------------------------------------------
        # Preparing data structure
        #-------------------------------------------------------------------------------------------

            # Add CollectionTime & ComputerName to array
            If ($WU_LastInstallations)
                {
                    # convert CIM array to PSCustomObject and remove CIM class information
                    $WU_LastInstallations = Convert-CimArrayToObjectFixStructure -data $WU_LastInstallations

                    $CountDataVariable = ($WU_LastInstallations | Measure-Object).Count
                    $PosDataVariable   = 0
                    Do
                        {
                            # CVEs
                                $UpdateCVEsInfo = $WU_LastInstallations[$PosDataVariable].CveIDs -join ";"
                                $WU_LastInstallations[$PosDataVariable] | Add-Member -Type NoteProperty -Name 'UpdateCVEs' -Value $UpdateCVEsInfo -force

                            # Classification (e.g. Security Update)
                                $UpdateClassification     = $WU_LastInstallations[$PosDataVariable].Categories | Where-Object { $_.Type -eq "UpdateClassification" } | Select Name
                                $UpdateClassificationName = $UpdateClassification.Name
                                $WU_LastInstallations[$PosDataVariable] | Add-Member -Type NoteProperty -Name 'UpdateClassification' -Value $UpdateClassificationName -force

                            # Target (e.g. product, SQL)
                                $UpdateTarget = $WU_LastInstallations[$PosDataVariable].Categories | Where-Object { $_.Type -ne "UpdateClassification" } | Select Name
                                $UpdateTargetName = $UpdateTarget.Name
                                $WU_LastInstallations[$PosDataVariable] | Add-Member -Type NoteProperty -Name 'UpdateTarget' -Value $UpdateTargetName -force

                            # KB
                                $KB = ($WU_LastInstallations[$PosDataVariable].KBArticleIDs -join ";")
                                If ($KB)
                                    {
                                        $UpdateKB = "KB" + $KB
                                    }
                                $WU_LastInstallations[$PosDataVariable] | Add-Member -Type NoteProperty -Name 'UpdateKB' -Value $UpdateKB -force

                            # KB Published Date
                                $UpdateKBPublished = $WU_LastInstallations[$PosDataVariable].LastDeploymentChangeTime
                                $WU_LastInstallations[$PosDataVariable] | Add-Member -Type NoteProperty -Name 'UpdateKBPublished' -Value $UpdateKBPublished -force

                            # Remove DownloadContents from array
                                $WU_LastInstallations[$PosDataVariable].PSObject.Properties.Remove("DownloadContents")

                            # Remove BundledUpdates from array
                                $WU_LastInstallations[$PosDataVariable].PSObject.Properties.Remove("BundledUpdates")

                            # Remove Categories from array
                                $WU_LastInstallations[$PosDataVariable].PSObject.Properties.Remove("Categories")

                            $PosDataVariable = 1 + $PosDataVariable
                        }
                    Until ($PosDataVariable -eq $CountDataVariable)

    
                # add CollectionTime to existing array
                $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $WU_LastInstallations

                # add Computer & UserLoggedOn info to existing array
                $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

                # Validating/fixing schema data structure of source data
                $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

                # Aligning data structure with schema (requirement for DCR)
                $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable
            }
        Else
            {
                $DataVariable = $WU_LastInstallations
            }

    #-------------------------------------------------------------------------------------------
    # Create/Update Schema for LogAnalytics Table & Data Collection Rule schema
    #-------------------------------------------------------------------------------------------

        If ( ($TableDcrSchemaCreateUpdateAppId) -and ($TableDcrSchemaCreateUpdateAppSecret) )
            {
                #-----------------------------------------------------------------------------------------------
                # Check if table and DCR exist - or schema must be updated due to source object schema changes
                #-----------------------------------------------------------------------------------------------

                    # Get insight about the schema structure
                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnFormat Array

                    $StructureCheck = Get-AzLogAnalyticsTableAzDataCollectionRuleStatus -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -TableName $TableName -DcrName $DcrName -SchemaSourceObject $Schema `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId

                #-----------------------------------------------------------------------------------------------
                # Structure check = $true -> Create/update table & DCR with necessary schema
                #-----------------------------------------------------------------------------------------------

                    If ($StructureCheck -eq $true)
                        {
                            If ( ( $env:COMPUTERNAME -in $AzDcrDceTableCreateFromReferenceMachine) -or ($AzDcrDceTableCreateFromAnyMachine -eq $true) )    # manage table creations
                                {
                                    # build schema to be used for LogAnalytics Table
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType Table -ReturnFormat Hash

                                    CreateUpdate-AzLogAnalyticsCustomLogTableDcr -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema -TableName $TableName `
                                                                                 -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId


                                    # build schema to be used for DCR
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType DCR -ReturnFormat Hash

                                    CreateUpdate-AzDataCollectionRuleLogIngestCustomLog -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema `
                                                                                        -DceName $DceName -DcrName $DcrName -TableName $TableName `
                                                                                        -LogIngestServicePricipleObjectId $AzDcrLogIngestServicePrincipalObjectId `
                                                                                        -AzDcrSetLogIngestApiAppPermissionsDcrLevel $AzDcrSetLogIngestApiAppPermissionsDcrLevel `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId
                                }
                        }

                } # create table/DCR

    #-----------------------------------------------------------------------------------------------
    # Upload data to LogAnalytics using DCR / DCE / Log Ingestion API
    #-----------------------------------------------------------------------------------------------

        $AzDcrDceDetails = Get-AzDcrDceDetails -DcrName $DcrName -DceName $DceName `
                                               -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId

        Post-AzLogAnalyticsLogIngestCustomLogDcrDce  -DceUri $AzDcrDceDetails[2] -DcrImmutableId $AzDcrDceDetails[6] `
                                                     -DcrStream $AzDcrDceDetails[7] -Data $DataVariable `
                                                     -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId
        
        # Write result to screen
        $DataVariable | Select-Object UpdateKB,LastDeploymentChangeTime,Title | Out-String | Write-Verbose


###############################################################
# Bitlocker [11]
###############################################################

    Write-output ""
    Write-output "#########################################################################################"
    Write-output "BITLOCKER INFORMATION [11]"
    Write-output ""

    #-------------------------------------------------------------------------------------------
    # Variables
    #-------------------------------------------------------------------------------------------
            
        $TableName  = 'InvClientBitlockerInfoV2'   # must not contain _CL
        $DcrName    = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"

    #-------------------------------------------------------------------------------------------
    # Collecting data (in)
    #-------------------------------------------------------------------------------------------
            
        Write-Output "Collecting Bitlocker information"

        # Default Values
        $OSDisk_DriveLetter = ""
        $OSDisk_CapacityGB = ""
        $OSDisk_VolumeStatus = ""
        $OSDisk_EncryptionPercentage = ""
        $OSDisk_KeyProtector = ""
        $OSDisk_AutoUnlockEnabled = ""
        $OSDisk_ProtectionStatus = ""

        # Step 1/3 - get information
        Try
            {
                $BitlockerVolumens = Get-BitLockerVolume 
            }
        Catch
            {
                Write-output "  Bitlocker was not found on this machine !!"
            }


        If ($BitlockerVolumens)
            {
                # OS Disk
                $OSVolumen = $BitLockerVolumens | where VolumeType -EQ "OperatingSystem"
                $OSDisk_DriveLetter = $OSVOlumen.MountPoint
                $OSDisk_CapacityGB = $OSVOlumen.CapacityGB
                $OSDisk_VolumeStatus = $OSVOlumen.VolumeStatus
                $OSDisk_EncryptionPercentage = $OSVOlumen.EncryptionPercentage
                $OSDisk_KeyProtector = $OSVOlumen.KeyProtector
                $OSDisk_AutoUnlockEnabled = $OSVOlumen.AutoUnlockEnabled
                $OSDisk_ProtectionStatus = $OSVOlumen.ProtectionStatus
            }

    #-------------------------------------------------------------------------------------------
    # Preparing data structure
    #-------------------------------------------------------------------------------------------

        $DataVariable = [pscustomobject]@{
                                            OSDisk_DriveLetter = $OSDisk_DriveLetter
                                            OSDisk_CapacityGB= $OSDisk_CapacityGB
                                            OSDisk_VolumeStatus = $OSDisk_VolumeStatus
                                            OSDisk_EncryptionPercentage = $OSDisk_EncryptionPercentage
                                            OSDisk_KeyProtector = $OSDisk_KeyProtector
                                            OSDisk_AutoUnlockEnabled = $OSDisk_AutoUnlockEnabled
                                            OSDisk_ProtectionStatus = $OSDisk_ProtectionStatus
                                         }

        # convert CIM array to PSCustomObject and remove CIM class information
        $DataVariable = Convert-CimArrayToObjectFixStructure -data $DataVariable
    
        # add CollectionTime to existing array
        $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable

        # add Computer & UserLoggedOn info to existing array
        $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

        # Validating/fixing schema data structure of source data
        $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

        # Aligning data structure with schema (requirement for DCR)
        $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable

    #-------------------------------------------------------------------------------------------
    # Create/Update Schema for LogAnalytics Table & Data Collection Rule schema
    #-------------------------------------------------------------------------------------------

        If ( ($TableDcrSchemaCreateUpdateAppId) -and ($TableDcrSchemaCreateUpdateAppSecret) )
            {
                #-----------------------------------------------------------------------------------------------
                # Check if table and DCR exist - or schema must be updated due to source object schema changes
                #-----------------------------------------------------------------------------------------------

                    # Get insight about the schema structure
                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnFormat Array

                    $StructureCheck = Get-AzLogAnalyticsTableAzDataCollectionRuleStatus -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -TableName $TableName -DcrName $DcrName -SchemaSourceObject $Schema `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId

                #-----------------------------------------------------------------------------------------------
                # Structure check = $true -> Create/update table & DCR with necessary schema
                #-----------------------------------------------------------------------------------------------

                    If ($StructureCheck -eq $true)
                        {
                            If ( ( $env:COMPUTERNAME -in $AzDcrDceTableCreateFromReferenceMachine) -or ($AzDcrDceTableCreateFromAnyMachine -eq $true) )    # manage table creations
                                {
                                    # build schema to be used for LogAnalytics Table
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType Table -ReturnFormat Hash

                                    CreateUpdate-AzLogAnalyticsCustomLogTableDcr -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema -TableName $TableName `
                                                                                 -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId


                                    # build schema to be used for DCR
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType DCR -ReturnFormat Hash

                                    CreateUpdate-AzDataCollectionRuleLogIngestCustomLog -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema `
                                                                                        -DceName $DceName -DcrName $DcrName -TableName $TableName `
                                                                                        -LogIngestServicePricipleObjectId $AzDcrLogIngestServicePrincipalObjectId `
                                                                                        -AzDcrSetLogIngestApiAppPermissionsDcrLevel $AzDcrSetLogIngestApiAppPermissionsDcrLevel `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId
                                }
                        }

                } # create table/DCR

    #-----------------------------------------------------------------------------------------------
    # Upload data to LogAnalytics using DCR / DCE / Log Ingestion API
    #-----------------------------------------------------------------------------------------------

        $AzDcrDceDetails = Get-AzDcrDceDetails -DcrName $DcrName -DceName $DceName `
                                               -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId

        Post-AzLogAnalyticsLogIngestCustomLogDcrDce  -DceUri $AzDcrDceDetails[2] -DcrImmutableId $AzDcrDceDetails[6] `
                                                     -DcrStream $AzDcrDceDetails[7] -Data $DataVariable `
                                                     -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId
        
        # Write result to screen
        $DataVariable | Out-String | Write-Verbose 


###############################################################
# EVENTLOG [12]
###############################################################

    Write-output ""
    Write-output "#########################################################################################"
    Write-output "EVENTLOG [12]"
    Write-output ""

    #-------------------------------------------------------------------------------------------
    # Variables
    #-------------------------------------------------------------------------------------------
            
        $TableName  = 'InvClientEventlogInfoV2'   # must not contain _CL
        $DcrName    = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"

    #-------------------------------------------------------------------------------------------
    # Collecting data (in)
    #-------------------------------------------------------------------------------------------
            
        Write-Output "Collecting Eventlog information"

        $FilteredEvents      = @()
        $Appl_Events_ALL     = @()
        $System_Events_ALL   = @()
        $Security_Events_ALL = @()

        ###############################################################################################

        $Application_EventId_Array = @(
                                        )


        $System_EventId_Array      = @(
                                        "6008;Eventlog"  # Unexpected shutdown ; Providername = Eventlog
                                        "7001;Microsoft-Windows-WinLogon" # Windows logon
                                        )

        $Security_EventId_Array    = @( 
                                        "4740;Microsoft-Windows-Security-Auditing"  # Accounts Lockouts
                                        "4728;Microsoft-Windows-Security-Auditing"  # User Added to Privileged Group
                                        "4732;Microsoft-Windows-Security-Auditing"  # User Added to Privileged Group
                                        "4756;Microsoft-Windows-Security-Auditing"  # User Added to Privileged Group
                                        "4735;Microsoft-Windows-Security-Auditing"  # Security-Enabled Group Modification
                                        "4625;Microsoft-Windows-Security-Auditing"  # Failed User Account Login
                                        "4648;Microsoft-Windows-Security-Auditing"  # Account Login with Explicit Credentials
                                        )
        <#
                                        "4624;Microsoft-Windows-Security-Auditing"  # Succesful User Account Login
        #>

        ###############################################################################################

        $Yesterday = (Get-Date).AddDays(-1)
            
        If ($Application_EventId_Array)
            {
                    ForEach ($Entry in $Application_EventId_Array)
                        {
                            $Split = $Entry -split ";"
                            $Id    = $Split[0]
                            $ProviderName = $Split[1]

                            $FilteredEvents += Get-WinEvent -FilterHashtable @{ProviderName = $ProviderName; Id = $Id} -ErrorAction SilentlyContinue | Where-Object { ($_.TimeCreated -ge $Yesterday) }
                        }
            }

        If ($System_EventId_Array)
            {
                    ForEach ($Entry in $System_EventId_Array)
                        {
                            $Split = $Entry -split ";"
                            $Id    = $Split[0]
                            $ProviderName = $Split[1]

                            $FilteredEvents += Get-WinEvent -FilterHashtable @{ProviderName = $ProviderName; Id = $Id} -ErrorAction SilentlyContinue | Where-Object { ($_.TimeCreated -ge $Yesterday) }
                        }
            }

        If ($Security_EventId_Array)
            {
                    ForEach ($Entry in $Security_EventId_Array)
                        {
                            $Split = $Entry -split ";"
                            $Id    = $Split[0]
                            $ProviderName = $Split[1]

                            $FilteredEvents += Get-WinEvent -FilterHashtable @{ProviderName = $ProviderName; Id = $Id} -ErrorAction SilentlyContinue | Where-Object { ($_.TimeCreated -ge $Yesterday) }
                        }
            }

    #-------------------------------------------------------------------------------------------
    # Preparing data structure
    #-------------------------------------------------------------------------------------------

        # convert CIM array to PSCustomObject and remove CIM class information
        $DataVariable = Convert-CimArrayToObjectFixStructure -data $FilteredEvents
    
        # add CollectionTime to existing array
        $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable

        # add Computer & UserLoggedOn info to existing array
        $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

        # Validating/fixing schema data structure of source data
        $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

        # Aligning data structure with schema (requirement for DCR)
        $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable

    #-------------------------------------------------------------------------------------------
    # Create/Update Schema for LogAnalytics Table & Data Collection Rule schema
    #-------------------------------------------------------------------------------------------

        If ( ($TableDcrSchemaCreateUpdateAppId) -and ($TableDcrSchemaCreateUpdateAppSecret) )
            {
                #-----------------------------------------------------------------------------------------------
                # Check if table and DCR exist - or schema must be updated due to source object schema changes
                #-----------------------------------------------------------------------------------------------

                    # Get insight about the schema structure
                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnFormat Array

                    $StructureCheck = Get-AzLogAnalyticsTableAzDataCollectionRuleStatus -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -TableName $TableName -DcrName $DcrName -SchemaSourceObject $Schema `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId

                #-----------------------------------------------------------------------------------------------
                # Structure check = $true -> Create/update table & DCR with necessary schema
                #-----------------------------------------------------------------------------------------------

                    If ($StructureCheck -eq $true)
                        {
                            If ( ( $env:COMPUTERNAME -in $AzDcrDceTableCreateFromReferenceMachine) -or ($AzDcrDceTableCreateFromAnyMachine -eq $true) )    # manage table creations
                                {
                                    # build schema to be used for LogAnalytics Table
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType Table -ReturnFormat Hash

                                    CreateUpdate-AzLogAnalyticsCustomLogTableDcr -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema -TableName $TableName `
                                                                                 -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId


                                    # build schema to be used for DCR
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType DCR -ReturnFormat Hash

                                    CreateUpdate-AzDataCollectionRuleLogIngestCustomLog -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema `
                                                                                        -DceName $DceName -DcrName $DcrName -TableName $TableName `
                                                                                        -LogIngestServicePricipleObjectId $AzDcrLogIngestServicePrincipalObjectId `
                                                                                        -AzDcrSetLogIngestApiAppPermissionsDcrLevel $AzDcrSetLogIngestApiAppPermissionsDcrLevel `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId
                                }
                        }

                } # create table/DCR

    #-----------------------------------------------------------------------------------------------
    # Upload data to LogAnalytics using DCR / DCE / Log Ingestion API
    #-----------------------------------------------------------------------------------------------

        $AzDcrDceDetails = Get-AzDcrDceDetails -DcrName $DcrName -DceName $DceName `
                                               -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId

        Post-AzLogAnalyticsLogIngestCustomLogDcrDce  -DceUri $AzDcrDceDetails[2] -DcrImmutableId $AzDcrDceDetails[6] `
                                                     -DcrStream $AzDcrDceDetails[7] -Data $DataVariable `
                                                     -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId
        
        # Write result to screen
        $DataVariable | Out-String | Write-Verbose 


###############################################################
# Network Adapter Information [13]
###############################################################

    Write-output ""
    Write-output "#########################################################################################"
    Write-output "NETWORK ADAPTER INFORMATION [13]"
    Write-output ""

    #-------------------------------------------------------------------------------------------
    # Variables
    #-------------------------------------------------------------------------------------------
            
        $TableName  = 'InvClientNetworkAdapterInfoV2'   # must not contain _CL
        $DcrName    = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"

    #-------------------------------------------------------------------------------------------
    # Collecting data (in)
    #-------------------------------------------------------------------------------------------
            
        Write-Output "Collecting Network Adapter information"

        $NetworkAdapter = Get-NetAdapter

    #-------------------------------------------------------------------------------------------
    # Preparing data structure
    #-------------------------------------------------------------------------------------------
        If ($NetworkAdapter)
            {
                # convert CIM array to PSCustomObject and remove CIM class information
                $DataVariable = Convert-CimArrayToObjectFixStructure -data $NetworkAdapter
    
                # add CollectionTime to existing array
                $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable

                # add Computer & UserLoggedOn info to existing array
                $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

                # Get insight about the schema structure of an object BEFORE changes. Command is only needed to verify schema - can be disabled
                $SchemaBefore = Get-ObjectSchema -Data $DataVariable -ReturnFormat Array
        
                # Remove unnecessary columns in schema
                $DataVariable = Filter-ObjectExcludeProperty -Data $DataVariable -ExcludeProperty Memento*,Inno*,'(default)',1033

                # Get insight about the schema structure of an object AFTER changes. Command is only needed to verify schema - can be disabled
                $Schema = Get-ObjectSchema -Data $DataVariable -ReturnFormat Array

                # Validating/fixing schema data structure of source data
                $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

                # Aligning data structure with schema (requirement for DCR)
                $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable            }
        Else
            {

                # log issue - typically WMI issue
                $TableName  = 'InvClientCollectionIssuesV2'   # must not contain _CL
                $DcrName    = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"

                $DataVariable = [pscustomobject]@{
                                                   IssueCategory   = "NetworkAdapterInformation"
                                                 }

                # add CollectionTime to existing array
                $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable

                # add Computer & UserLoggedOn info to existing array
                $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

                # Validating/fixing schema data structure of source data
                $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

                # Aligning data structure with schema (requirement for DCR)
                $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable
            }         
    #-------------------------------------------------------------------------------------------
    # Create/Update Schema for LogAnalytics Table & Data Collection Rule schema
    #-------------------------------------------------------------------------------------------

        If ( ($TableDcrSchemaCreateUpdateAppId) -and ($TableDcrSchemaCreateUpdateAppSecret) )
            {
                #-----------------------------------------------------------------------------------------------
                # Check if table and DCR exist - or schema must be updated due to source object schema changes
                #-----------------------------------------------------------------------------------------------

                    # Get insight about the schema structure
                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnFormat Array

                    $StructureCheck = Get-AzLogAnalyticsTableAzDataCollectionRuleStatus -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -TableName $TableName -DcrName $DcrName -SchemaSourceObject $Schema `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId

                #-----------------------------------------------------------------------------------------------
                # Structure check = $true -> Create/update table & DCR with necessary schema
                #-----------------------------------------------------------------------------------------------

                    If ($StructureCheck -eq $true)
                        {
                            If ( ( $env:COMPUTERNAME -in $AzDcrDceTableCreateFromReferenceMachine) -or ($AzDcrDceTableCreateFromAnyMachine -eq $true) )    # manage table creations
                                {
                                    # build schema to be used for LogAnalytics Table
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType Table -ReturnFormat Hash

                                    CreateUpdate-AzLogAnalyticsCustomLogTableDcr -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema -TableName $TableName `
                                                                                 -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId


                                    # build schema to be used for DCR
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType DCR -ReturnFormat Hash

                                    CreateUpdate-AzDataCollectionRuleLogIngestCustomLog -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema `
                                                                                        -DceName $DceName -DcrName $DcrName -TableName $TableName `
                                                                                        -LogIngestServicePricipleObjectId $AzDcrLogIngestServicePrincipalObjectId `
                                                                                        -AzDcrSetLogIngestApiAppPermissionsDcrLevel $AzDcrSetLogIngestApiAppPermissionsDcrLevel `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId
                                }
                        }

                } # create table/DCR

    #-----------------------------------------------------------------------------------------------
    # Upload data to LogAnalytics using DCR / DCE / Log Ingestion API
    #-----------------------------------------------------------------------------------------------

        $AzDcrDceDetails = Get-AzDcrDceDetails -DcrName $DcrName -DceName $DceName `
                                               -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId

        Post-AzLogAnalyticsLogIngestCustomLogDcrDce  -DceUri $AzDcrDceDetails[2] -DcrImmutableId $AzDcrDceDetails[6] `
                                                     -DcrStream $AzDcrDceDetails[7] -Data $DataVariable `
                                                     -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId
        
        # Write result to screen
        $DataVariable | Out-String | Write-Verbose 


###############################################################
# IP INFORMATION [14]
###############################################################

    Write-output ""
    Write-output "#########################################################################################"
    Write-output "IP INFORMATION [14]"
    Write-output ""

    #-------------------------------------------------------------------------------------------
    # Variables
    #-------------------------------------------------------------------------------------------
            
        $TableName  = 'InvClientNetworkIPv4InfoV2'   # must not contain _CL
        $DcrName    = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"

    #-------------------------------------------------------------------------------------------
    # Collecting data (in)
    #-------------------------------------------------------------------------------------------
            
        Write-Output "Collecting IPv4 information"

        $IPv4Status = Get-NetIPAddress -AddressFamily IPv4

    #-------------------------------------------------------------------------------------------
    # Preparing data structure
    #-------------------------------------------------------------------------------------------
        If ($IPv4Status)
            {
                # convert CIM array to PSCustomObject and remove CIM class information
                $DataVariable = Convert-CimArrayToObjectFixStructure -data $IPv4Status
    
                # add CollectionTime to existing array
                $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable

                # add Computer & UserLoggedOn info to existing array
                $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

                # Validating/fixing schema data structure of source data
                $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

                # Aligning data structure with schema (requirement for DCR)
                $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable
            }
        Else
            {

                # log issue - typically WMI issue
                $TableName  = 'InvClientCollectionIssuesV2'   # must not contain _CL
                $DcrName    = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"

                $DataVariable = [pscustomobject]@{
                                                   IssueCategory   = "IPInformation"
                                                 }

                # add CollectionTime to existing array
                $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable

                # add Computer & UserLoggedOn info to existing array
                $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

                # Validating/fixing schema data structure of source data
                $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

                # Aligning data structure with schema (requirement for DCR)
                $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable
            }         

    #-------------------------------------------------------------------------------------------
    # Create/Update Schema for LogAnalytics Table & Data Collection Rule schema
    #-------------------------------------------------------------------------------------------

        If ( ($TableDcrSchemaCreateUpdateAppId) -and ($TableDcrSchemaCreateUpdateAppSecret) )
            {
                #-----------------------------------------------------------------------------------------------
                # Check if table and DCR exist - or schema must be updated due to source object schema changes
                #-----------------------------------------------------------------------------------------------

                    # Get insight about the schema structure
                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnFormat Array

                    $StructureCheck = Get-AzLogAnalyticsTableAzDataCollectionRuleStatus -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -TableName $TableName -DcrName $DcrName -SchemaSourceObject $Schema `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId

                #-----------------------------------------------------------------------------------------------
                # Structure check = $true -> Create/update table & DCR with necessary schema
                #-----------------------------------------------------------------------------------------------

                    If ($StructureCheck -eq $true)
                        {
                            If ( ( $env:COMPUTERNAME -in $AzDcrDceTableCreateFromReferenceMachine) -or ($AzDcrDceTableCreateFromAnyMachine -eq $true) )    # manage table creations
                                {
                                    # build schema to be used for LogAnalytics Table
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType Table -ReturnFormat Hash

                                    CreateUpdate-AzLogAnalyticsCustomLogTableDcr -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema -TableName $TableName `
                                                                                 -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId


                                    # build schema to be used for DCR
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType DCR -ReturnFormat Hash

                                    CreateUpdate-AzDataCollectionRuleLogIngestCustomLog -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema `
                                                                                        -DceName $DceName -DcrName $DcrName -TableName $TableName `
                                                                                        -LogIngestServicePricipleObjectId $AzDcrLogIngestServicePrincipalObjectId `
                                                                                        -AzDcrSetLogIngestApiAppPermissionsDcrLevel $AzDcrSetLogIngestApiAppPermissionsDcrLevel `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId
                                }
                        }

                } # create table/DCR

    #-----------------------------------------------------------------------------------------------
    # Upload data to LogAnalytics using DCR / DCE / Log Ingestion API
    #-----------------------------------------------------------------------------------------------

        $AzDcrDceDetails = Get-AzDcrDceDetails -DcrName $DcrName -DceName $DceName `
                                               -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId

        Post-AzLogAnalyticsLogIngestCustomLogDcrDce  -DceUri $AzDcrDceDetails[2] -DcrImmutableId $AzDcrDceDetails[6] `
                                                     -DcrStream $AzDcrDceDetails[7] -Data $DataVariable `
                                                     -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId
        
        # Write result to screen
        $DataVariable | Out-String | Write-Verbose 


###############################################################
# LOCAL ADMINISTRATORS GROUP [15]
###############################################################

    Write-output ""
    Write-output "#########################################################################################"
    Write-output "LOCAL ADMINISTRATORS GROUP INFORMATION [15]"
    Write-output ""

    #-------------------------------------------------------------------------------------------
    # Variables
    #-------------------------------------------------------------------------------------------
            
        $TableName  = 'InvClientLocalAdminsV2'   # must not contain _CL
        $DcrName    = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"

    #-------------------------------------------------------------------------------------------
    # Collecting data (in)
    #-------------------------------------------------------------------------------------------
            
        Write-Output "Collecting Local Admin information"

        $LocalAdminGroupname = (Get-localgroup -Sid S-1-5-32-544).name       # SID S-1-5-32-544 = local computers Administrators group
        $LocalAdmins = Get-LocalGroupMember -Group  $LocalAdminGroupname

    #-------------------------------------------------------------------------------------------
    # Preparing data structure
    #-------------------------------------------------------------------------------------------

        If ($LocalAdmins -eq $null)
            {
                ########################################################################################################################
                # Fix local admin group - The problem is empty SIDs in the Administrators Group caused by domain joins/leave/join etc
                ########################################################################################################################
                    $administrators = @(
                    ([ADSI]"WinNT://./$($LocalAdminGroupname)").psbase.Invoke('Members') |
                    % { 
                        $_.GetType().InvokeMember('AdsPath','GetProperty',$null,$($_),$null) 
                    }
                    ) -match '^WinNT';

                    $administrators = $administrators -replace "WinNT://",""

                    foreach ($administrator in $administrators)
                        {
                            #write-host $administrator "got here"
                            if ($administrator -like "$env:COMPUTERNAME/*" -or $administrator -like "AzureAd/*")
                                {
                                    continue;
                                }
                            elseif ($administrator -match "S-1") #checking for empty/orphaned SIDs only
                                {
                                    Remove-LocalGroupMember -group $LocalAdminGroupname -member $administrator
                                }
                        }
            }
        Else
            {
                # convert CIM array to PSCustomObject and remove CIM class information
                $DataVariable = Convert-CimArrayToObjectFixStructure -data $LocalAdmins
    
                # add CollectionTime to existing array
                $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable

                # add Computer & UserLoggedOn info to existing array
                $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

                # Validating/fixing schema data structure of source data
                $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

                # Aligning data structure with schema (requirement for DCR)
                $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable
            }

    #-------------------------------------------------------------------------------------------
    # Create/Update Schema for LogAnalytics Table & Data Collection Rule schema
    #-------------------------------------------------------------------------------------------

        If ( ($TableDcrSchemaCreateUpdateAppId) -and ($TableDcrSchemaCreateUpdateAppSecret) )
            {
                #-----------------------------------------------------------------------------------------------
                # Check if table and DCR exist - or schema must be updated due to source object schema changes
                #-----------------------------------------------------------------------------------------------

                    # Get insight about the schema structure
                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnFormat Array

                    $StructureCheck = Get-AzLogAnalyticsTableAzDataCollectionRuleStatus -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -TableName $TableName -DcrName $DcrName -SchemaSourceObject $Schema `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId

                #-----------------------------------------------------------------------------------------------
                # Structure check = $true -> Create/update table & DCR with necessary schema
                #-----------------------------------------------------------------------------------------------

                    If ($StructureCheck -eq $true)
                        {
                            If ( ( $env:COMPUTERNAME -in $AzDcrDceTableCreateFromReferenceMachine) -or ($AzDcrDceTableCreateFromAnyMachine -eq $true) )    # manage table creations
                                {
                                    # build schema to be used for LogAnalytics Table
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType Table -ReturnFormat Hash

                                    CreateUpdate-AzLogAnalyticsCustomLogTableDcr -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema -TableName $TableName `
                                                                                 -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId


                                    # build schema to be used for DCR
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType DCR -ReturnFormat Hash

                                    CreateUpdate-AzDataCollectionRuleLogIngestCustomLog -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema `
                                                                                        -DceName $DceName -DcrName $DcrName -TableName $TableName `
                                                                                        -LogIngestServicePricipleObjectId $AzDcrLogIngestServicePrincipalObjectId `
                                                                                        -AzDcrSetLogIngestApiAppPermissionsDcrLevel $AzDcrSetLogIngestApiAppPermissionsDcrLevel `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId
                                }
                        }

                } # create table/DCR

    #-----------------------------------------------------------------------------------------------
    # Upload data to LogAnalytics using DCR / DCE / Log Ingestion API
    #-----------------------------------------------------------------------------------------------

        $AzDcrDceDetails = Get-AzDcrDceDetails -DcrName $DcrName -DceName $DceName `
                                               -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId

        Post-AzLogAnalyticsLogIngestCustomLogDcrDce  -DceUri $AzDcrDceDetails[2] -DcrImmutableId $AzDcrDceDetails[6] `
                                                     -DcrStream $AzDcrDceDetails[7] -Data $DataVariable `
                                                     -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId
        
        # Write result to screen
        $DataVariable | Out-String | Write-Verbose 


#####################################################################
# WINDOWS FIREWALL [16]
#####################################################################

    Write-output ""
    Write-output "#########################################################################################"
    Write-output "WINDOWS FIREWALL INFORMATION [16]"
    Write-output ""

        #-------------------------------------------------------------------------------------------
        # Variables
        #-------------------------------------------------------------------------------------------
            
            $TableName  = 'InvClientWindowsFirewallInfoV2'   # must not contain _CL
            $DcrName    = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"

        #-------------------------------------------------------------------------------------------
        # Collecting data (in)
        #-------------------------------------------------------------------------------------------
            
            Write-Output "Collecting Windows Firewall information"

            $WinFw = Get-NetFirewallProfile -policystore activestore

    #-------------------------------------------------------------------------------------------
    # Preparing data structure
    #-------------------------------------------------------------------------------------------
        If ($WinFw)
            {
                # convert CIM array to PSCustomObject and remove CIM class information
                $DataVariable = Convert-CimArrayToObjectFixStructure -data $WinFw
    
                # add CollectionTime to existing array
                $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable

                # add Computer & UserLoggedOn info to existing array
                $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

                # Validating/fixing schema data structure of source data
                $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

                # Aligning data structure with schema (requirement for DCR)
                $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable
            }
        Else
            {

                # log issue - typically WMI issue
                $TableName  = 'InvClientCollectionIssuesV2'   # must not contain _CL
                $DcrName    = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"

                $DataVariable = [pscustomobject]@{
                                                   IssueCategory   = "WinFwInformation"
                                                 }

                # add CollectionTime to existing array
                $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable

                # add Computer & UserLoggedOn info to existing array
                $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

                # Validating/fixing schema data structure of source data
                $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

                # Aligning data structure with schema (requirement for DCR)
                $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable
            }         

    #-------------------------------------------------------------------------------------------
    # Create/Update Schema for LogAnalytics Table & Data Collection Rule schema
    #-------------------------------------------------------------------------------------------

        If ( ($TableDcrSchemaCreateUpdateAppId) -and ($TableDcrSchemaCreateUpdateAppSecret) )
            {
                #-----------------------------------------------------------------------------------------------
                # Check if table and DCR exist - or schema must be updated due to source object schema changes
                #-----------------------------------------------------------------------------------------------

                    # Get insight about the schema structure
                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnFormat Array

                    $StructureCheck = Get-AzLogAnalyticsTableAzDataCollectionRuleStatus -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -TableName $TableName -DcrName $DcrName -SchemaSourceObject $Schema `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId

                #-----------------------------------------------------------------------------------------------
                # Structure check = $true -> Create/update table & DCR with necessary schema
                #-----------------------------------------------------------------------------------------------

                    If ($StructureCheck -eq $true)
                        {
                            If ( ( $env:COMPUTERNAME -in $AzDcrDceTableCreateFromReferenceMachine) -or ($AzDcrDceTableCreateFromAnyMachine -eq $true) )    # manage table creations
                                {
                                    # build schema to be used for LogAnalytics Table
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType Table -ReturnFormat Hash

                                    CreateUpdate-AzLogAnalyticsCustomLogTableDcr -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema -TableName $TableName `
                                                                                 -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId


                                    # build schema to be used for DCR
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType DCR -ReturnFormat Hash

                                    CreateUpdate-AzDataCollectionRuleLogIngestCustomLog -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema `
                                                                                        -DceName $DceName -DcrName $DcrName -TableName $TableName `
                                                                                        -LogIngestServicePricipleObjectId $AzDcrLogIngestServicePrincipalObjectId `
                                                                                        -AzDcrSetLogIngestApiAppPermissionsDcrLevel $AzDcrSetLogIngestApiAppPermissionsDcrLevel `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId
                                }
                        }

                } # create table/DCR

    #-----------------------------------------------------------------------------------------------
    # Upload data to LogAnalytics using DCR / DCE / Log Ingestion API
    #-----------------------------------------------------------------------------------------------

        $AzDcrDceDetails = Get-AzDcrDceDetails -DcrName $DcrName -DceName $DceName `
                                               -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId

        Post-AzLogAnalyticsLogIngestCustomLogDcrDce  -DceUri $AzDcrDceDetails[2] -DcrImmutableId $AzDcrDceDetails[6] `
                                                     -DcrStream $AzDcrDceDetails[7] -Data $DataVariable `
                                                     -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId
        
        # Write result to screen
        $DataVariable | Out-String | Write-Verbose 



###############################################################
# GROUP POLICY REFRESH [17]
###############################################################

    Write-output ""
    Write-output "#########################################################################################"
    Write-output "GROUP POLICY INFORMATION [17]"
    Write-output ""

    #-------------------------------------------------------------------------------------------
    # Variables
    #-------------------------------------------------------------------------------------------
            
        $TableName  = 'InvClientGroupPolicyRefreshV2'   # must not contain _CL
        $DcrName    = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"

    #-------------------------------------------------------------------------------------------
    # Collecting data (in)
    #-------------------------------------------------------------------------------------------
            
        Write-Output "Collecting Group Policy information"

        # Get StartTimeHi Int32 value
        $startTimeHi = (Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Extension-List\{00000000-0000-0000-0000-000000000000}").startTimeHi
            
        # Get StartTimeLo Int32 value
        $startTimeLo = (Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Extension-List\{00000000-0000-0000-0000-000000000000}").startTimeLo
            
        # Convert from FileTime
        # [datetime]::FromFileTime(([Int64] $startTimeHi -shl 32) -bor $startTimeLo)

        $GPLastRefresh = [datetime]::FromFileTime(([Int64] ((Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Extension-List\{00000000-0000-0000-0000-000000000000}").startTimeHi) -shl 32) -bor ((Get-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Extension-List\{00000000-0000-0000-0000-000000000000}").startTimeLo))
        $CalculateGPLastRefreshTimeSpan = NEW-TIMESPAN –Start $GPLastRefresh –End (Get-date)

    #-------------------------------------------------------------------------------------------
    # Preparing data structure
    #-------------------------------------------------------------------------------------------

        If ($GPLastRefresh)
            {
                $DataArray = [pscustomobject]@{
                                                GPLastRefresh       = $GPLastRefresh
                                                GPLastRefreshDays   = $CalculateGPLastRefreshTimeSpan.Days
                                              }
   
                # add CollectionTime to existing array
                $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataArray

                # add Computer & UserLoggedOn info to existing array
                $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

                # Validating/fixing schema data structure of source data
                $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

                # Aligning data structure with schema (requirement for DCR)
                $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable
            }

    #-------------------------------------------------------------------------------------------
    # Create/Update Schema for LogAnalytics Table & Data Collection Rule schema
    #-------------------------------------------------------------------------------------------

        If ( ($TableDcrSchemaCreateUpdateAppId) -and ($TableDcrSchemaCreateUpdateAppSecret) )
            {
                #-----------------------------------------------------------------------------------------------
                # Check if table and DCR exist - or schema must be updated due to source object schema changes
                #-----------------------------------------------------------------------------------------------

                    # Get insight about the schema structure
                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnFormat Array

                    $StructureCheck = Get-AzLogAnalyticsTableAzDataCollectionRuleStatus -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -TableName $TableName -DcrName $DcrName -SchemaSourceObject $Schema `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId

                #-----------------------------------------------------------------------------------------------
                # Structure check = $true -> Create/update table & DCR with necessary schema
                #-----------------------------------------------------------------------------------------------

                    If ($StructureCheck -eq $true)
                        {
                            If ( ( $env:COMPUTERNAME -in $AzDcrDceTableCreateFromReferenceMachine) -or ($AzDcrDceTableCreateFromAnyMachine -eq $true) )    # manage table creations
                                {
                                    # build schema to be used for LogAnalytics Table
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType Table -ReturnFormat Hash

                                    CreateUpdate-AzLogAnalyticsCustomLogTableDcr -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema -TableName $TableName `
                                                                                 -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId


                                    # build schema to be used for DCR
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType DCR -ReturnFormat Hash

                                    CreateUpdate-AzDataCollectionRuleLogIngestCustomLog -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema `
                                                                                        -DceName $DceName -DcrName $DcrName -TableName $TableName `
                                                                                        -LogIngestServicePricipleObjectId $AzDcrLogIngestServicePrincipalObjectId `
                                                                                        -AzDcrSetLogIngestApiAppPermissionsDcrLevel $AzDcrSetLogIngestApiAppPermissionsDcrLevel `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId
                                }
                        }

                } # create table/DCR

    #-----------------------------------------------------------------------------------------------
    # Upload data to LogAnalytics using DCR / DCE / Log Ingestion API
    #-----------------------------------------------------------------------------------------------

        $AzDcrDceDetails = Get-AzDcrDceDetails -DcrName $DcrName -DceName $DceName `
                                               -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId

        Post-AzLogAnalyticsLogIngestCustomLogDcrDce  -DceUri $AzDcrDceDetails[2] -DcrImmutableId $AzDcrDceDetails[6] `
                                                     -DcrStream $AzDcrDceDetails[7] -Data $DataVariable `
                                                     -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId
        
        # Write result to screen
        $DataVariable | Out-String | Write-Verbose 


###############################################################
# TPM [18]
###############################################################

    Write-output ""
    Write-output "#########################################################################################"
    Write-output "TPM [18]"
    Write-output ""

    #-------------------------------------------------------------------------------------------
    # Variables
    #-------------------------------------------------------------------------------------------
            
        $TableName  = 'InvClientHardwareTPMInfoV2'   # must not contain _CL
        $DcrName    = "dcr-" + $AzDcrPrefixClient + "-" + $TableName + "_CL"

    #-------------------------------------------------------------------------------------------
    # Collecting data (in)
    #-------------------------------------------------------------------------------------------
            
        Write-Output "Collecting TPM information"

        $TPM = Get-TPM -ErrorAction SilentlyContinue -WarningVariable SilentlyContinue

    #-------------------------------------------------------------------------------------------
    # Preparing data structure
    #-------------------------------------------------------------------------------------------

        If ($TPM)
            {
                # Get TPM Version, cannot be found using Get-TPM - must be retrieved from WMI
                $TPMInfo_WMI = Get-WmiObject -Namespace "Root\CIMV2\Security\MicrosoftTpm" -query "Select * from Win32_Tpm"
                If ($TPMInfo_WMI)
                    {
                        $TPM_Version_WMI_Major = (($TPMInfo_WMI.SpecVersion.split(","))[0])
                        $TPM_Version_WMI_Major = $TPM_Version_WMI_Major.trim()

                        $TPM_Version_WMI_Minor = (($TPMInfo_WMI.SpecVersion.split(","))[1])
                        $TPM_Version_WMI_Minor = $TPM_Version_WMI_Minor.trim()

                        $TPM_Version_WMI_Rev = (($TPMInfo_WMI.SpecVersion.split(","))[2])
                        $TPM_Version_WMI_Rev = $TPM_Version_WMI_Rev.trim()
                    }

                $TPMCount = 0
                ForEach ($Entry in $TPM)
                    {
                        $TPMCount = 1 + $TPMCount
                    }

                $CountDataVariable = $TPMCount
                $PosDataVariable   = 0
                Do
                    {
                        $TPM[$PosDataVariable] | Add-Member -Type NoteProperty -Name TPM_Version_WMI_Major -Value $TPM_Version_WMI_Major -force
                        $TPM[$PosDataVariable] | Add-Member -Type NoteProperty -Name TPM_Version_WMI_Minor -Value $TPM_Version_WMI_Minor -force
                        $TPM[$PosDataVariable] | Add-Member -Type NoteProperty -Name TPM_Version_WMI_Rev -Value $TPM_Version_WMI_Rev -force
                        $PosDataVariable = 1 + $PosDataVariable
                    }
                Until ($PosDataVariable -eq $CountDataVariable)

                # add CollectionTime to existing array
                $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $TPM

                # add Computer & UserLoggedOn info to existing array
                $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

                # Validating/fixing schema data structure of source data
                $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable
            }
        Else
            {
                $DataVariable = [pscustomobject]@{
                                                    IssueCategory   = "TPM"
                                                    }

                # add CollectionTime to existing array
                $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable

                # add Computer & UserLoggedOn info to existing array
                $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable -Column1Name Computer -Column1Data $Env:ComputerName -Column2Name UserLoggedOn -Column2Data $UserLoggedOn

                # Validating/fixing schema data structure of source data
                $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable

                # Aligning data structure with schema (requirement for DCR)
                $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable
            }

    #-------------------------------------------------------------------------------------------
    # Create/Update Schema for LogAnalytics Table & Data Collection Rule schema
    #-------------------------------------------------------------------------------------------

        If ( ($TableDcrSchemaCreateUpdateAppId) -and ($TableDcrSchemaCreateUpdateAppSecret) )
            {
                #-----------------------------------------------------------------------------------------------
                # Check if table and DCR exist - or schema must be updated due to source object schema changes
                #-----------------------------------------------------------------------------------------------

                    # Get insight about the schema structure
                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnFormat Array

                    $StructureCheck = Get-AzLogAnalyticsTableAzDataCollectionRuleStatus -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -TableName $TableName -DcrName $DcrName -SchemaSourceObject $Schema `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId

                #-----------------------------------------------------------------------------------------------
                # Structure check = $true -> Create/update table & DCR with necessary schema
                #-----------------------------------------------------------------------------------------------

                    If ($StructureCheck -eq $true)
                        {
                            If ( ( $env:COMPUTERNAME -in $AzDcrDceTableCreateFromReferenceMachine) -or ($AzDcrDceTableCreateFromAnyMachine -eq $true) )    # manage table creations
                                {
                                    # build schema to be used for LogAnalytics Table
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType Table -ReturnFormat Hash

                                    CreateUpdate-AzLogAnalyticsCustomLogTableDcr -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema -TableName $TableName `
                                                                                 -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId


                                    # build schema to be used for DCR
                                    $Schema = Get-ObjectSchema -Data $DataVariable -ReturnType DCR -ReturnFormat Hash

                                    CreateUpdate-AzDataCollectionRuleLogIngestCustomLog -AzLogWorkspaceResourceId $ClientLogAnalyticsWorkspaceResourceId -SchemaSourceObject $Schema `
                                                                                        -DceName $DceName -DcrName $DcrName -TableName $TableName `
                                                                                        -LogIngestServicePricipleObjectId $AzDcrLogIngestServicePrincipalObjectId `
                                                                                        -AzDcrSetLogIngestApiAppPermissionsDcrLevel $AzDcrSetLogIngestApiAppPermissionsDcrLevel `
                                                                                        -AzAppId $TableDcrSchemaCreateUpdateAppId -AzAppSecret $TableDcrSchemaCreateUpdateAppSecret -TenantId $TenantId
                                }
                        }

                } # create table/DCR

    #-----------------------------------------------------------------------------------------------
    # Upload data to LogAnalytics using DCR / DCE / Log Ingestion API
    #-----------------------------------------------------------------------------------------------

        $AzDcrDceDetails = Get-AzDcrDceDetails -DcrName $DcrName -DceName $DceName `
                                               -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId

        Post-AzLogAnalyticsLogIngestCustomLogDcrDce  -DceUri $AzDcrDceDetails[2] -DcrImmutableId $AzDcrDceDetails[6] `
                                                     -DcrStream $AzDcrDceDetails[7] -Data $DataVariable `
                                                     -AzAppId $LogIngestAppId -AzAppSecret $LogIngestAppSecret -TenantId $TenantId
        
        # Write result to screen
        $DataVariable | Out-String | Write-Verbose 


##################################
# WRITE LASTRUN KEY
##################################

    $Now = (Get-date)

    # Create initial reg-path stucture in registry
        If (-not (Test-Path $LastRun_RegPath))
            {
                $Err = New-Item -Path $LastRun_RegPath -Force | Out-Null
            }

    #  Set last run value in registry
        $Result = New-ItemProperty -Path $LastRun_RegPath -Name $LastRun_RegKey -Value $Now -PropertyType STRING -Force | Out-Null

Stop-Transcript

