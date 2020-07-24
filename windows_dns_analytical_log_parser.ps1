function Get-ParsedDNSAnalyticalLog
{
    <#
    .SYNOPSIS
    This cmdlet parses a Windows DNS Analytical log with details.

    Author: @ksec_io
    License: GPL-3.0 License
    Required Dependencies: None
    Optional Dependencies: None

    .DESCRIPTION
    When a DNS Analytical log is converted with this cmdlet it will be turned into objects for further parsing.

    .EXAMPLE 1
    PS C:\> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -force
    PS C:\> . .\windows_dns_analytical_log_parser.ps1
    ####### Disable Microsoft-Windows-DNSServer/Analytical Log
    PS C:\> wevtutil sl "Microsoft-Windows-DNSServer/Analytical" /e:false
    PS C:\> move C:\Windows\System32\winevt\Logs\Microsoft-Windows-DNSServer%4Analytical.etl C:\temp\
    ####### Enable Microsoft-Windows-DNSServer/Analytical Log
    PS C:\> Set-DnsServerDiagnostics -All $true
    ## This one will filter all Event ID except Event ID 256 or 257 and export the DNSServer/Analytical Event Log to expected text file format.
    PS C:\> wevtutil qe /lf "C:\temp\Microsoft-Windows-DNSServer%4Analytical.etl" /q:"*[System[(EventID=256 or EventID=257)]]" /f:text > C:\temp\Microsoft-Windows-DNSServer_Analytical.txt
    PS C:\> Get-ParsedDNSAnalyticalLog -DNSLogFile "C:\temp\Microsoft-Windows-DNSServer_Analytical.txt" -debugmode "no"

        DNS_DateTime      : 7/17/2020 3:21:52 PM
        DNS_Remote_IP     : ::1
        DNS_ResponseCode  : NOERROR
        DNS_Question_Type : A
        DNS_Question_Name : www.google.com.hk
        DNS_DATA          : 172.217.24.67

    .EXAMPLE 2
    PS C:\> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -force
    PS C:\> . .\windows_dns_analytical_log_parser
    ####### Disable Microsoft-Windows-DNSServer/Analytical Log
    PS C:\> wevtutil sl "Microsoft-Windows-DNSServer/Analytical" /e:false
    PS C:\> move C:\Windows\System32\winevt\Logs\Microsoft-Windows-DNSServer%4Analytical.etl C:\temp\
    ####### Enable Microsoft-Windows-DNSServer/Analytical Log
    PS C:\> Set-DnsServerDiagnostics -All $true
    ## This one will filter all Event ID except Event ID 256 or 257 and export the DNSServer/Analytical Event Log to expected text file format.
    PS C:\> wevtutil qe /lf "C:\temp\Microsoft-Windows-DNSServer%4Analytical.etl" /f:text > C:\temp\Microsoft-Windows-DNSServer_Analytical_full.txt
    PS C:\> Get-ParsedDNSAnalyticalLog -DNSLogFile "C:\temp\Microsoft-Windows-DNSServer_Analytical.txt" -debugmode "no" | Where-Object DNS_Question_Name -like *msedge.api.cdp.microsoft.com* | Format-Table -Property * -Autosize | Out-String -Width 192

        DNS_DateTime         DNS_Remote_IP DNS_ResponseCode DNS_Question_Type DNS_Question_Name            DNS_DATA                                                                           
          
        ------------         ------------- ---------------- ----------------- -----------------            --------   
        7/17/2020 3:06:15 PM ::1           NOERROR          A                 msedge.api.cdp.microsoft.com api.cdp.microsoft.com....                                                          
          
        7/17/2020 3:06:15 PM 127.0.0.1     NOERROR          A                 msedge.api.cdp.microsoft.com api.cdp.microsoft.com....         

    .EXAMPLE 3
    PS C:\> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -force
    PS C:\> . .\windows_dns_analytical_log_parser.ps1
    PS C:\> Get-ParsedDNSAnalyticalLog -DNSLogFile ".\dns5.log" -debugmode "no" | Where-Object DNS_Question_Name -like *msedge.api.cdp.microsoft.com* | export-csv -Path C:\dns.csv -NoTypeInformation
    #>

    [CmdletBinding()]
    param(
      [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
      [Alias('Fullname')]
      [ValidateScript({Test-Path($_)})]
      [string] $DNSLogFile = 'StringMode',
      [string] $debugmode = 'StringMode')


    BEGIN { }

    PROCESS {
        try
        {
            $entry_num=0;
            . .\DNS-Lib.ps1

            $DNS_Description_Array=@("TCP","Source","Destination","InterfaceIP","RD","QNAME","QTYPE","XID","Port","Flags","ServerScope","CacheScope","AA","AD","DNSSEC","RCODE","Scope","Zone","SECURE","ZoneScope")

            #empty array
            $AllObjectsArray = @()
            
            $ALL_DNS_DATA = (Get-Content $DNSLogFile -raw)

            $ALL_DNS_DATA_regex = [regex] 'Event\[\d+\]:\r\n\s+Log Name: (?<DNS_LogName>.*?)\r\n\s+Source: (?<DNS_Source>.*?)\r\n\s+Date: (?<DNS_DateTime>.*?)\r\n\s+Event ID: (?<DNS_EventID>.*?)\r\n\s+Task: (?<DNS_Task>.*?)\r\n\s+Level: (?<DNS_Level>.*?)\r\n\s+Opcode: (?<DNS_Opcode>.*?)\r\n\s+Keyword: (?<DNS_Keyword>.*?)\r\n\s+User: (?<DNS_User>.*?)\r\n\s+User Name: (?<DNS_UserName>.*?)\r\n\s+Computer: (?<DNS_Computer>.*?)\r\n\s+Description: \r\n(?<DNS_DATA_TYPE>.*?): (?<DNS_Description>.*?)PacketData=0x(?<DNS_PacketData>.*)'

            $ALL_DNS_DATA_match = $ALL_DNS_DATA_regex.Match($ALL_DNS_DATA)

            while ($ALL_DNS_DATA_match.Success) {

                # $DNSLogHashTable = New-Object PSObject               
                $DNSLogHashTable = [ordered]@{} # use hashtable
                $DNSLogHashTable.add('DNS_LogName', $ALL_DNS_DATA_match.Groups['DNS_LogName'].Value)
                $DNSLogHashTable.add('DNS_Source', $ALL_DNS_DATA_match.Groups['DNS_Source'].Value)
                $DNSLogHashTable.add('DNS_DateTime', $ALL_DNS_DATA_match.Groups['DNS_DateTime'].Value)
                $DNSLogHashTable.add('DNS_EventID', $ALL_DNS_DATA_match.Groups['DNS_EventID'].Value)
                $DNSLogHashTable.add('DNS_Task', $ALL_DNS_DATA_match.Groups['DNS_Task'].Value)
                $DNSLogHashTable.add('DNS_Level', $ALL_DNS_DATA_match.Groups['DNS_Level'].Value)
                $DNSLogHashTable.add('DNS_Opcode', $ALL_DNS_DATA_match.Groups['DNS_Opcode'].Value)
                $DNSLogHashTable.add('DNS_Keyword', $ALL_DNS_DATA_match.Groups['DNS_Keyword'].Value)
                $DNSLogHashTable.add('DNS_User', $ALL_DNS_DATA_match.Groups['DNS_User'].Value)
                $DNSLogHashTable.add('DNS_UserName', $ALL_DNS_DATA_match.Groups['DNS_UserName'].Value)
                $DNSLogHashTable.add('DNS_Computer', $ALL_DNS_DATA_match.Groups['DNS_Computer'].Value)
                $DNSLogHashTable.add('DNS_DATA_TYPE', $ALL_DNS_DATA_match.Groups['DNS_DATA_TYPE'].Value)
                $DNSLogHashTable.add('DNS_Description', $ALL_DNS_DATA_match.Groups['DNS_Description'].Value)
                $DNSLogHashTable.add('DNS_PacketData', $ALL_DNS_DATA_match.Groups['DNS_PacketData'].Value)
                
                ##################################
                if ($ALL_DNS_DATA_match.Groups['DNS_Description'].Value) {

                    $regex = [regex] '(?<name>\w*)=(?<value>.*?)(; |$)'
                    $match = $regex.Match($ALL_DNS_DATA_match.Groups['DNS_Description'].Value)

                    while ($match.Success) {
                        #[PSCustomObject]@{
                        #    Name = $match.Groups['name'].Value
                        #    Value = $match.Groups['value'].Value
                        #}
                        $DNSLogHashTable.add($match.Groups['name'].Value, $match.Groups['value'].Value)

                        $Exists_in_DNS_Description_Array=0;
                        $DNS_Description_Array | ForEach-Object {
                            if ($match.Groups['name'].Value -eq $PSItem) {
                                $Exists_in_DNS_Description_Array=1;
                            }
                        }
                        if ($Exists_in_DNS_Description_Array -eq 0){
                            write-host $match.Groups['name'].Value
                        }

                        $match = $match.NextMatch()
                    }
                    $DNS_Description_Array | ForEach-Object {
                        if (!$DNSLogHashTable[$PSItem]) {
                            #$DNSLogHashTable[$PSItem]
                            $DNSLogHashTable.add($PSItem, $null)
                        }
                    }
                }

                if ($ALL_DNS_DATA_match.Groups['DNS_PacketData'].Value -and $DNSLogHashTable['DNS_DATA_TYPE'] -eq "RESPONSE_SUCCESS") {
                        $DNSPacketData = [DNSPacket]::new();
                        $PacketData_temp_ByteArray=Convert-HexStringToByteArray($ALL_DNS_DATA_match.Groups['DNS_PacketData'].Value.Trim());
                        $DNSPacketData.AddData($PacketData_temp_ByteArray);
                        $PacketData_temp_ByteArray=$null
                        $DNSPacketData.AnswerRecords | % {
                            $RDATA_index=0;
                            $RDATA_TYPE=$_.TYPE;
                            $LENGTH_BEFORE_DOT=0;
                            $SUBDOMAIN_INDEX=0;
                            $Is_DNS_pointer=0;
                            $RDATA_decoded+="`n";
                            $_.RDATA |% {
                                if ($_ -eq 192){ # 0xC0 DNS pointer. 11 00 00 00, 2 high bit is dns pointer
                                    $Is_DNS_pointer=1;
                                } elseif ($Is_DNS_pointer -eq 1){
                                    $RDATA_decoded+='.{0}' -f $DNSPacketData.ParseLabel($_, 3).Label
                                    $Is_DNS_pointer=0;
                                } elseif ($Is_DNS_pointer -eq 0){
                                    if ($RDATA_TYPE -eq 1) { # A Record / How about AAAA Record ?
                                        if($RDATA_index -gt 0) {
                                            $RDATA_decoded+='.{0}' -f $_
                                        } else {
                                            $RDATA_decoded+=$_
                                        }
                                    } elseif ($RDATA_TYPE -eq 5) { # CNAME Record
                                        if ($_ -eq 0){
                                            #write-host "End of record"
                                        } elseif($RDATA_index -eq 0) {
                                            $LENGTH_BEFORE_DOT=$_;
                                            #$SUBDOMAIN_INDEX=1;
                                            #$SUBDOMAIN_INDEX++;
                                        } elseif ($SUBDOMAIN_INDEX -lt $LENGTH_BEFORE_DOT) {
                                            #write-host "RDATA_index" $RDATA_index
                                            #write-host "_" $_
                                            #write-host "char_" [char]$_
                                            #write-host "LENGTH_BEFORE_DOT" $LENGTH_BEFORE_DOT
                                            #write-host "SUBDOMAIN_INDEX" $SUBDOMAIN_INDEX
                                            $RDATA_decoded+=[char]$_;
                                            $SUBDOMAIN_INDEX++;
                                        } elseif ($SUBDOMAIN_INDEX -eq $LENGTH_BEFORE_DOT) {
                                            $RDATA_decoded+='.';
                                            $LENGTH_BEFORE_DOT=$_;
                                            $SUBDOMAIN_INDEX=0;
                                            #$SUBDOMAIN_INDEX++;
                                        }
                                    } else {
                                        if($RDATA_index -gt 0) {
                                            $RDATA_decoded+=[char]$_
                                        } else {
                                            $RDATA_decoded+="`n";
                                        }
                                    }
                                }
                                $RDATA_index++;
                            }
                        }
                        
                        if ($RDATA_decoded) {
                            $RDATA_decoded=$RDATA_decoded.Trim() -replace "^\n",""
                            $DNSLogHashTable.add('RDATA_decoded', $RDATA_decoded)
                        } else {
                            $RDATA_decoded=$null
                            $DNSLogHashTable.add('RDATA_decoded', $RDATA_decoded)
                        }
                        if ($debugmode -eq "yes"){
                            write-host $RDATA_decoded
                        }
                        $RDATA_decoded=$null
                        $DNSPacketData=$null
                } else {
                    $RDATA_decoded=$null
                    $DNSLogHashTable.add('RDATA_decoded', $RDATA_decoded)
                }

                ##################################

                if ($DNSLogHashTable){
                    $DNSLogObject = New-Object PSObject -Property $DNSLogHashTable
                }
                $DNSLogHashTable = $null;
                $AllObjectsArray += $DNSLogObject
                #write-host $DNSLogObject.RDATA_decoded
                $DNSLogObject = $null;
                $entry_num++;
                if ($debugmode -eq "yes"){
                    write-host $entry_num;
                }

                $ALL_DNS_DATA_match = $ALL_DNS_DATA_match.NextMatch()
            }
            return $AllObjectsArray
        }
        catch
        {
            Write-Error $_
        }
        finally
        {
        }
    }
    END { }
}