function Get-ParsedDNSDebugLog
{
    <#
    .SYNOPSIS
    This cmdlet parses a Windows DNS Debug log with details.

    Author: @ksec_io
    License: GPL-3.0 License
    Required Dependencies: None
    Optional Dependencies: None

    .DESCRIPTION
    When a DNS log is converted with this cmdlet it will be turned into objects for further parsing.

    .EXAMPLE 1
    PS C:\> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -force
    PS C:\> . .\windows_dns_debug_log_parser.ps1
    PS C:\> Get-ParsedDNSDebugLog -DNSLogFile ".\dns.log" -debugmode "no"

        DNS_DateTime      : 7/17/2020 3:21:52 PM
        DNS_Remote_IP     : ::1
        DNS_ResponseCode  : NOERROR
        DNS_Question_Type : A
        DNS_Question_Name : www.google.com.hk
        DNS_DATA          : 172.217.24.67

    .EXAMPLE 2
    PS C:\> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -force
    PS C:\> . .\windows_dns_debug_log_parser
    PS C:\> Get-ParsedDNSDebugLog -DNSLogFile ".\dns5.log" -debugmode "no" | Where-Object DNS_Question_Name -like *msedge.api.cdp.microsoft.com* | Format-Table -Property * -Autosize | Out-String -Width 192

        DNS_DateTime         DNS_Remote_IP DNS_ResponseCode DNS_Question_Type DNS_Question_Name            DNS_DATA                                                                           
          
        ------------         ------------- ---------------- ----------------- -----------------            --------   
        7/17/2020 3:06:15 PM ::1           NOERROR          A                 msedge.api.cdp.microsoft.com api.cdp.microsoft.com....                                                          
          
        7/17/2020 3:06:15 PM 127.0.0.1     NOERROR          A                 msedge.api.cdp.microsoft.com api.cdp.microsoft.com....         

    .EXAMPLE 3
    PS C:\> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -force
    PS C:\> . .\windows_dns_debug_log_parser.ps1
    PS C:\> Get-ParsedDNSDebugLog -DNSLogFile ".\dns5.log" -debugmode "no" | Where-Object DNS_Question_Name -like *msedge.api.cdp.microsoft.com* | export-csv -Path dns.csv -NoTypeInformation
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

            #empty array
            $AllObjectsArray = @()
            
            $ALL_DNS_DATA = (Get-Content $DNSLogFile -raw)

            $ALL_DNS_DATA_regex = [regex] '(?<DNS_DateTime>\d{1,2}\/\d{1,2}\/\d{4} \d{1,2}:\d{1,2}:\d{1,2} (AM|PM))\s{1}(?<DNS_ThreadID>\w{4})\s{1}(?<DNS_Context>PACKET)\s{2}(?<DNS_Internal_packet_identifier>\w{16})\s{1}(?<DNS_UDP_TCP_indicator>(TCP|UDP))\s{1,2}(?<DNS_Send_Receive_indicator>(Snd|Rcv))\s{1}(?<DNS_Remote_IP>(::1|127.0.0.1|\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}))\s+(?<DNS_Xid_hex>\w{4})\s{1}(?<DNS_Query_Response>(R| ))\s{1}(?<DNS_Opcode>\w{1})\s{1}\[(?<DNS_Flags_hex>\w{4})\s(?<DNS_Flags_char_codes>.*?)(?<DNS_ResponseCode>\w+)]\s{1}(?<DNS_Question_Type>\w+)\s+(?<DNS_Question_Name>.*?)\r\n((?ms).*?\s{4}QUESTION SECTION:\r\n(?<QUESTION_SECTION>.*?)\r\n\s{4}ANSWER SECTION:\r\n(?<ANSWER_SECTION>.*?)\s{4}AUTHORITY SECTION:\r\n(?<AUTHORITY_SECTION>.*?)\s{4}ADDITIONAL SECTION:\r\n(?<ADDITIONAL_SECTION>.*?)\r\n\r\n)?'

            $ALL_DNS_DATA_match = $ALL_DNS_DATA_regex.Match($ALL_DNS_DATA)

            while ($ALL_DNS_DATA_match.Success) {               

                $DNS_Question_Name=((($ALL_DNS_DATA_match.Groups['DNS_Question_Name'].Value) -replace "`\(\d+`\)","." -replace "^.","").trim(".")).TRIM()

               #################################################
                      
                if ($ALL_DNS_DATA_match.Groups['ANSWER_SECTION'].Value) {
                    ForEach ($dns_row in $($ALL_DNS_DATA_match.Groups['ANSWER_SECTION'].Value -split "`r`n")) {
                        if ($dns_row -like "      DATA *") {
                            $DNS_DATA_TEMP=$($dns_row -split "\s+",3)[2].Trim()
                                
                            $DNS_DATA_TEMP=$DNS_DATA_TEMP -replace "`\[\w+`\]",""
                            $DNS_DATA_TEMP=((($DNS_DATA_TEMP) -replace "`\(\d+`\)",".").trim(".")).TRIM()

                            $DNS_DATA_TEMP=$DNS_DATA_TEMP -replace "\s+Offset = 0x\w{4}, RR count = \d{1,3}",""

                            if (-Not ([string]::IsNullOrWhiteSpace($DNS_DATA_TEMP))){
                                if ($DNS_DATA) {
                                        $DNS_DATA+="`n"+$DNS_DATA_TEMP
                                } else {
                                    $DNS_DATA+=$DNS_DATA_TEMP
                                }
                            }
                        } elseif ($dns_row -eq "      empty") {
                            $DNS_DATA="empty"
                        }
                        $DNS_DATA_TEMP=$null
                    }
                }
                #################################################
                $DNS_Unicode_Question_Name=ConvertTo-UnicodeDNSName -Domain $DNS_Question_Name
                if ($debugmode -eq "yes") {
                    $DNSLogObject = New-Object PsObject -Property ([ordered]@{
                        DNS_DateTime=$ALL_DNS_DATA_match.Groups['DNS_DateTime'].Value
                        DNS_ThreadID=$ALL_DNS_DATA_match.Groups['DNS_ThreadID'].Value
                        DNS_Context=$ALL_DNS_DATA_match.Groups['DNS_Context'].Value
                        DNS_Internal_packet_identifier=$ALL_DNS_DATA_match.Groups['DNS_Internal_packet_identifier'].Value
                        DNS_UDP_TCP_indicator=$ALL_DNS_DATA_match.Groups['DNS_UDP_TCP_indicator'].Value
                        DNS_Send_Receive_indicator=$ALL_DNS_DATA_match.Groups['DNS_Send_Receive_indicator'].Value
                        DNS_Remote_IP=$ALL_DNS_DATA_match.Groups['DNS_Remote_IP'].Value
                        DNS_Xid_hex=$ALL_DNS_DATA_match.Groups['DNS_Xid_hex'].Value
                        DNS_Query_Response=$ALL_DNS_DATA_match.Groups['DNS_Query_Response'].Value
                        DNS_Opcode=$ALL_DNS_DATA_match.Groups['DNS_Opcode'].Value
                        DNS_Flags_hex=$ALL_DNS_DATA_match.Groups['DNS_Flags_hex'].Value
                        DNS_Flags_char_codes=$ALL_DNS_DATA_match.Groups['DNS_Flags_char_codes'].Value
                        DNS_ResponseCode=$ALL_DNS_DATA_match.Groups['DNS_ResponseCode'].Value
                        DNS_Question_Type=$ALL_DNS_DATA_match.Groups['DNS_Question_Type'].Value                                                 
                        DNS_Question_Name=$DNS_Question_Name
                        DNS_Unicode_Question_Name=$DNS_Unicode_Question_Name
                        DNS_DATA=$ALL_DNS_DATA_match.Groups['DNS_DATA'].Value
                    })
                } else {
                    $DNSLogObject = New-Object PsObject -Property ([ordered]@{
                        DNS_DateTime=$ALL_DNS_DATA_match.Groups['DNS_DateTime'].Value
                        DNS_Remote_IP=$ALL_DNS_DATA_match.Groups['DNS_Remote_IP'].Value
                        DNS_ResponseCode=$ALL_DNS_DATA_match.Groups['DNS_ResponseCode'].Value
                        DNS_Question_Type=$ALL_DNS_DATA_match.Groups['DNS_Question_Type'].Value                                       
                        DNS_Question_Name=$DNS_Question_Name
                        DNS_Unicode_Question_Name=$DNS_Unicode_Question_Name
                        DNS_DATA=$DNS_DATA
                    })
                }

                if ($DNSLogObject) {
                    $AllObjectsArray += $DNSLogObject
                }
                
                $DNS_DATA=$null
                $DNSLogObject=$null
                $DNS_Question_Name=$null
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

function ConvertTo-UnicodeDNSName {
    [CmdletBinding()]
    param (
        # Domain name
        [Parameter(Mandatory = $true)]
        [String]
        $Domain
    )
    process {
        $Idn = New-Object System.Globalization.IdnMapping
        $Idn.GetUnicode("$Domain")
    }
}