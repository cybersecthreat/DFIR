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
    When a DNS log is converted with this cmdlet it will be turned into objects for further parsing.

    .EXAMPLE 1
    PS C:\> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -force
    PS C:\> . .\windows_dns_analytical_log_parser.ps1
    PS C:\> Get-ParsedDNSAnalyticalLog -DNSLogFile ".\dns.log" -debugmode "no"

        DNS_DateTime      : 7/17/2020 3:21:52 PM
        DNS_Remote_IP     : ::1
        DNS_ResponseCode  : NOERROR
        DNS_Question_Type : A
        DNS_Question_Name : www.google.com.hk
        DNS_DATA          : 172.217.24.67

    .EXAMPLE 2
    PS C:\> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -force
    PS C:\> . .\windows_dns_analytical_log_parser
    PS C:\> Get-ParsedDNSAnalyticalLog -DNSLogFile ".\dns5.log" -debugmode "no" | Where-Object DNS_Question_Name -like *msedge.api.cdp.microsoft.com* | Format-Table -Property * -Autosize | Out-String -Width 192

        DNS_DateTime         DNS_Remote_IP DNS_ResponseCode DNS_Question_Type DNS_Question_Name            DNS_DATA                                                                           
          
        ------------         ------------- ---------------- ----------------- -----------------            --------   
        7/17/2020 3:06:15 PM ::1           NOERROR          A                 msedge.api.cdp.microsoft.com api.cdp.microsoft.com....                                                          
          
        7/17/2020 3:06:15 PM 127.0.0.1     NOERROR          A                 msedge.api.cdp.microsoft.com api.cdp.microsoft.com....         

    .EXAMPLE 3
    PS C:\> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -force
    PS C:\> . .\windows_dns_analytical_log_parser.ps1
    PS C:\> Get-ParsedDNSAnalyticalLog -DNSLogFile ".\dns5.log" -debugmode "no" | Where-Object DNS_Question_Name -like *msedge.api.cdp.microsoft.com* | export-csv -Path C:\dns.csv
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
            . .\DNS-Lib.ps1
            #empty array
            $AllObjectsArray = @()
            
            $ALL_DNS_DATA = (Get-Content $DNSLogFile -raw) -split '\r\n\r\n'
            $ALL_DNS_DATA | foreach {
               $data = $_ | Select-String -Pattern '^Event\[\d+\]:'
                  
               $NextLineIsDescription=0
               ForEach ($dns_row in $($data -split "`r`n"))
                {
                       
                   if ($NextLineIsDescription -eq 1) {

                        $DNS_DATA_TYPE=$dns_row.split(':',2)[0].TRIM()
                        Add-Member -in $DNSLogObject NoteProperty 'DNS_DATA_TYPE' $DNS_DATA_TYPE

                        $regex = [regex] '(?<name>\w*)=(?<value>.*?)(; |$)'
                        $match = $regex.Match($dns_row.split(':',2)[1].TRIM())
                        while ($match.Success) {
                            #[PSCustomObject]@{
                            #    Name = $match.Groups['name'].Value
                            #    Value = $match.Groups['value'].Value
                            #}
                            if ($match.Groups['name'].Value -eq "PacketData") {
                                    $PacketData_temp=$match.Groups['value'].Value.Substring(2);
                                    $DNSPacketData = [DNSPacket]::new();
                                    $PacketData_temp_ByteArray=Convert-HexStringToByteArray($PacketData_temp);
                                    $DNSPacketData.AddData($PacketData_temp_ByteArray);
                                    $DNSPacketData.AnswerRecords |% {
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
                                    Add-Member -in $DNSLogObject NoteProperty 'RDATA_decoded' $RDATA_decoded
                                    $PacketData_temp=""
                                    $PacketData_temp_ByteArray=""
                                    $RDATA_decoded=""
                            }
                            Add-Member -in $DNSLogObject NoteProperty $match.Groups['name'].Value $match.Groups['value'].Value
                            $match = $match.NextMatch()
                        }
                        $NextLineIsDescription=0
                   } elseif ($dns_row -like "  Date: *"){
                        $DNS_DATETIME=$dns_row.split(':',2)[1].trim()
                        Add-Member -in $DNSLogObject NoteProperty 'DNS_DATETIME' $DNS_DATETIME
                   } elseif ($dns_row -like "  Computer: *"){
                        $DNS_Computer=$dns_row.split(':',2)[1].trim()
                        Add-Member -in $DNSLogObject NoteProperty 'DNS_Computer' $DNS_Computer
                   } elseif ($dns_row -like "  Description: *"){
                        $NextLineIsDescription=1
                   } elseif ($dns_row -match "^Event\[\d+\]:") {
                        $DNSLogObject = New-Object PSObject
                   }
                }
    
                #write-host $DNS_DATA
                if ($DNSLogObject -and $DNS_DATA) {
                    Add-Member -in $DNSLogObject NoteProperty 'DNS_DATA' $DNS_DATA
                }
                $AllObjectsArray += $DNSLogObject
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
