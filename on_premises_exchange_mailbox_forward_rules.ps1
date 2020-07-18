Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn;

$LogTime = Get-Date -Format "MM-dd-yyyy_hh-mm-ss"

$domains = Get-AcceptedDomain
$mailboxes = Get-Mailbox -ResultSize Unlimited
 
foreach ($mailbox in $mailboxes) {
 
    $forwardingRules = $null
    #Write-Host "Checking rules for $($mailbox.displayname) - $($mailbox.primarysmtpaddress)" -foregroundColor Green
    $rules = get-inboxrule -Mailbox $mailbox.UserPrincipalName -IncludeHidden
     
    $forwardingRules = $rules | Where-Object {$_.RedirectTo -or $_.ForwardTo -or $_.ForwardAsAttachmentTo}
 
    foreach ($rule in $forwardingRules) {
        $recipients = @()
        if ($rule.ForwardTo) {
            $recipients += $rule.ForwardTo | Where-Object {$_ -match "SMTP"}
        }
        if ($rule.ForwardAsAttachmentTo) {
            $recipients += $rule.ForwardAsAttachmentTo | Where-Object {$_ -match "SMTP"}
        }
        if ($rule.RedirectTo) {            
            $recipients += $rule.RedirectTo | Where-Object {$_ -match "SMTP"}
        }
     
        $externalRecipients = @()
 
        foreach ($recipient in $recipients) {
            $email = ($recipient -split "SMTP:")[1].Trim("]")
            $domain = ($email -split "@")[1]
    
            if ($domains.DomainName -notcontains $domain) {
                $externalRecipients += $email
            }
        }
 
        if ($externalRecipients) {
            $extRecString = $externalRecipients -join "; "
            #Write-Host "User: $($mailbox.SamAccountName) Rule: $($rule.Name) forwards to $extRecString" -ForegroundColor Yellow
 
            $ruleHash = $null
            $ruleHash = [ordered]@{
                SamAccountName         = $mailbox.SamAccountName
                UserPrincipalName      = $mailbox.UserPrincipalName
                PrimarySmtpAddress     = $mailbox.PrimarySmtpAddress
                RuleId                 = $rule.Identity
		RuleEnabled            = $rule.Enabled
                RuleName               = $rule.Name
                ExternalRecipients     = $extRecString
                RedirectTo             = $rule.RedirectTo -join ';'
                ForwardTo              = $rule.ForwardTo -join ';'
                ForwardAsAttachmentTo  = $rule.ForwardAsAttachmentTo -join ';'
                RuleDescription        = $rule.Description
            }
            $ruleObject = New-Object PSObject -Property $ruleHash
            $ruleObject | Export-CSV D:\Splunk\ForwardRule_$LogTime.csv -NoTypeInformation -Append
        }
    }
}