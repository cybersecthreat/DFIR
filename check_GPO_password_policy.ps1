$dest_nt_domain="mydomain.local"
dir \\$dest_nt_domain\sysvol\$dest_nt_domain -I *.inf -R | Select-String MaximumPasswordAge
dir \\$dest_nt_domain\sysvol\$dest_nt_domain -I *.inf -R | Select-String MinimumPasswordLength
dir \\$dest_nt_domain\sysvol\$dest_nt_domain -I *.inf -R | Select-String PasswordComplexity
dir \\$dest_nt_domain\sysvol\$dest_nt_domain -I *.inf -R | Select-String PasswordHistorySize
dir \\$dest_nt_domain\sysvol\$dest_nt_domain -I *.inf -R | Select-String LockoutBadCount
dir \\$dest_nt_domain\sysvol\$dest_nt_domain -I *.inf -R | Select-String ResetLockoutCount
dir \\$dest_nt_domain\sysvol\$dest_nt_domain -I *.inf -R | Select-String LockoutDuration
dir \\$dest_nt_domain\sysvol\$dest_nt_domain -I *.inf -R | Select-String RequireLogonToChangePassword
dir \\$dest_nt_domain\sysvol\$dest_nt_domain -I *.inf -R | Select-String ForceLogoffWhenHourExpire
dir \\$dest_nt_domain\sysvol\$dest_nt_domain -I *.inf -R | Select-String ClearTextPassword

$gpo_folders = Get-ChildItem -Path \\$dest_nt_domain\sysvol\$dest_nt_domain\Policies\* | where { $_.PSIsContainer}
foreach ($gpo_folder in $gpo_folders)
{
    Select-String -Path "$gpo_folder\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf" -pattern MaximumPasswordAge
    Select-String -Path "$gpo_folder\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf" -pattern MinimumPasswordLength
    Select-String -Path "$gpo_folder\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf" -pattern PasswordComplexity
    Select-String -Path "$gpo_folder\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf" -pattern PasswordHistorySize
    Select-String -Path "$gpo_folder\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf" -pattern LockoutBadCount
    Select-String -Path "$gpo_folder\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf" -pattern ResetLockoutCount
    Select-String -Path "$gpo_folder\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf" -pattern LockoutDuration
    Select-String -Path "$gpo_folder\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf" -pattern RequireLogonToChangePassword
    Select-String -Path "$gpo_folder\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf" -pattern ForceLogoffWhenHourExpire
    Select-String -Path "$gpo_folder\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf" -pattern ClearTextPassword    
}