$ous = Get-ADOrganizationalUnit -Filter 'Name -like "*"' 
foreach ($ou in $ous)
{
    $ou_block_inheritance=Get-GPInheritance -Target $ou.DistinguishedName | where {$_.GpoInheritanceBlocked -eq "Yes"}
    $ou_block_inheritance.Name
}