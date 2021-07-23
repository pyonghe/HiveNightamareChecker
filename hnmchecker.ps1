write-host("`n====Checking if System is vulnerable to CVE-2021-36934====") -ForegroundColor Green
$result = @((Get-Item -LiteralPath C:\windows\System32\config\SAM).GetAccessControl().AccessToString)
$result2 = @((Get-Item -LiteralPath C:\windows\System32\config\SYSTEM).GetAccessControl().AccessToString)
$result3 = @((Get-Item -LiteralPath C:\windows\System32\config\SECURITY).GetAccessControl().AccessToString)


if ($result -like "*BUILTIN\Users Allow*"){
	
	write-host("`nMisconfiguration") -ForegroundColor red -NoNewline; Write-host(" in SAM file")
	if ($result -like "*BUILTIN\Users Allow*"){
		write-host("Misconfiguration") -ForegroundColor red -NoNewline; Write-host(" in SYSTEM file")
		if ($result -like "*BUILTIN\Users Allow*"){
			write-host("Misconfiguration") -ForegroundColor red -NoNewline; Write-host(" in SECURITY file")
			$enable = Read-Host -Prompt "`nDo you want to change the permission of the files? [Y] [N]"
			if ($enable -like "Y"){
				write-host("Changing the permission of the files to disable read access for BUILTIN\Users")
				icacls C:\Windows\system32\config\*.* /inheritance:e
				write-host("Done!") -ForegroundColor Green -NoNewline;
				# Check for shadowdrives 
				write-host("`nChecking for shadow copies prior to permission changed ...")
				$shdresult = @(vssadmin list shadows)
				if ($shdresult -like "*shadow copies*"){
					$delete = Read-Host -Prompt "`nYour system contains shadow copies prior to updating the file permission. Do you want to delete the shadow copies? [Y] [N]"
					if ($delete -like "Y"){
						# delete shadow copies 
						vssadmin delete shadows /for=c:
						write-host("`nSystem is ") -ForegroundColor white -NoNewline; write-host("not vulnerable") -ForegroundColor Green -NoNewline; Write-host(" to CVE-2021-36934") -ForegroundColor white -NoNewline;
						$create = Read-Host -Prompt "`n[Optional] Create a new restore point? [Y] [N]"
						if ($create -like "Y"){
							Checkpoint-Computer -Description "New Restorepoint for CVE-2021-36934" -RestorePointType MODIFY_SETTINGS
							write-host("`nDone") -ForegroundColor Green -NoNewline; Write-host(" creating restore point and mitigating CVE-2021-36943!")
						}
					}else {
						write-host("`nYour system is ") -ForegroundColor white -NoNewline; Write-host("vulnerable!") -ForegroundColor Red -NoNewline; Write-host(" Please delete the shadow copies!") -ForegroundColor white -NoNewline;
					}
				}else{
					write-host("`nSystem is ") -ForegroundColor white -NoNewline; write-host("not vulnerable") -ForegroundColor Green -NoNewline; Write-host(" to CVE-2021-36934") -ForegroundColor white -NoNewline;
				}
			}else{
				write-host("`nYour system is ") -ForegroundColor white -NoNewline; Write-host("vulnerable!") -ForegroundColor Red -NoNewline; Write-host(" Please change the permission of the files!") -ForegroundColor white -NoNewline;
				
				
			}
		}
	}	

}else {
	write-host("File permission for SAM, SYSTEM, SECURITY is correct`nPrcoeeding to check shadow copies....")
	$shdresult = @(vssadmin list shadows)
	if ($shdresult -like "*shadow copies*"){
		$delete = Read-Host -Prompt "`nYour system contains shadow copies. You could have created a restore point before changing the permission of SAM, SECURITY, SYSTEM files. Do you want to delete the shadow copies and create a new restore point? [Y] [N]"
		if ($delete -like "Y"){
			# delete shadow copies 
			vssadmin delete shadows /for=c:
			# Create new restore point
			Checkpoint-Computer -Description "New Restorepoint for CVE-2021-36934" -RestorePointType MODIFY_SETTINGS
			write-host("`nDone") -ForegroundColor Green -NoNewline; Write-host(" creating restore point and mitigating CVE-2021-36943!")
			write-host("`nSystem is ") -ForegroundColor white -NoNewline; write-host("not vulnerable") -ForegroundColor Green -NoNewline; Write-host(" to CVE-2021-36934") -ForegroundColor white -NoNewline;
			
		}else {
			write-host("`nYour system ") -ForegroundColor white -NoNewline; Write-host("might be vulnerable!") -ForegroundColor Red -NoNewline; Write-host(" Please ensure the shadow copies are created after tightening the acl of the affected files!") -ForegroundColor white -NoNewline;
		}
	} else {
	  write-host("`nNo shadow Copies found. System is ") -ForegroundColor white -NoNewline; write-host("not vulnerable") -ForegroundColor Green -NoNewline; Write-host(" to CVE-2021-36934`n") -ForegroundColor white
	}
}
