$Accounts =  Get-WmiObject -Class Win32_UserAccount -filter "LocalAccount = True"
$ListUsers = @()
$currentuser = $env:USERNAME
$Accounts = $Accounts -split ' '

ForEach($account in $Accounts){
         $stringAccount = [string]$account -split '"'
         for($i = 0; $i -lt $stringAccount.Count; $i+=1){
             if ($i -eq 3){
             $user = $stringAccount[$i]
             $ListUsers += $user
             }
         }
}

ForEach($user in $ListUsers){
      if (-not($username -eq $currentuser)){
            Try{
                Disable-LocalUser -Name $username
            }
            Catch{
                continue
            }
        }
}