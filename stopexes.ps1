$tasklist = tasklist.exe
$tasklist = $tasklist.Split(" ") 
$truetaskList =  @()

ForEach($task in $tasklist){
    if ($task -match '.exe' -and -Not($truetaskList.Contains($task)) -and -Not($task -match 'powershell')){
        $truetaskList += $task
    }
}


ForEach($task in $truetaskList){
    Try{
            $truetask = $task.Substring(0,$task.Length-4)
            Stop-Process -Name $truetask 
    }
    Catch{
   continue 
    }
}
