$num = Read-Host 'Enter Port to Block'
Try{
    netsh advfirewall firewall add rule name="Blocktcp + $num" protocol=TCP dir=in localport = $num action=block
    netsh advfirewall firewall add rule name="Blockudp + $num" protocol=TCP dir=out localport = $num action=block
    #echo $num
    }
    Catch{
        	echo "Blocking failed" 
	}
