$logpath = "C:\QNS\TASKS\W10Upgrades\LOGS"
$logfile = "Log.txt"
$DistrictID = "GF4"
$NetworkID = "GF4HS" + "*"
$BeginHour = "18:00:00"
$CutOffHour = "2:00:00"

$Date = @()
$Date += New-Object PSCustomObject -Property @{
                day = (get-date).day
                tomorrow = ((get-date).adddays(1)).day
                month = (get-date).month
                year = (get-date).year
            }
$day = (get-date).day
$tomorrow = ((get-date).adddays(1)).day
$month = (get-date).month
$year = (get-date).year

$StartTime = ($Date.month).ToString() + '/' + ($Date.day).ToString() + '/' + ($Date.year).ToString() + ' ' + $BeginHour
$CutOffTime = ($Date.month).ToString() + '/' + ($Date.tomorrow).ToString() + '/' + ($Date.year).ToString() + ' ' + $CutOffHour

Function Send-MagicPacket ($computer, $mac){
    if (Test-Connection -CN $computer -Count 1 -ErrorAction SilentlyContinue){ 
		if (-Not $mac){$mac = ($dhcp_list | where-object {$_.HostName -like $computer + "*"}).ClientId}
        Write-Host "$computer : $Mac" -ForegroundColor Green
    }else{
        if (-Not $mac){$mac = ($dhcp_list | where-object {$_.HostName -like $computer + "*"}).ClientId}
        if ($mac) {
            $MacByteArray = $Mac -split "[:-]" | ForEach-Object { [Byte] "0x$_"}
            [Byte[]] $Magicpacket = (,0xFF * 6) + ($MacByteArray * 16)
            $UdpClient = New-Object System.Net.Sockets.UdpClient
            $UdpClient.Connect(([System.Net.IPAddress]::Broadcast),7)
            $UdpClient.Send($MagicPacket,$MagicPacket.Length) | Out-Null
            $UdpClient.Close()
            Clear-Variable -name mac
        }
    }
}
$functions = { #All of the functions need to be a variable so they can be called by the job and -InitializationScript
    Function Upgrade-ToWindows10 ($computer){
        $logpath = "C:\QNS\TASKS\W10Upgrades"
        $logfile = "Log.txt"
        $now = Get-Date
        echo "$now - Starting upgrade procedure for  $computer" | add-content $logpath\$logfile, $logpath\$computer.txt
        #Reboot if necessary
        $uptime = Get-WmiObject win32_operatingsystem -ComputerName $computer| select csname, @{LABEL='LastBootUpTime';EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}}
        $starttime = Get-Date -Format "M/d/yyyy 18:00:00"

        if($uptime.LastBootUpTime -lt $starttime){
            $now = Get-Date
            echo "$now - Rebooting $computer" | add-content C:\temp\upgradelog.txt
            Restart-Computer -ComputerName $computer -Force
            shutdown -r -m \\$computer -f -t 0
        }
        $now = Get-Date
        echo "$now - Waiting 5 minutes for $computer to reboot" | add-content $logpath\$logfile, $logpath\$computer.txt
        start-sleep -seconds 300
    
        #Run OCS
        $now = Get-Date
        echo "$now - Running OCS on $computer" | add-content $logpath\$logfile, $logpath\$computer.txt
        & \\server1\update$\QNSSYNC2\INCOMING\SERVERS\C_QNS\DEPLOY\PSEXEC\psexec.exe \\$computer -accepteula -s -n 2 "\\server1\netlogon\newocs.bat"
        
        $now = Get-Date
        echo "$now - Waiting 5 minutes for $computer" | add-content $logpath\$logfile, $logpath\$computer.txt
        start-sleep -seconds 300

        #Fire off upgrade scripts
        $now = Get-Date
        echo "$now - Starting upgrade script on $computer" | add-content $logpath\$logfile, $logpath\$computer.txt
        & \\server1\update$\QNSSYNC2\INCOMING\SERVERS\C_QNS\DEPLOY\PSEXEC\psexec.exe \\$computer -accepteula -s -n 2 "\\server1\install$\SCHOOL\WIN10_X64_1909\upgrade2.bat"
    }
}

New-Item -Path $logpath\..\ -Name "LOGS" -ItemType "directory" -ErrorVariable capturedErrors -ErrorAction SilentlyContinue
get-job | Stop-Job
get-job | remove-job
remove-item $logpath\*.txt
clear
echo "Getting workstation list from AD" | add-content $logpath\$logfile
Write-Host "Getting workstation list from AD"
$host_list = Get-ADComputer -Filter {Name -like $NetworkID -and Name -notlike "*OFC*" -and Name -notlike "*CAF*" -and OperatingSystemVersion -like "10.0*" -and OperatingSystemVersion -notlike "10.0 (18363)" -and OperatingSystem -like "Windows 10*"} -Properties *
$dhcp_list = Get-DhcpServerv4Scope | Get-DhcpServerv4Lease

echo "Checking alive computers & sending magic packet to off computers" | add-content $logpath\$logfile
Write-Host "Checking alive computers & sending magic packet to off computers"
$computer_list = @()
$computer_off = @()
foreach ($computer in $host_list.Name) {
    $mac = ($dhcp_list | where-object {$_.HostName -like $computer + "*"}).ClientId
    if (Test-Connection -CN $computer -Count 1 -ErrorAction SilentlyContinue){
		if ($computer) {
            Write-Host "$computer : $Mac is Alive!" -ForegroundColor Green
            echo "$computer : $mac is Alive!" | add-content $logpath\$logfile, $logpath\$computer.txt
            $computer_list += New-Object PSCustomObject -Property @{
                Name = $computer
            }
        } 
	}else{
		if ($computer) {
            if ($mac){
                write-host "$computer : $Mac is Dead!" -ForegroundColor Red
                echo "$computer : $mac is not responsive to pings" | add-content $logpath\$logfile, $logpath\$computer.txt
                echo "Sending Magic Packet to $computer" | add-content $logpath\$logfile, $logpath\$computer.txt
                $computer_off += New-Object PSCustomObject -Property @{
                    Name = $computer
                }
            }
            if (-not $mac){
                write-host "$computer : NODHCP is Dead!" -ForegroundColor Red
                echo "$computer : NODHCP is not responsive to pings" | add-content $logpath\$logfile, $logpath\$computer.txt
                echo "Sending Magic Packet to $computer" | add-content $logpath\$logfile, $logpath\$computer.txt
                $computer_off += New-Object PSCustomObject -Property @{
                    Name = $computer
                }
            }
        }
#        echo "Attempting to wake up the following pcs" | add-content $logpath\$logfile
        <#Send-MagicPacket -computer $computer
        Send-MagicPacket -computer $computer
        Send-MagicPacket -computer $computer#>
        Send-MagicPacket -computer $computer
	}
}
echo "Alive Pcs" | add-content $logpath\$logfile
write-host "Alive Pcs"
echo $computer_list.name | add-content $logpath\$logfile
write-host $computer_list.name -ForegroundColor Green
Write-Host "Waiting 2 minutes for other computers (if any) to boot"
echo "Waiting 2 minutes for other computers (if any) to boot" | add-content $logpath\$logfile
start-sleep -seconds 120

#Add previously off computers to the on-computers list
foreach ($computer in $computer_off.Name) {
    if (Test-Connection -CN $computer -Count 1 -ErrorAction SilentlyContinue){
		Write-Host "$computer is NOW Alive!" -ForegroundColor Green
        echo "$computer is NOW Alive!" | add-content $logpath\$logfile, $logpath\$computer.txt
        if ($computer) {
            $computer_list += New-Object PSCustomObject -Property @{
                Name = $computer
            }
        } 
	}
}

$MaxComputers = 15
echo "Starting W10 Upgrades on a maximum of $maxcomputers machines at a time" | add-content $logpath\$logfile
if ($MaxComputers -gt ($computer_list.Name).Count){$MaxComputers = $computer_list.Count}
#Initialize List with $MaxComputers of computers
for ($n = 1; $n -le $MaxComputers; $n++){
    if($computer_list.Count -eq 1){
        $pc = $computer_list.Name
    }else{
        $pc = $computer_list.Name[$n-1]
    }
    Start-Job -name $pc -InitializationScript $functions -Arg @($pc) -ScriptBlock { #The -InitializationScript calls the function to be loaded into the job session
        param($pc)
        Upgrade-ToWindows10 -computer $pc
    }
}

#Keep a watch for any jobs that have completed
while ($n-1 -lt ($computer_list.Name).Count ) {
    Clear
    get-job
    start-sleep 5
    while ((Get-Job | ?{$_.State -eq 'Running'}).Count -lt $MaxComputers) {
        $now = Get-Date -Format "M/d/yyyy HH:mm:ss"
        if ($now -lt $cutofftime) {
            if($computer_list.Count -eq 1){
                $pc = $computer_list.Name
            }else{
                $pc = $computer_list.Name[$n-1]
            }
            Start-Job -name $pc -InitializationScript $functions -Args @($pc) -ScriptBlock {
                param($pc)
                 Upgrade-ToWindows10 -computer $pc `
                 -Verbose 4>&1
            }
            $n++
        }
    }
}

while ((Get-job).state -match "Running"){
    clear
    Get-Job | FT Name, ID, PSBeginTime, PSEndTime, State
    start-sleep 5
}

$jobs = (Get-Job).ID
foreach ($job in $jobs){
    echo "********************** Job $job **********************" | Add-Content $logpath\Job_$job.txt
    Receive-job -id $job -ErrorVariable RemoteErr -OutVariable output
    $RemoteErr | Add-Content $logpath\Job_$job.txt
}
