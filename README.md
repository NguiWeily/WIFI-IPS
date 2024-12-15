open cmd with administrator privilege

install notepad
install python 3.12.8

pip install kivy

idle windows_wifi_blocker.py

python windows_wifi_blocker.py

open powershell with administrator privilege

Get-NetFirewallRule | Where-Object DisplayName -Like "Block_Rogue*" | Remove-NetFirewallRule

Get-NetFirewallRule | Where-Object DisplayName -Like "Block_Rogue*"
