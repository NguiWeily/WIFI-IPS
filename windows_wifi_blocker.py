import os
import re
import subprocess
import ctypes
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.scrollview import ScrollView
from kivy.uix.gridlayout import GridLayout

# Function to check if the script is running with administrator privileges
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

# Function to scan for WiFi networks using 'netsh wlan show networks'
def scan_wifi():
    try:
        result = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception("Error running netsh command. Ensure WiFi is enabled.")

        networks = []
        ssid, bssid = None, None
        for line in result.stdout.splitlines():
            line = line.strip()
            ssid_match = re.match(r"^SSID\s\d+\s*:\s(.+)$", line)
            bssid_match = re.match(r"^BSSID\s\d+\s*:\s(.+)$", line)
            signal_match = re.match(r"^Signal\s*:\s(.+)%", line)
            
            if ssid_match:
                ssid = ssid_match.group(1)
            if bssid_match:
                bssid = bssid_match.group(1)
            if signal_match and ssid and bssid:
                networks.append({
                    "SSID": ssid,
                    "BSSID": bssid,
                    "Signal": signal_match.group(1),
                })
                ssid, bssid = None, None  # Reset for next network
        return networks
    except Exception as e:
        print(f"[!] Error scanning WiFi: {e}")
        return []

# Function to block a network by adding a Windows Firewall rule
def block_rogue_network(bssid, ip_range="192.168.0.0/24"):
    try:
        print(f"[*] Blocking network with BSSID: {bssid}")
        rule_name = f"Block_Rogue_{bssid}"
        command = f'New-NetFirewallRule -DisplayName "{rule_name}" -Direction Inbound -RemoteAddress "{ip_range}" -Action Block'
        subprocess.run(["powershell", "-Command", command], check=True)
        print(f"[+] Network {bssid} with IP range {ip_range} has been blocked successfully.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to block network: {e}")
    except Exception as e:
        print(f"[!] Error: {e}")

# Kivy GUI for WiFi Blocker
class WifiBlockerApp(App):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.networks = []

    def build(self):
        self.title = "WiFi Rogue Network Blocker (Windows)"

        # Root layout
        self.layout = BoxLayout(orientation='vertical', padding=10, spacing=10)

        # Title Label
        self.layout.add_widget(Label(text="WiFi Rogue Network Blocker", font_size=20, bold=True, halign="center", size_hint=(1, 0.1)))

        # Scan Button
        self.scan_button = Button(text="Scan for WiFi Networks", size_hint=(1, 0.1))
        self.scan_button.bind(on_press=self.scan_and_display)
        self.layout.add_widget(self.scan_button)

        # Scrollable area for network list
        self.scroll_view = ScrollView(size_hint=(1, 1))
        self.network_list = GridLayout(cols=1, size_hint_y=None)
        self.network_list.bind(minimum_height=self.network_list.setter('height'))
        self.scroll_view.add_widget(self.network_list)
        self.layout.add_widget(self.scroll_view)

        return self.layout

    def scan_and_display(self, instance):
        print("[*] Scan button clicked.")

        # Clear the previous list
        self.network_list.clear_widgets()

        # Check for admin privileges
        if not is_admin():
            self.network_list.add_widget(Label(text="[ERROR] Run the script as Administrator!", color=(1, 0, 0, 1), size_hint_y=None, height=30))
            return

        # Perform WiFi scan
        self.networks = scan_wifi()
        if not self.networks:
            self.network_list.add_widget(Label(text="No WiFi networks found or WiFi is disabled.", size_hint_y=None, height=30))
            return

        # Display scanned networks
        for network in self.networks:
            ssid = network.get("SSID", "Unknown")
            bssid = network.get("BSSID", "Unknown")
            signal = network.get("Signal", "N/A")
            label_text = f"{ssid} ({bssid}) - Signal: {signal}%"

            # Check if the network meets rogue criteria
            if "FreeWiFi" in ssid or int(signal) < 30:  # Example criteria
                block_rogue_network(bssid)
                label_text += " [BLOCKED]"

            # Add a button to manually block networks
            network_row = BoxLayout(orientation='horizontal', size_hint_y=None, height=40)
            network_row.add_widget(Label(text=label_text, halign="left", valign="middle"))
            block_button = Button(text="Block", size_hint_x=0.3)
            block_button.bind(on_press=lambda instance, bssid=bssid: self.manual_block(bssid))
            network_row.add_widget(block_button)
            self.network_list.add_widget(network_row)

    def manual_block(self, bssid):
        print(f"[*] Manually blocking network with BSSID: {bssid}")
        block_rogue_network(bssid)
        self.network_list.add_widget(Label(text=f"Manually blocked {bssid}", size_hint_y=None, height=30, color=(0, 1, 0, 1)))

# Run the App
if __name__ == "__main__":
    if not is_admin():
        print("[!] Please run this script as Administrator for full functionality.")
    WifiBlockerApp().run()
