import os  # For interacting with the operating system
import re  # For using regular expressions to parse text
import subprocess  # For running shell commands and capturing their output
import ctypes  # For checking administrative privileges
from kivy.app import App  # Kivy framework for building applications
from kivy.uix.boxlayout import BoxLayout  # Layout widget for organizing UI elements
from kivy.uix.label import Label  # Label widget for displaying text
from kivy.uix.button import Button  # Button widget for user interactions
from kivy.uix.scrollview import ScrollView  # Scrollable container for content
from kivy.uix.gridlayout import GridLayout  # Grid layout for displaying content in a grid

# Function to check if the script is running with administrator privileges
def is_admin():
    try:
        # Call Windows API to check if the user is an administrator
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        # Return False if there is an error (e.g., non-Windows systems)
        return False

# Function to scan for WiFi networks using 'netsh wlan show networks'
def scan_wifi():
    try:
        # Run the 'netsh' command to display available WiFi networks
        result = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True, text=True)
        if result.returncode != 0:
            # Raise an error if the command fails
            raise Exception("Error running netsh command. Ensure WiFi is enabled.")

        networks = []  # List to store parsed WiFi networks
        ssid, bssid = None, None  # Initialize variables for SSID and BSSID
        for line in result.stdout.splitlines():  # Loop through each line of the output
            line = line.strip()  # Remove leading/trailing whitespace
            # Match SSID lines using regex
            ssid_match = re.match(r"^SSID\s\d+\s*:\s(.+)$", line)
            # Match BSSID lines using regex
            bssid_match = re.match(r"^BSSID\s\d+\s*:\s(.+)$", line)
            # Match Signal strength lines using regex
            signal_match = re.match(r"^Signal\s*:\s(.+)%", line)

            if ssid_match:
                ssid = ssid_match.group(1)  # Extract the SSID
            if bssid_match:
                bssid = bssid_match.group(1)  # Extract the BSSID
            if signal_match and ssid and bssid:
                # Add the network to the list if all details are available
                networks.append({
                    "SSID": ssid,
                    "BSSID": bssid,
                    "Signal": signal_match.group(1),
                })
                ssid, bssid = None, None  # Reset variables for the next network
        return networks  # Return the list of networks
    except Exception as e:
        print(f"[!] Error scanning WiFi: {e}")  # Log any errors
        return []  # Return an empty list in case of error

# Function to block a network by adding a Windows Firewall rule
def block_rogue_network(bssid, ip_range="192.168.0.0/24"):
    try:
        print(f"[*] Blocking network with BSSID: {bssid}")  # Log the blocking action
        # Create a rule name based on the BSSID
        rule_name = f"Block_Rogue_{bssid}"
        # PowerShell command to add a firewall rule
        command = f'New-NetFirewallRule -DisplayName "{rule_name}" -Direction Inbound -RemoteAddress "{ip_range}" -Action Block'
        # Execute the command using PowerShell
        subprocess.run(["powershell", "-Command", command], check=True)
        print(f"[+] Network {bssid} with IP range {ip_range} has been blocked successfully.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to block network: {e}")  # Log PowerShell execution errors
    except Exception as e:
        print(f"[!] Error: {e}")  # Log other errors

# Kivy GUI for WiFi Blocker
class WifiBlockerApp(App):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.networks = []  # Store scanned networks

    def build(self):
        self.title = "WiFi Rogue Network Blocker (Windows)"  # Set the application title

        # Root layout
        self.layout = BoxLayout(orientation='vertical', padding=10, spacing=10)

        # Title Label
        self.layout.add_widget(Label(text="WiFi Rogue Network Blocker", font_size=20, bold=True, halign="center", size_hint=(1, 0.1)))

        # Scan Button
        self.scan_button = Button(text="Scan for WiFi Networks", size_hint=(1, 0.1))
        self.scan_button.bind(on_press=self.scan_and_display)  # Bind scan button to the scan function
        self.layout.add_widget(self.scan_button)

        # Scrollable area for network list
        self.scroll_view = ScrollView(size_hint=(1, 1))  # Allow scrolling for the list of networks
        self.network_list = GridLayout(cols=1, size_hint_y=None)  # Grid layout for displaying networks
        self.network_list.bind(minimum_height=self.network_list.setter('height'))  # Adjust height based on content
        self.scroll_view.add_widget(self.network_list)  # Add the grid to the scroll view
        self.layout.add_widget(self.scroll_view)  # Add the scroll view to the root layout

        return self.layout  # Return the complete layout

    def scan_and_display(self, instance):
        print("[*] Scan button clicked.")  # Log the button click event

        # Clear the previous list
        self.network_list.clear_widgets()

        # Check for admin privileges
        if not is_admin():
            # Show an error if not running as administrator
            self.network_list.add_widget(Label(text="[ERROR] Run the script as Administrator!", color=(1, 0, 0, 1), size_hint_y=None, height=30))
            return

        # Perform WiFi scan
        self.networks = scan_wifi()
        if not self.networks:
            # Show a message if no networks are found
            self.network_list.add_widget(Label(text="No WiFi networks found or WiFi is disabled.", size_hint_y=None, height=30))
            return

        # Display scanned networks
        for network in self.networks:
            ssid = network.get("SSID", "Unknown")  # Get SSID or default to "Unknown"
            bssid = network.get("BSSID", "Unknown")  # Get BSSID or default to "Unknown"
            signal = network.get("Signal", "N/A")  # Get signal strength or "N/A"
            label_text = f"{ssid} ({bssid}) - Signal: {signal}%"  # Format network details

            # Check if the network meets rogue criteria
            if "FreeWiFi" in ssid or int(signal) < 30:  # Example criteria
                block_rogue_network(bssid)  # Automatically block if criteria met
                label_text += " [BLOCKED]"  # Indicate that the network was blocked

            # Add a button to manually block networks
            network_row = BoxLayout(orientation='horizontal', size_hint_y=None, height=40)  # Row for each network
            network_row.add_widget(Label(text=label_text, halign="left", valign="middle"))  # Add network details
            block_button = Button(text="Block", size_hint_x=0.3)  # Add block button
            block_button.bind(on_press=lambda instance, bssid=bssid: self.manual_block(bssid))  # Bind button to blocking
            network_row.add_widget(block_button)  # Add button to the row
            self.network_list.add_widget(network_row)  # Add row to the list

    def manual_block(self, bssid):
        print(f"[*] Manually blocking network with BSSID: {bssid}")  # Log manual block action
        block_rogue_network(bssid)  # Call the block function
        # Add confirmation message to the list
        self.network_list.add_widget(Label(text=f"Manually blocked {bssid}", size_hint_y=None, height=30, color=(0, 1, 0, 1)))

# Run the App
if __name__ == "__main__":
    if not is_admin():
        print("[!] Please run this script as Administrator for full functionality.")  # Warn if not admin
    WifiBlockerApp().run()  # Launch the Kivy app
