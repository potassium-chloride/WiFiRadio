# WiFiRadio
Simplest WiFi Radio on Python for Linux

# Start
Run ```bash
$sudo python3 WiFiMessengerAsync.py wlan0```
where ```wlan0``` is your wireless interface in monitor mode.
I recommend you stop apps which can use the wireless interface and reset its mode

You and your companion(s) should set the same channels(use ```iw```, ```iwconfig``` or etc), start this script, enter names and use it as messenger!

# Notes
This script shouldn't interfere with work of routers and another WiFi devices.
This script haven't any encryption. Anybody can sniff your messages.
This script is experimental, remember it.
