# Bug List

## Mac
- [x] BUG-MAC-001: MAC Address is showing up as just the letter 'A' for all devices
- [x] BUG-MAC-002: Despite verifying that nmap is installed and in my path, it is not being found by the application.

## Linux
- [x] BUG-LIN-001: Similiar to BUG-MAC-001, MAC Address is showing up as just the letter 'A' for all devices

## Windows


## Overall

- [x] Capture Packets button on the host details panel does nothing.
- [x] Passive Intel tab does not let you resize the width
- [x] Select interface dropdown is not populated on the Passive Intel tab
- [x] The "topology" tab shows the hosts but they are black circles with purple outlines.  I don't see any info on each and they don't match the legend.  See screenshot attached to conversation.
- [x] The "topology" tab is still showing a black background circle with a purple outline.  I now also see a zoomed in image of a monitor in that circle but can't tell what it is.
- [x] The font for the hosts are white and the background is white as well.  Background should be transparent?
- [x] when a hostname is unknown it should show the ip address instead of "unknown"
- [x] The font is a little too large for each host in the topology tab
- [x] The icons still don't seem right for each host.  See the screenshot attached to the conversation.
- [x] Clicking or right clicking the host does nothing and should show the host details panel.
- [x] The topology tab does not seem to handle all of the potential different device types.  That logic needs expanding and improving. See sample folder for json files from saved scans that include extensive metadata on different devices
- [x] The host on each topology tab should also act like host panels on other views.  It should warn you if a given host has vulnerabilities, open ports, etc. 
- [x] On the Passive Intel tab, the "start capture" button does nothing
- [x] on the topology tab, the legend should be updated to reflect all device types or if there are too many device types there should be an easy way to see the legend in some way with all device types
- [x] on the topology tab, the icons should be updated to reflect all device types
- [x] on the topology tab, the icons are still too large and the border is too thick.  There should also be some padding between the icon and the border.
- [x] for the vulnerability list on the host details panel, the raw html is being rendered for the link and the text is not selectable to copy
- [x] Capture packets button does attempt to start a capture but fails with an error. " Starting passive capture module: pcap on 192.168.1" in the console but in the ui it just shows "failed to start PCAP capture"
- [x] The import .pcap button does nothing  
- [x] Not necessary to add "host" to the capture filter as it seems to be redundant: "[1] tshark: Invalid capture filter "host host 192.168.1.162" for interface 'Ethernet 2'."
- [x] No packets are being captured, even no error is shown in the console: "[1] Starting passive capture module: pcap on Ethernet 2"
- [ ] When smb/nfs shares scanning is enabled, smb or nfs related ports found open for each host, should be able to launch the smb/nfs shared browser right from the host details just like you can with nmap scan and brute force and dir fuzzing.

