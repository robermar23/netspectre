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
- [x] When smb/nfs shares scanning is enabled, smb or nfs related ports found open for each host, should be able to launch the smb/nfs shared browser right from the host details just like you can with nmap scan and brute force and dir fuzzing.
- [x] A user should be able to add an individual already discovered host to the hardening monitor right from its host details
- [x] A user, from the hardening monitor panel, should be able to add all existing discovered hosts instead of having to input a cidr
- [x] On the hardening monitor panel, when a new host appears, the investigate button does nothing
- [x] On the hardening monitor panel, when a new host appears, the investigate button should show the host details panel for that host
- [x] On the hardening monitor panel, after I add a baseline from monitoring a subnet, the host details panels does not always show that the host has being monitored
- [x] On the passive intelligence panel, capture creds shows this error: "tshark: some fields are not valid: pop.request.org" and console output shows: "Starting passive capture     module: arp on Ethernet 2
  Starting passive module arp at tshark with args: -l -i Ethernet 2 -Y arp.opcode == 2 -T fields -e arp.src.proto_ipv4 -e arp.src.hw_mac -e arp.dst.proto_ipv4 -e arp.dst.hw_mac
  Starting passive capture module: creds on Ethernet 2
  Starting passive module creds at tshark with args: -l -i Ethernet 2 -Y ftp.request.command == USER or ftp.request.command == PASS or telnet.data or http.authorization contains     "Basic" or pop.request.command == USER or pop.request.command == PASS or imap.request contains "LOGIN" -T fields -e ip.src -e ip.dst -e tcp.dstport -e ftp.request.command -e ftp.request.arg -e http.authorization -e pop.request.command -e pop.request.arg -e imap.request   Passive module creds exited with code 1"
- [x] On the CloudEnum Panel, after you have discovered some hosts, the "scan host" button on each does nothing.
- [x] on the host details panel, under nmap, nmap-scripts.  It used to show info on each script, including it risk and what not.  All that no longer shows up
- [x] For the Cloud Enum feature, once a host is discovered, the cloud evidence needs to be stored with the host and show on the host detais panel. The host on the dashboard should get a badge as well signifying that cloud enum found data on it
- [x] On the host details panel, only the native port scan, shows options to connect to ports like 22,3389,443,80, etc.  Those ports, discovered by ANY means/tool should be an option under the main ports section where we already offer other netspectre feature quick access buttons.
- [ ] When a web vulnerability is found, I never see a web vulnerability badge appear on the host the web app is on.  I performed a web scan by IP and that host exists by that same IP.  The count should be included in the badge as well as show up on host details panel.  If the scan is performed on a domain and that domain matches the hostname of an existing host, it should update that host.  The web vulnerabilities should then also stick with the host in its json when the session is saved.
- [ ] The Brute force feature appears as a modal.  Like every other features, this should be its own panel that is resizable.
- [ ] Just like the Web workspace vulnerability scanner, the Web workspace SiteMap and DirFuzz features/panels need a visually appealing activity log





