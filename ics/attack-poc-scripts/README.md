# Proof-of-Concept Tools and Scripts

* ICSV-prevent-modbus-write.filter - Ettercap filter that prevents Modbus write commands. Requires ARP-Spoofing attack.
* se-M221-modbus-prevent-start.filter - Ettercap filter that prevents SE M221 Modbus start commands.  Requires ARP-Spoofing attack.
* mitmdump_https_cred_grabber.py - Mitmdump script to automatically grab form-based and HTTP basic authentications, store them for reporting, and run commands using the credentials.  Requires ARP-Spoofing attack.

# Mitigations

**ARP-Spoofing** - this attack required gratuitous ARP network traffic. These ARP messages are only detectable on the local subnet. Most network monitoring and host-based protections (that monitor network communications) can detect and alert on ARP-spoofing activities. 