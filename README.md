iwconfig\_hostap\_fallback
========================

A wireless interface manager which will attempt connection to any number of wireless networks and will gracefully fail to become a host AP.

It uses a python file as a configuration, see [iwf_networks.py](iwf_networks.py)

---

#####Required Debian Package
* hostapd
* wireless-tools (for iwconfig)
* wpasupplicant
* isc-dhcp-server

#####Recommended Debian Packages (you'll have to remove references to these if you wish ommit)
* dnsmasq


---


