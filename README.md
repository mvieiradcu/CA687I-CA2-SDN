# DCU Cloud Systems - CA2 - SDN using Mininet and Ryu 


## Useful commands

**Clear existent Mininet network**
- `sudo mn -c`

**Starts the topology**
- `sudo python3 acl_topo.py`

**Start Ryu Manager in Verbose mode**
- `ryu-manager --verbose acl_rest_switch.py`

**On Mininet terminal ping all available hosts**
- `pingall`

**Execute a curl command between H1 and H2 with connection timeout of 1 second**
- `h1 curl --connect-timeout 1 h2`

**Execute a UDP command between H1 and H2 ** https://www.kali.org/tools/hping3/
- `h1 hping3 -c 1 --udp h2`



