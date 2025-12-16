# Networks-Project
CS 7457 research project authored by Gavin Crigger, Tao Groves, Matthew Lucio, and Sebastian Wiktorowicz

## File Structure

### Captures directory

The 'captures' directory houses subdirectories that each contain corresponding packet captures. The 'all' directories have captures of all traffic on an interface and should be used as non-LLM flow data. The 'chatgpt', 'gemini', and 'claude' directories all contain captures of LLM-specific data for one set of interactions corresponding to a single IP address. Thus, these captures each represent one flow and contain many flowlets (exact number depends on selected threshold). Furthermore, capture names end with a general description of the queries that took place to hopefully allow for insight into any anomalous data. Finally, 'ipv4' and 'ipv6' simply distinguishes between the IP version that the captures correspond to - all eduroam packet captures are in ipv4 folders. 

### Front-end directory

### Packet-analysis directory

## ip_range_capture.py

This script is the primary data-collection method that we used. Invoking ip_range_capture.py with a specified IP address or range begins a tcpdump into a .txt file with that range/address applied as a filter. The general workflow that we used was:

1) Open Wireshark and an LLM browser interface
2) Issue some long request to the LLM
3) Observe Wireshark traffic to identify the IP address streaming the LLM's response to the device
    - This became easy with time, as LLM flows have a pretty identifiable pattern among the noise of our device connections.
4) Invoke the python script with: *sudo python3 ip_range_capture.py <IP_ADDRESS>*
5) Issue queries to LLM
6) Terminate packet collection with Ctrl+C when done issuing queries or the connection switches off of the specified IP address (when a FIN ACK appears in the Wireshark capture)

Output captures were then moved to their corresponding directory, and the default naming convention of captures was *capture_<DATE>_<TIME>_<IP>_<ADDRESS_SIZE>.txt* - we then manually added qualitative notes to the end of the file name. 