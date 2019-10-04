# sdn_rpc
SDN based load balancing and fault tolerance for IoT Remote Procedure Calls

This application makes use of CoAP (The Constrained application protocol)
## Problem for ryu

1. The link between ryu_application and Zodiac Fx is not stable  
Sometimes will reload the application and add the flows again  
This might caused by the cable between Zodiac and controller  
This might caused by the Zodiac itself  
2. This flow is not stable for Zodiac Fx
```
match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ip_proto=inet.IPPROTO_ICMP,
icmpv4_type=icmp.ICMP_DEST_UNREACH, icmpv4_code=icmp.ICMP_PORT_UNREACH_CODE)
actions = []
self.add_flow(datapath=datapath, table_id=0, priority=100, match=match, actions=actions)
```
This flow is used for blocking the icmp destination unreachable packet  
Sometimes doesn't work  
You may check the flows that could work checked by Zodiac Fx:  
match:  
https://forums.northboundnetworks.com/downloads/zodiac_fx/RYU_Cert/RYU_Cert_v068_Match.txt  
actions:  
https://forums.northboundnetworks.com/downloads/zodiac_fx/RYU_Cert/RYU_Cert_v068_Actions.txt  
metters:  
https://forums.northboundnetworks.com/downloads/zodiac_fx/RYU_Cert/RYU_Cert_v068_Meters.txt  
group:  
https://forums.northboundnetworks.com/downloads/zodiac_fx/RYU_Cert/RYU_Cert_v068_Group.txt  
3. The delete for Zodiac is not stable  
careful when you try to delete the flow and make sure the information you give Zodiac to delete the flow  
4. Must add this to keep application loop  
```
@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
def keep_loop(self):
self.logger.info("get packet")
self.send_event('packet_manager',ryu_event_base.EventMessage())
```
Maybe can change own event to make it loop  
5. The scapy need interface name to send the packet properly  
This problem is solved by using netiface api, but be carefully when you use scapy to send the packet  

## The resource I use to learn

1. openflow: http://flowgrammable.org/sdn/openflow/  
2. ryu: https://ryu.readthedocs.io/en/latest/writing_ryu_app.html  
3. Zodiac: https://forums.northboundnetworks.com/index.php?topic=52.0  
4. scapy: https://scapy.net/  
5. netifaces: https://0xbharath.github.io/python-network-programming/libraries/netifaces/index.html  
6. aiocoap: https://aiocoap.readthedocs.io/en/latest/index.html  
7. socket: https://docs.python.org/3/library/socket.html  
8. multi threading: https://docs.python.org/3/library/threading.html  
9. struct: https://docs.python.org/3/library/struct.html
10. pickle: https://docs.python.org/3/library/pickle.html  


