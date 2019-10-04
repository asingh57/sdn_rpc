# sdn_rpc
SDN based load balancing and fault tolerance for IoT Remote Procedure Calls

This application makes use of CoAP (The Constrained application protocol)
## Xuelin Wei's Work (weixuelings@gmail.com)

The code written by Xuelin Wei is shown below:  

1）controller_api folder  
  
for example_controller.py  
  
-----coap_handler_thread_api.py (handle the coap data)  
-----heartbeat_thread_api.py (handle heartbeat)  
-----job_manager_api.py (class job_manager and class job)  
-----controller_server_api.py (class for controller of specific job_type and packet buffer)  
-----controller_api.py (class for create object controller)  
  
for example_ryu_controller.py and packet_manager.py  
  
-----ryu_event_base.py (class for own ryu event)  
-----ryu_controller_api.py (all class ryu needs)  

2）controll folder  
  
-----config.json   
-----example_controller.py  
-----example_ryu_controller.py   
-----packet_manager  


