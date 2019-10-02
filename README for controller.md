# RPC_based_SDN
An RPC protocol based on SDN


# Basic Installation - Ubuntu 18.04.3 LTS

This controller runs on Python3, so you may need to install if it does not come with your distribution. 

```bash
sodu apt-get install python3
```


- [Cloning the repository](#cloning-the-repository)
- [Installing dependencies](#installing-dependencies)
- [Application structure](#application-structure)
- [Configure](#configure)
	- [Ryu configure](#ryu-configure)
	- [Controller configure](#controller-configure)
 - [Run sdn_ryu](#run-sdn_ryu)
	- [First: Run the packet_manager.py and example_ryu_controller.py at same time]
 	- [Second: Run example_controller.py with sudo ]
	- [Third: Run the servers and clients]


## Cloning the repository

Run these commands to clone the repository and set up your environment variable to run this application:

```
git clone https://github.com/asingh57/sdn_rpc.git
```

## Installing dependencies

To install sdn_ryu, you need the following libraries and applications:

```
# git clone https://github.com/faucetsdn/python3-ryu.git
# cd into directory where you cloned python3-ryu
# pip install .
```

```
sudo pip3 install scapy
sudo pip3 install --upgrade "aiocoap[all]"
sudo pip3 install netifaces
```

## Application structure

The whole controller part is devided into three parts:
1) example_conteroller.py

process the heartbeat and coap data

2) packet_manager.py

receive message from example_controller.py and pass this message to example_ryu_controller.py

3) example_ryu_controller.py

configure the openflow switch (In our case is Zodiac Fx)

## Configure

Before you run the controller, you need to config the network and server information:

The config.json is shown below:
```
{
    "ryu_config" : {
        "_commit":"this is the topology of this switch",
        "network_config" : {
            "ryu_listen_port":7000,
            "ipv4_port" : {"10.0.0.1":1,
                                        "10.0.0.2":2,
                                        "10.0.0.3":3},
            "ipv4_mac" : {"10.0.0.1":"B8:27:EB:C7:FB:EE",
                                        "10.0.0.2":"00:E0:4C:6A:41:DF",
                                        "10.0.0.3":"00:E0:4C:69:CA:6D"}
        }
    },
    "controller_config":{
        "struct of controller config":{
            "_commit1":"The key word can't be changed",
            "_commit2":"Add the contoller in the controller_config_list",
            "job_type":"Type the name of job_type",
            "server_controller_ipv4":"The ip address of controller",
            "server_udp_port":"The port this kind of server used",
            "coap_data_ipv4":"The ip address you want to use to get the coap data from ryu",
            "coap_data_port":"The port you want to use to get the coap data from ryu",
            "heartbeat_ipv4":"The ip address you want to use to get heartbeat",
            "heartbeat_port":"The port you want to use to get the heartbeat",
            "call_port":"The port calls ryu"
        },
        "controller_config_list":[
            {
                "job_type":"add character",
                "server_controller_ipv4":"10.10.10.10",
                "server_udp_port":5001,
                "coap_data_ipv4":"10.0.0.3",
                "coap_data_port":6001,
                "heartbeat_ipv4":"10.0.0.3",
                "heartbeat_port":6002,
                "call_port":6003
            }
        ]
    }
}
```
### Ryu configure
The ryu config is what the controller use to config the network and ryu-application:
```
"ryu_listen_port":7000
```
This is the port that packet_manager.py use to listen the message from example_controller.py
```
"ipv4_port" : {"10.0.0.1":1, "10.0.0.2":2, "10.0.0.3":3}
```
This is the dictionary that example_ryu_controller.py use to bind the ip address and the port in switch
```
"ipv4_mac" : {"10.0.0.1":"B8:27:EB:C7:FB:EE", "10.0.0.2":"00:E0:4C:6A:41:DF", "10.0.0.3":"00:E0:4C:69:CA:6D"}
 ```
This is a dictionary that queries the mac address.

### Controller configure
```
"struct of controller config":
{
    "_commit1":"The key word of controller config can't be changed",
    "_commit2":"Add the contoller in the controller_config_list",
    "job_type":"Type the name of job_type",
    "server_controller_ipv4":"The ip address of controller",
    "server_udp_port":"The port this kind of server used",
    "coap_data_ipv4":"The ip address you want to use to get the coap data from ryu",
    "coap_data_port":"The port you want to use to get the coap data from ryu",
    "heartbeat_ipv4":"The ip address you want to use to get heartbeat",
    "heartbeat_port":"The port you want to use to get the heartbeat",
    "call_port":"The port calls ryu"
}
```
Add your controller to the controller list as shown:
For example:
```
{
                "job_type":"add character",
                "server_controller_ipv4":"10.10.10.10",
                "server_udp_port":5001,
                "coap_data_ipv4":"10.0.0.3",
                "coap_data_port":6001,
                "heartbeat_ipv4":"10.0.0.3",
                "heartbeat_port":6002,
                "call_port":6003
}
```

## Run sdn_ryu

### First: Run the packet_manager.py and example_ryu_controller.py at same time
```
python3-ryu-manager example_ryu_controller.py packet_manager.py 
```
Wait the ryu-application adds all flows and shows:
```
listen start
```
### Second: Run example_controller.py with sudo 
```
sudo python3 example_controller.py 
```

### Third: Run the servers and clients
The server:
```
python3 controller_beat.py 
python3 example_server.py
```
The client:
```
python3 example_client.py
```


# Notes

sdn-ryu should work on all Linux distributions with the required dependencies
installed.  If you have any problems on any distribution and/or
release, please e-mail weixuelings@gmail.com, or open an issue on this repository.
