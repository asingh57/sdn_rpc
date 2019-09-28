Install the following


libboost-all-dev
https://github.com/obgm/libcoap
https://github.com/DaveGamble/cJSON

Use -Wno-error flag when compliling the above using Make in Ubuntu

MAKE SURE TO USE 
export LD_LIBRARY_PATH=/usr/local/lib


OR PERMANENTLY:
echo 'export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib' >> ~/.bashrc

