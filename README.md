## Sock
Recreational programming for fun and relaxation. Includes a UDP and TCP server
and client. The servers are implemented with multi-processing. The TCP server forks
when started and every time a new connection gets accepted. The UDP server also
forks when started. You can controll the client interaction by providing a
client handler callback function. See ```client_test.c``` and ```server_test.c```
for examples. 
