Netlite
============


Netlite is a very lightweight IPv4 netflow alternative written in Go.  
It outputs tab separated lines with this header:  
```
sourceIP        srcPort destinationIP   dstPort proto   timestamp
```

### Requirements ###

 * libpcap
``` 
sudo apt-get install libpcap-dev
```


### Backend ###
Every IP:Port source destination pair gets stored in a simple database.  
The pair only gets printed once.  
Every 10 minutes (configurable) the database is reset and the unique IP:port pair are logged again.  