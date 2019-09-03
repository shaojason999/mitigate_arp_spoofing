# Mitigation of ARP Spoofing
## 成大資工專題展
1. we came up with a new mechanism to mitigate ARP spoofing
2. implemented in OpenFlow and P4, and this repo contains only OpenFlow
3. the common solution for ARP spoofing is called DAI, which is used to compare to our mechanism and it is in the ./only_dhcp_snooping folder

### topology
![](https://i.imgur.com/GalHsoo.png)

### experiment
In the attack scenario simulated in Mininet, the attacker (H1) sends 1000 valid ARP request packets to H3 in one minute.
![](https://i.imgur.com/7TCGqS7.png)
![](https://i.imgur.com/Z8B1eWa.png)

### comman
1. one window run controller
	```
	$ ./controller_start.sh
	```
2. another window run mininet
	```
	$ ./mininet_start.sh
	```
### ps
1. clean the mininet first if there is a problem when creting a mininet
  ```
  $ sudo mn -c
  ```
