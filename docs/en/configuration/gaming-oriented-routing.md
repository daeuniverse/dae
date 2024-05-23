DAE Config  (e.g. /etc/dae/config.dae)

```
routing {            
#stop using low efficiency socks5 proxy or else
#dscp(8) -> game             

#using fw mark for ultra fast gaming experience
dscp(8) -> direct(mark:0x800)
}

```

OpenWRT Network Config  (e.g. /etc/config/network)

Please choose the tunnel MTU carefully (CS2 Require MTU > 1300 due to UDP Ping (1300 bytes))

```
config interface 'wg100'                                                 
        option proto 'wireguard'                                         
        option private_key '[Client Private Key]'
        list addresses '10.7.0.2/24'                                    
        list addresses 'fd42:42:42::2/64'                               
        option mtu '1420'                                               
                                                                        
config wireguard_wg100                                                  
        option public_key '[Server Public Key]'
        option endpoint_host '[Your Server IP]'
        list allowed_ips '0.0.0.0/0'  
        list allowed_ips '::/0'       
                                      
config route                          
        option interface 'wg100'      
        option target '0.0.0.0/0'     
        option gateway '10.7.0.1'     
        option table '114'            
                                      
config route6                         
        option interface 'wg100'      
        option target '::/0'          
        option gateway 'fd42:42:42::1'
        option table '114'       
                                 
config rule                      
        option lookup '114'      
        option mark '0x800/0x800'
                                 
config rule6                     
        option lookup '114'      
        option mark '0x800/0x800'
```

OpenWRT Firewall Config (e.g. /etc/config/firewall)

```
config nat                       
        option src 'vpn'         
        option src_ip '[Gaming PC IPv4 Address]'
        option target 'SNAT'         
        option snat_ip '10.7.0.2'    
        option family 'ipv4'         
        list proto 'all'    

config nat                     
        option src 'vpn'
         option src_ip '[Gaming PC IPv6 Address]'
        option target 'SNAT'
        option snat_ip 'fd42:42:42::2'
        option family 'ipv6'
        list proto 'all'

```