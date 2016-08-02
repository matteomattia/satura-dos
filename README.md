# satura-dos

It's a packet forger that implement some well know denial of service attacks on OSI layer 4
The packet forger is built with libnet and libpcap (for packet capturing)

Satura-dos options:

    -i inteface ex. -i eth0. Default auto
    -l list available intefaces
    -s Source IP address. Default random!
    -r Source port. Default random!
    -t Target IP address.
    -p Target port. 
    -T Time delay in milliseconds (1 - 1000ms). Default 1000ms (1 sec) 
    -e Add an exception to a parameter. Different from each attack
    -V Super Verbouse Mode: Start libpcap and printf sent packet.
    -h -? this help
    -v Print libnet version

---------------------------- ATTACKS -----------------------------

    -a 1 : Invalid TCP SYN flood attack (NEW) + Random Payload
      -e : Force the program to forge packet from source port 0
          need to be provided trough -r option)

    -a 2 : NTP amplification DoS attack VU#348126 (ntpd prior to 4.2.7)
          Usage: -s [Spoofed IP (victim)] -t [NTP Server IP] -p 123

    -a 3 : CharGEN Character generation request amplification DoS attack 
          Usage: -s [Spoofed IP (victim)] -t [CharGEN Server IP] -p 19
          
  
# Todo
  
  fix random num gen from libnet beacuse it's not threadsafe
