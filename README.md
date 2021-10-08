# threatenrich-demo
This is a simple demo python script to automate the enrichment of certain file attributes received from the forensic data collector script.
Please use the following instructions below for setup. This automation script should be executed from a debian based linux host.
The following instructions were executed on a Ubuntu 20.04 OS.

## Setup
For demostartion purposes, this code can be ran  driectly on the Ubuntu Linux OS. This project could have been placed in a docker container for easier portability and horizontal scaling. However, this project is only ment to convey a conceptual demonstration of enriching data from typical file attributes (ip address, domain, file hash etc.)

1. Install dependencies using apt ```sudo apt install redis nginx```
2. Configure nginx
  * Place config file in the nginx conf directory ```cp nginx/threatenrich.conf /etc/nginx/conf.d/```
