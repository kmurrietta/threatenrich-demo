# threatenrich-demo
This is a simple demo python script to automate the enrichment of certain file attributes received from the forensic data collector script.
Please use the following instructions below for setup. This automation script should be executed from a debian based linux host.
The following instructions were executed on a Ubuntu 20.04 OS.

## Setup
For demonstration purposes, this code can be ran  directly on the Ubuntu Linux OS. This project could have been placed in a docker container for easier portability and horizontal scaling. However, this project is only ment to convey a conceptual demonstration of enriching data from typical file attributes (ip address, domain, file hash etc.)

1. Install dependencies using apt ```sudo apt install redis nginx```
2. Clone this repository ```git clone https://github.com/kmurrietta/threatenrich-demo.git```
3. Configure nginx
	* Place config file in the nginx conf directory ```cp nginx/threatenrich.conf /etc/nginx/conf.d/```
	* For demonstration purposes, create a self sign cert ```sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/nginx-selfsigned.key -out /etc/ssl/certs/nginx-selfsigned.crt```
	* Restart the nginx service ```sudo systemctl restart nginx```
4. Next, use python pip to install python libraries ```python3 -m pip install -r requirements.txt```
5. Finally, for demonstration purposes we will use screen to run the script in the background ```screen -dmSL threatenrich python3 threatenrich-demo.py ```

To test the new HTTP API, use the following curl command.
``curl --location --request POST 'https://<HOSTIP>:8443/file/enrichment' --header 'Content-Type: application/json' --data-raw '{
    "ipaddress": "72.21.81.240",
    "filehashMD5": "3848a99f2efb923a79e7d47577ae9599",
    "domain":"atmape.ru"
}'``
