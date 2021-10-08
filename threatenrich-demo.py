from flask import Flask, request, jsonify
from pprint import pprint
import threading
import requests
import shodan
import redis
import time
import ast

# Config section
API_HOST= "127.0.0.1"
API_PORT = 8888
REDIS_SERVER="127.0.0.1"
REDIS_PORT=6379
REDIS_EXPIRE_TIME= 86400
VT_API=""
SHODAN_API = ""
RISKIQ_API = ""
RISKIQ_USERNAME = ""
ALL_RESULTS = {}

# Initialize the HTTP API
app = Flask(__name__)

# Connect to redis
try:
    print('[+] Connecting to redis at {}:{}'.format(REDIS_SERVER, REDIS_PORT))
    r = redis.Redis(host=REDIS_SERVER, port=REDIS_PORT)
    ping = r.ping()
    if ping is True:
        print('[+] Redis connection successful')
except Exception as e:
    print('[-] Failed to connect to redis. Exiting: {}'.format(e))
    exit()

@app.route("/file/enrichment", methods=["POST"])
# Function to handle request
def query():
    if request.headers["Content-Type"] == "application/json":
        # Pull json out of POST body
        content = request.get_json()
        status = r.lpush("threatenrich", str(content))
        print("[+] Data sent to threat enrich queue")
        resp = jsonify(success=True)
        return resp
    else:
        resp = jsonify(success=False)
        return resp            

def virustotal_lookup(filehash):
    print("[+] Performing VirusTotal lookup")
    headers = {"x-apikey": VT_API}
    try:
        if r.exists(filehash) == 1:
            print("[+] Found filehash in cache")
            redis_message_cache = r.get(filehash)
            parsed_message = redis_message_cache.decode("utf-8")
            redis_json_message = ast.literal_eval(parsed_message)
            ALL_RESULTS.update(redis_json_message)
        else:
            print('[+] Filehash not found in cache')
            time.sleep(15)
            vt_r = requests.get("https://www.virustotal.com/api/v3/search?query={}".format(filehash), headers=headers)
            vt_r.json()
            print("[+] Status code is {}".format(vt_r.status_code))
            status = r.set(filehash, str(vt_r.json()), ex=REDIS_EXPIRE_TIME)
            print("[+] Filehash set in cache")
            ALL_RESULTS.update(vt_r.json())
    except Exception as e:
        print("[-] VirusTotal failed lookup: {}".format(e))
        ALL_RESULTS.update({"virustotalError": str(e)})

def get_shodan_data(ipaddress):
    try:
        if r.exists(ipaddress) == 1:
            print("[+] Found ipaddress in cache")
            redis_message_cache = r.get(ipaddress)
            parsed_message = redis_message_cache.decode("utf-8")
            redis_json_message = ast.literal_eval(parsed_message)
            ALL_RESULTS.update(redis_json_message)
        else:
            print("[+] Performing Shodan.io lookup on {}. Waiting 1 second for Shodan Rate Limiting".format(ipaddress))
            time.sleep(15)
            api = shodan.Shodan(SHODAN_API)
            results = api.host(ipaddress)
            shodanDict = {
                "shodan.ports": "",
                "shodan.isp": "",
                "shodan.hosts": [],
                "shodan.tags": "",
                "shodan.portdata": [],
                "shodan.vulns": [],
                "shodan.url": "https://www.shodan.io/host/{}".format(ipaddress),
                "shodan.results": "",
            }
            shodanDict["shodan.ports"] = results["ports"]
            shodanDict["shodan.isp"] = results["isp"]
            shodanDict["shodan.tags"] = results["tags"]
            shodanDict["shodan.results"] = "ip found"
            shodanDict["shodan.vulns"] = results.get("vulns", "No vuln data")
            for i in results["data"]:
                shodanDict["shodan.portdata"].append(i["data"])
                if "http" in i:
                    shodanDict["shodan.hosts"].append(i["http"]["host"])
            print("[+] Shodan lookup complete")
            #pprint(shodanDict)
            status = r.set(ipaddress, str(shodanDict), ex=REDIS_EXPIRE_TIME)
            print("[+] Ipaddress set in cache")
            ALL_RESULTS.update(shodanDict)
    except shodan.exception.APIError as e:
        print("[-] Failure: ShodanAPIError for ip {0}: {1}".format(ipaddress, e))
        ALL_RESULTS.update({"shodanError": str(e)})
    except Exception as e:
        print("[-] Failed to lookup Shodan.io data for {0} with : {1}".format(ipaddress, e))  
        ALL_RESULTS.update({"shodanError": str(e)})

def risk_iq_lookup_enrichment(domain):
    print("[+] Performing Risk IQ Domain lookup")
    auth = (RISKIQ_USERNAME, RISKIQ_API)
    enrich_url = 'https://api.riskiq.net/pt/v2/enrichment?query={}'
    try:
        if r.exists(domain) == 1:
            print("[+] Found domain in cache")
            redis_message_cache = r.get(domain)
            parsed_message = redis_message_cache.decode("utf-8")
            redis_json_message = ast.literal_eval(parsed_message)
            ALL_RESULTS.update(redis_json_message)
        else:        
            response = requests.get(enrich_url.format(domain), auth=auth)
            #pprint(response.json())
            status = r.set(domain, str(response.json()), ex=REDIS_EXPIRE_TIME)
            print("[+] Domain set in cache")            
            ALL_RESULTS.update(response.json())
    except Exception as e:
        print("[-] Risk IQ failed lookup: {}".format(e))
        ALL_RESULTS.update({"riskIQError": str(e)})

def main(arg):
    while True:
        try:
            print("[+] Queue handler waiting for messages")
            _, message = r.blpop("threatenrich")
            message = message.decode("utf-8")
            json_message = ast.literal_eval(message)
            pprint(json_message)
            print("[+] Starting threads for forensic enrichment")
            threads =list()
            t1 = threading.Thread(target=virustotal_lookup, args=(json_message['filehashMD5'],), daemon=True)
            t2 = threading.Thread(target=get_shodan_data, args=(json_message['ipaddress'],), daemon=True)
            t3 = threading.Thread(target=risk_iq_lookup_enrichment, args=(json_message['domain'],), daemon=True)
            t1.start()
            t2.start()
            t3.start()
            threads.append(t1)
            threads.append(t2)
            threads.append(t3)
            for index, thread in enumerate(threads):
                thread.join()
                print("[+] {} thread complete".format(index))
            #pprint(ALL_RESULTS)
        except Exception as e:
            print("[-] Error occured: {}".format(e))

if __name__ == "__main__":
    print("[+] Starting queue handler")
    que_handler_thread = threading.Thread(target=main, args=(None,), daemon=True)
    que_handler_thread.start()
    print("[+] Starting Flask")
    app.run(host=API_HOST, port=API_PORT)
