## Creates the baseline to generate requests to the REST API ##
import json, requests, ipaddress

##CONFIG VARS
PORT = 5002
BASE_URL = f"http://localhost:{PORT}"
HTTP_ENDPOINT = f"{BASE_URL}/analyze_http"
DNS_ENDPOINT = f"{BASE_URL}/analyze_dns"

def gen_payload_dns(packet):
    payload = '{"source": %s, \
                "destination" : %s, \
                "length" : %s, \
                "dns_flag" : %s, \
                "nr_of_requests" : %s, \
                "question_type" : %s, \
                "queries_null" : %s, \
                "timestamp": %s, \
                "domain" : "%s"}' \
                % ( int(ipaddress.IPv4Address(packet['source_ip'])), 
                    int(ipaddress.IPv4Address(packet['destination_ip'])), 
                    int(packet['frame_len']),
                    int(packet['dns_flags']), 
                    int(packet['dns_count_queries']), 
                    int(packet['dns_query_type']), 
                    int(packet['dns_query_name_null']), 
                    int(packet['timestamp']),
                    packet['dns_query_name'])
    return payload

def gen_payload_http(packet): 
    payload = '{"source": %s, \
                "destination" : %s, \
                "timestamp": %s, \
                "domain" : "%s"}' \
                % ( int(ipaddress.IPv4Address(packet['source_ip'])), 
                    int(ipaddress.IPv4Address(packet['destination_ip'])), 
                    int(packet['timestamp']),
                    packet['host'])
    return payload

def gen_requests(path, http_endpoint = HTTP_ENDPOINT, dns_endpoint = DNS_ENDPOINT): # POC for packet injection in the system
    headers = {'content-type': 'application/json'}
    packets = {}
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f) 
        packets = data['packets']
    for packet in packets:
        if packet['type'] == 'dns':
            payload = gen_payload_dns(packet)
            endpoint = dns_endpoint
        elif packet['type'] == 'http':
            payload = gen_payload_http(packet)
            endpoint = http_endpoint
        else: 
            print('Something went wrong')
            exit(0)
        
        r = requests.post(endpoint, data=payload, headers=headers)
        try:
            print(r.json())
        except:
            print('THERE WAS AN ERROR')
            print(r)
            print(r.content)
            print(payload)
            return 1
    return 0

if __name__ == '__main__':
    gen_requests('pcaps_aida_mondeo/cap_115_125.json')