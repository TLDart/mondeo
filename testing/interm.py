import json, requests, ipaddress

##CONFIG VARS
port = 5002
base_url = f"http://localhost:{port}"
http_endpoint = f"{base_url}/analyze_http"
dns_endpoint = f"{base_url}/analyze_dns"
##path = f'''test_files/{filename}.csv''' #Data used for test purposes

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

def gen_requests(path): # POC for packet injection in the system
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
            exit(0)

if __name__ == '__main__':
    gen_requests('pcaps/cap_115_125.json')