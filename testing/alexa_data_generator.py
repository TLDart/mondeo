## Generates random packets based on a list containing the Alexa's top 1million most visited domains ##
import json, random, socket, struct

PKT_NR = 10000
TIME_DELTA = 15 #seconds
DOMAIN_PATH = 'domains.txt'

def gen_packet(i, time, domain_list):
    domain = random.choice(domain_list)
    domain = 'null' if random.random() < 0.01 else domain
    return {
            "type": "dns",
            "index_number": str(i),
            "source_ip": socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff))),
            "destination_ip": socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff))),
            "frame_len": str(len(domain) + 18), #18 extra size from the packet frame
            "dns_flags": random.randint(0,1),
            "dns_count_queries": str(0),
            "dns_query_type": random.choice(['1','28']),
            "dns_query_name": domain,
            "dns_query_name_null": 1 if domain == 'null' else 0,
            "timestamp": time + random.randint(0, TIME_DELTA)
        }

def gen_multiple_packets(domain_list):
    packet_list = {'total' : 0 , 
                    'packets' : []}
    time =  random.randint(1000000000,2000000000)
    for i in range(PKT_NR):
        packet_list['total'] += 1
        packet = gen_packet(i,time, domain_list)
        packet_list['packets'].append(packet)
    return packet_list

def load_domains(domain_file):
    with open(domain_file, 'r') as f:
        domains = f.read().splitlines() 
    return domains

def save_capture(data, filename):
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

if __name__ == '__main__':
    domains = load_domains(DOMAIN_PATH)
    packets = gen_multiple_packets(domains)
    save_capture(packets,f"alexa_based_{PKT_NR}.json")