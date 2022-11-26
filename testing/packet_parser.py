import pyshark, json
from datetime import datetime

def parse_capture(capture):
    print('STARTED PARSING')
    result = {'total' : 0,
                'packets' : []}
    for packet in capture:
        if 'http' in packet.frame_info.protocols:
            p = {
            'type': 'http',
            'index_number': packet.frame_info.number,
            'source_ip' : packet.ip.src,
            'destination_ip' : packet.ip.dst,
            'host': packet.http.host,
            'timestamp': int(datetime.strptime(packet.frame_info.time[:27], '%b %d, %Y %H:%M:%S.%f').timestamp())
            }
            result['total'] += 1
            result['packets'].append(p)
        elif 'dns' in packet.frame_info.protocols:
            if packet.dns.qry_type in ['255,255','255,255,255','255,255,255,255','255,255,255,255,255']:
                continue #ignore android studio auto generated queries
            p = {
                'type': 'dns',
                'index_number': packet.frame_info.number,
                'source_ip' : packet.ip.src,
                'destination_ip' : packet.ip.dst,
                'frame_len' : packet.frame_info.len,
                'dns_flags' : 0 if packet.dns.flags == '0x0100' or packet.dns.flags == '0x0120' else 1,
                'dns_count_queries' : packet.dns.count_queries,
                'dns_query_type': packet.dns.qry_type,
                'dns_query_name': packet.dns.qry_name,
                'dns_query_name_null': 1 if packet.dns.qry_name == "null" else 0 ,
                'timestamp': int(datetime.strptime(packet.frame_info.time[:27], '%b %d, %Y %H:%M:%S.%f').timestamp())
            }
            result['total'] += 1
            result['packets'].append(p)
    return result


if __name__ == '__main__':
    folder = 'pcaps'
    files = ['cap_115_125']
    for file in files:
        cap = pyshark.FileCapture(f'{folder}/{file}.pcapng', display_filter='(http && tcp.port == 80 && http.request.method == "POST") or (dns and dns.flags.response == 0)')
        res = parse_capture(cap)
        with open(f'{folder}/{file}.json', 'w', encoding='utf-8') as f:
            json.dump(res, f, ensure_ascii=False, indent=4)