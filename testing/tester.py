## Automates the process of resetting the container, generating the requests to the server, and collecting the required metrics ##
import sys, json, requests, docker,time
from threading import Thread
import request_generator

PORT = 5002
BASE_URL = f"http://localhost:{PORT}"
HTTP_ENDPOINT = f"{BASE_URL}/analyze_http"
DNS_ENDPOINT = f"{BASE_URL}/analyze_dns"
ALL_STATS_ENDPOINT = f"{BASE_URL}/all_stats"
CONTAINER_NAME = 'mondeo_backend_1'
FOLDER = 'pcaps_aida_mondeo'
#FILELIST = ['20221104-6a1e14-Correos', '20221104-7f5f95-FedEx','20221104-686cfdd-UPS','20221104-35427f-DHL','20221104-edf4b-VoiceMail','20221104-xxxx-FedEx','cap_00023_20220506232010']
FILELIST = ['cap_115_125']
results = {}
stop = False

def parse_docker_stats(stat):
    used_memory = stat['memory_stats']['usage'] - stat['memory_stats']['stats']['inactive_file']
    available_memory = stat['memory_stats']['limit']
    memory_usage = (used_memory / available_memory) * 100.0 # In pct
    cpu_delta = stat['cpu_stats']['cpu_usage']['total_usage'] - stat['precpu_stats']['cpu_usage']['total_usage']
    system_cpu_delta = stat['cpu_stats']['system_cpu_usage'] - stat['precpu_stats']['system_cpu_usage']
    number_cpus = stat['cpu_stats']['online_cpus']
    cpu_usage = (cpu_delta / system_cpu_delta) * number_cpus * 100.0 # IN pct
    net_io_rx = stat['networks']['eth0']['rx_bytes']
    net_io_tx = stat['networks']['eth0']['tx_bytes']
    blk_io_rx = 0 if stat['blkio_stats']['io_service_bytes_recursive'] is None else stat['blkio_stats']['io_service_bytes_recursive'][0]['value'] #read
    blk_io_tx = 0 if stat['blkio_stats']['io_service_bytes_recursive'] is None else stat['blkio_stats']['io_service_bytes_recursive'][1]['value']#write
    pid = stat['pids_stats']['current']
    time = stat['read']
    return {'timestamp': time,
            'cpu_usage': cpu_usage,
            'memory_usage': used_memory,
            'memory_limit': available_memory,
            'memory_pct': memory_usage,
            'net_input' : net_io_rx, # To MB *10**-6
            'net_output' : net_io_tx, # To MB *10**-6
            'block_input': blk_io_rx, # To MB *10**-6
            'block_output': blk_io_tx, # To MB *10**-6
            'pid': pid}

def gen_data(file):
    r = request_generator.gen_requests(file + '.json')
    if not r: #
        data = requests.get(ALL_STATS_ENDPOINT)
        #Save to file
        with open(file + '_analysis_output.json', 'w', encoding='utf-8') as f:
            json.dump(data.json(), f, ensure_ascii=False, indent=4)

def measure_container(container): #Get stats every second
    global results, stop
    while not stop:
        current_stat = container.stats(decode=None, stream = False)
        parsed = parse_docker_stats(current_stat)
        results['data'].append(parsed)
        results['total'] += 1
        time.sleep(1) #Records stats every second

def save_container_stats(stats, file_path):
    with open(file_path + '_docker_logs.json', 'a', encoding='utf-8') as f:
        json.dump(stats, f, ensure_ascii=False, indent=4)


if __name__ == '__main__':
    cli = docker.from_env()
    container = cli.containers.get(CONTAINER_NAME)
    container.stop()
    time.sleep(7)
    for file in FILELIST:
        print(f'PARSING FILE {file}')
        stop = False
        results = {'total': 0, 'data': []}
        container.start()
        time.sleep(7)
        #Measure the container
        thread = Thread(target=measure_container, args=(container,)) 
        thread.start()
        #Start generating the tests
        gen_data(f"{FOLDER}/{file}")
        #Wait for thread to join
        stop = True
        thread.join()
        #Save stats
        save_container_stats(results, f"{FOLDER}/{file}")
        container.stop()
