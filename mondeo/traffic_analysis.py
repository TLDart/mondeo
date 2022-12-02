import configparser, timeit, dgaintel, tld, pandas as pd, pickle
from traffic_stats import StatCounter

class TrafficAnalyzer:

    class Result:
        def __init__(self) -> None:
            self.value = 0
            self.domain = ''
            self.source = ''
        
        def set_all(self, value, domain, source):
            self.value = value
            self.domain = domain
            self.source = source
        
        def to_dict(self):
            return { 'value': self.value, 'domain':self.domain, 'source': self.source}
    
    class Config:
        def __init__(self, config_path) -> None:
            try:
                self.config = configparser.ConfigParser()
                self.config.read(config_path)
                self.ai_model_path = self.config['PARAMETERS']['AIModelPath']
                self.whitelist_path = self.config['PARAMETERS']['WhitelistPath']
                self.n_packet_warning = int(self.config['PARAMETERS']['NPacketWarning'])
                self.n_packet_interval = int(self.config['PARAMETERS']['NPacketInterval'])
                self.dga_detection_sensitivity_upper = float(self.config['PARAMETERS']['DGASensitivityUpper'])
                self.dga_detection_sensitivity_lower = float(self.config['PARAMETERS']['DGASensitivityLower'])
                self.time_tresh = int(self.config['PARAMETERS']['HTTPTimeTresh'])
                self.retroactive_list = True if self.config['PARAMETERS']['RetroactiveList'] == 'True' else False

                ##Atributing Values
                self.val_pass = float(self.config['FLAG LEVELS']['Pass'])
                self.val_blacklist = float(self.config['FLAG LEVELS']['Blacklist'])
                self.val_whitelist = float(self.config['FLAG LEVELS']['Whitelist'])
                self.val_high_query = float(self.config['FLAG LEVELS']['HighQuery'])
                self.val_dga_prob = float(self.config['FLAG LEVELS']['DgaProb'])
                self.val_ml_classifier = float(self.config['FLAG LEVELS']['MLClassifier'])
            except:
                raise Exception('There was an error parsing the traffic config')

    def __init__(self, config_path, debug = False) -> None:
        self.config = self.Config(config_path)
        self.debug = debug
        self.reset()

        #Load AI Model
        self.ai_model = pickle.load(open(self.config.ai_model_path, 'rb')) 
    
    def reset(self):
        try:
            self.whitelist = self.load_list(self.config.whitelist_path)
            self.blacklist = []
            self.database = {} #database contains a IP : [Counter, Last_msg_timing]-> Used in Query Rate Mechanism
            self.infected_devices = {}
            self.stats = StatCounter()
            return True
        except Exception as e:
            if self.debug:
                print(e)
            return False

    def analyze_dns(self, packet):
        """Abstraction of the Analyze function used to measure time of execution, call regular _analyze function as a subroutine

        Args:
            packet (dict): Packet to be analysed

        Returns:
            Result: Result of the packet analysis
        """
        self.stats.total += 1
        self.stats.total_dns +=1
        result = self.Result()
        wrapped = self.wrapper(self._analyze_dns, packet, result)
        t = timeit.Timer(wrapped).timeit(number=1) * 1000 # In Miliseconds
        self.stats.attribute_time(t)
        return result.to_dict()

    def analyze_http(self, packet):
        self.stats.total += 1
        self.stats.total_http += 1

        result = self.Result()
        wrapped = self.wrapper(self._analyze_http, packet, result)
        t = timeit.Timer(wrapped).timeit(number=1) * 1000 # In Miliseconds
        self.stats.attribute_time(t)
        return result.to_dict()


    def _analyze_http(self, packet,result):
        source = packet['source']
        destination = packet['destination']
        timestamp = int(packet['timestamp'])
        domain = packet['domain']
        
        if source in self.infected_devices:
            if self.infected_devices[source] < timestamp + self.config.time_tresh:
                dga_prob = dgaintel.get_prob(domain)
                if dga_prob >= self.config.dga_detection_sensitivity_upper:
                    self.stats.time_attributer = 'http_flag'
                    result.set_all(1, domain, destination)
                    return
            else:
                self.infected_devices.pop(source)

        self.stats.time_attributer = 'http_pass'
        result.set_all(0, domain, destination) #If it not in the possibly infected list, ignore
        return

    def _analyze_dns(self, packet, result):
        """Analises the Packet According to the designed pipeline

        Args:
            packet (dict): packet to be analyzed
        """
        source = packet['source']
        timestamp = int(packet['timestamp'])
        domain = packet['domain']

        ##Cond0 Whitelisting
        if domain.endswith(tuple(self.whitelist)):
            self.stats.whitelist_domains.append(domain)
            self.stats.time_attributer = 'whitelist'
            result.set_all(self.config.val_pass, domain, source)
            return 
        
        ##Cond1 Blacklisting
        if domain.endswith(tuple(self.blacklist)):
            self.stats.blacklist_domains.append(domain)
            self.stats.time_attributer = 'blacklist'
            result.set_all(self.config.val_blacklist, domain, source)
            self.update_infected_list(source, timestamp)
            return 

        ##Cond2 High Query Rate
        try:
            data = self.database[source]
            if int(data[1]) + self.config.n_packet_interval >= timestamp:
                self.database[source] = [data[0] + 1, timestamp]
            else:
                self.database[source] = [1, timestamp]
        except KeyError as e:
            self.database[source] = [1, timestamp]
        
        if(self.database[source][0] >= self.config.n_packet_warning):
            ##Stats
            self.stats.query_rate_flag_domains.append(domain)
            self.stats.time_attributer = 'query_rate'
            ##
            result.set_all(self.config.val_high_query, domain, source)
            self.update_infected_list(source, timestamp)
            return


        ##Cond2 Simple DGA_value
        dga_prob = dgaintel.get_prob(domain)
        if(dga_prob > self.config.dga_detection_sensitivity_upper): #Most likely a DGA domain
            ##Stats
            self.stats.dga_flagged_domains.append(domain)
            self.stats.time_attributer= 'dga_flag'
            self.update_infected_list(source, timestamp)
            ##
            if self.config.retroactive_list:
                try:
                    fld = tld.get_fld(domain, fix_protocol=True)
                except:
                    fld = domain
                self.blacklist.append(fld)   #TODO: CHECK FOR DUPLICATES (EFFICIENTLY)
            result.set_all(dga_prob, domain, source)
            return 

        if(dga_prob < self.config.dga_detection_sensitivity_lower): #Most likely NOT a DGA domain
            ##Stats
            self.stats.dga_passed_domains.append(domain)
            self.stats.time_attributer= 'dga_pass'
            ##
            if self.config.retroactive_list:
                try:
                    fld = tld.get_fld(domain, fix_protocol=True)
                except:
                    fld = domain
                self.whitelist.append(fld)
            result.set_all(self.config.val_pass, domain, source)
            return 

        ##Cond3 ML
        else:
            _packet = [int(packet['source']), int(packet['destination']),int(packet['length']), int(packet['dns_flag']), int(packet['nr_of_requests']), int(packet['question_type']), int(packet['queries_null']), int(packet['timestamp'])]
            named_packet = pd.DataFrame([_packet], columns = ['SOURCE','DESTINATION','LENGHT','DNS FLAG','NR OF REQUESTS','QUESTION TYPE','QUERIES NULL','TIMESTAMP'])
            pred_rfc = self.ai_model.predict(named_packet)
            if pred_rfc[0] == 1:
                ##Stats
                self.stats.ai_flagged_domains.append(domain)
                self.stats.time_attributer= 'ml_flag'
                result.set_all(self.config.val_ml_classifier, domain, source)
                ##
                self.update_infected_list(source, timestamp)
                return 
        ##Stats 
        self.stats.ai_passed_domains.append(domain)
        self.stats.time_attributer= 'ml_pass'
        ##
        result.set_all(self.config.val_pass, domain, source)
        return

    ## Helper Functions
    def wrapper(self,func, *args, **kwargs):
        """Wrapper funcion used to by timeit

        Args:
            func (function): function to be passed
            args : parameters added to the functions
            kwargs: keywords added to the function

        Returns:
            function: function defined as func
        """
        def wrapped():
            return func(*args, **kwargs)
        return wrapped
    

    def load_list(self, list_path): #TODO: Whitelist with no path
        try:
            with open(list_path, 'r') as f:
                data = f.read().split('\n')
                return data
        except:
            raise Exception('Invalid Path for Whitelist')
    
    def update_infected_list(self, source, timestamp):
        infected_source = int(source)
        timestamp = int(timestamp)
        self.infected_devices[infected_source] = timestamp
        return
