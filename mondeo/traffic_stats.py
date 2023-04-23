from datetime import datetime
import numpy as np, json
from enum import Enum

Dga_name = Enum('Dga_name', ['dga_intel', 'dgad'])

class StatCounter:

    def __init__(self, load_path = None) -> None:
        self.reset_stats() 

        #Alternatively we can directly load the model into the traffic instance
        if load_path is not None:
            self.load_stats(load_path)

    def reset_stats(self):
        #Model Name and info
        self.model_name = 'undefined'
        self.dga_name = 'undefined'
        self.total = 0
        self.total_dns = 0
        self.total_http = 0
        #List containing all the recorded times
        self.time_query_ratio_list = []
        self.time_whitelist_list = []
        self.time_blacklist_list = []
        self.time_dga_flag_list = []
        self.time_dga_pass_list = []
        self.time_ml_flag_list = []
        self.time_ml_pass_list = []
        self.time_http_pass_list = []
        self.time_http_flag_list = []

        #List containing all the analyzed domains
        self.whitelist_domains = []
        self.blacklist_domains = []
        self.query_rate_flag_domains = []
        self.dga_flagged_domains = []
        self.dga_passed_domains = []
        self.ai_flagged_domains = []
        self.ai_passed_domains = []
        self.http_passed_domains = []
        self.http_flagged_domains = []

        #Other
        self.time_attributer = ''
        return True

    def __repr__(self):
        return self.eval_to_json()

    #Packet numbers
    def total_packets(self):
        return self.total_packets_dns() + self.total_packets_http()

    def total_packets_dns(self):
        return self.flagged_packets_dns() + self.passed_packets_dns()

    def total_packets_http(self):
        return self.flagged_packets_http() + self.passed_packets_http()
    
    def flagged_packets_dns(self):
        return len(self.time_query_ratio_list) + len(self.time_blacklist_list) + len(self.time_dga_flag_list) + len(self.time_ml_flag_list)

    def passed_packets_dns(self):
        return len(self.time_whitelist_list) + len(self.time_dga_pass_list) + len(self.time_ml_pass_list)

    def flagged_packets_http(self):
        return len(self.time_http_flag_list)

    def passed_packets_http(self):
        return len(self.time_http_pass_list)
    

    ## Time Operations
    def time_total_packets(self):
        return self.time_total_packets_dns() + self.time_total_packets_http()

    def time_total_packets_dns(self):
        return self.time_passed_packets_dns() + self.time_flagged_packets_dns()

    def time_passed_packets_dns(self):
        return np.sum(self.time_whitelist_list) + np.sum(self.time_dga_pass_list) + np.sum(self.time_ml_pass_list)

    def time_flagged_packets_dns(self):
        return np.sum(self.time_query_ratio_list) + np.sum(self.time_blacklist_list) + np.sum(self.time_dga_flag_list) + np.sum(self.time_ml_flag_list)

    def time_total_packets_http(self):
        return self.time_flagged_packets_http() + self.time_passed_packets_http()

    def time_flagged_packets_http(self):
        return np.sum(self.time_http_flag_list)

    def time_passed_packets_http(self):
        return np.sum(self.time_http_pass_list)

    def get_domain_list(self, list):
        return '\n' + '\n'.join(list)

    def attribute_time(self, time):
        #Places the time instance in the correct list
        if self.time_attributer == 'whitelist': #whitelist
            self.time_whitelist_list.append(time)

        if self.time_attributer == 'blacklist': #Blacklist
            self.time_blacklist_list.append(time)

        if self.time_attributer == 'query_rate': #Query Rate
            self.time_query_ratio_list.append(time)

        if self.time_attributer == 'dga_flag': #DGA Flag
            self.time_dga_flag_list.append(time)

        if self.time_attributer == 'dga_pass': #DGA Pass
            self.time_dga_pass_list.append(time)

        if self.time_attributer == 'ml_flag': #ML Flag
            self.time_ml_flag_list.append(time)

        if self.time_attributer == 'ml_pass': #ML Pass
            self.time_ml_pass_list.append(time)

        if self.time_attributer == 'http_pass': #http Query
            self.time_http_pass_list.append(time)

        if self.time_attributer == 'http_flag': #http Query
            self.time_http_flag_list.append(time)
        self.reset_attribution()
        
        return
    
    def reset_attribution(self):
        self.time_attributer = ''
        return

    ## JSON Response

    def eval_to_json(self):
        return {
        "total_packets": self.total_packets(),
        "total_packets_dns": self.total_packets_dns(),
        "total_packets_http": self.total_packets_http(),
        "passed_packets_dns": self.passed_packets_dns(),
        "flagged_packets_dns": self.flagged_packets_dns(),
        "passed_packets_http": self.passed_packets_http(),
        "flagged_packets_http": self.flagged_packets_http(),
        "flagged_by_query_rate" : len(self.time_query_ratio_list),
        "flagged_by_blacklist" : len(self.time_blacklist_list),
        "passed_by_whitelist" : len(self.time_whitelist_list),
        "flagged_by_dga_calc" : len(self.time_dga_flag_list),
        "passed_by_dga_calc" : len(self.time_dga_pass_list),
        "flagged_by_ml" : len(self.time_ml_flag_list),
        "passed_by_ml" : len(self.time_ml_pass_list),
        "flagged_by_http_eval" : len(self.time_http_flag_list),
        "passed_by_http_eval" : len(self.time_http_pass_list),
        }

    def time_to_json(self):
        return {
        "total_time_packets": self.time_total_packets(),
        "total_time_packets_dns": self.time_total_packets_dns(),
        "total_time_packets_http": self.time_total_packets_http(),
        "time_of_passed_packets_dns" : self.time_passed_packets_dns(),
        "time_of_flagged_packets_dns" : self.time_flagged_packets_dns(),
        "time_of_passed_packets_http" : self.time_passed_packets_http(),
        "time_of_flagged_packets_http" : self.time_flagged_packets_http(),
        "time_flagged_by_query_rate": {"average": np.average(self.time_query_ratio_list), "std" : np.std(self.time_query_ratio_list), "total": len(self.time_query_ratio_list)},
        "time_flagged_by_blacklist" : {"average" : np.average(self.time_blacklist_list), "std": np.std(self.time_blacklist_list), "total": len(self.time_blacklist_list)},
        "time_passed_by_whitelist" : {"average" : np.average(self.time_whitelist_list), "std": np.std(self.time_whitelist_list), "total":  len(self.time_whitelist_list)},
        "time_flagged_by_dga_prob" : {"average" : np.average(self.time_dga_flag_list), "std": np.std(self.time_dga_flag_list), "total": len(self.time_dga_flag_list)},
        "time_passed_by_dga_prob" : {"average" : np.average(self.time_dga_pass_list), "std": np.std(self.time_dga_pass_list), "total": len(self.time_dga_pass_list)},
        "time_flagged_by_ml" : {"average" : np.average(self.time_ml_flag_list), "std": np.std(self.time_ml_flag_list), "total": len(self.time_ml_flag_list)},
        "time_passed_by_ml" : {"average" : np.average(self.time_ml_pass_list), "std": np.std(self.time_ml_pass_list), "total": len(self.time_ml_pass_list)},
        "time_flagged_by_eval_http": {"average": np.average(self.time_http_flag_list), "std" : np.std(self.time_http_flag_list), "total": len(self.time_http_flag_list)},
        "time_passed_by_eval_http" : {"average" : np.average(self.time_http_pass_list), "std": np.std(self.time_http_pass_list), "total": len(self.time_http_pass_list)}
        }

    def domains_to_json(self):
        return {
            "whitelist_domains" : self.whitelist_domains,
            "blacklist_domains" : self.blacklist_domains,
            "query_rate_domains": self.query_rate_flag_domains ,
            "dga_flagged_domains": self.dga_flagged_domains,
            "dga_passed_domains": self.dga_passed_domains,
            "ai_flagged_domains": self.ai_flagged_domains,
            "ai_passed_domains": self.ai_passed_domains,
            "http_passed_domains": self.http_passed_domains,
            "http_flagged_domains": self.http_flagged_domains,
        }
    
    def get_all_stats(self):
        return self.dict_merge(self.domains_to_json(), self.dict_merge(self.time_to_json(), self.eval_to_json()))

    def save_stats(self, path): 
        try:
            data = {'timestamp' : str(datetime.now().strftime("%Y_%m_%d-%I:%M:%S_%p")),
                    'model_name' : self.model_name,
                    'dga_detector': self.config.dga_method,
                    'total_packets': self.total_packets(),
                    'total_packets_dns': self.total_packets_dns(),
                    'total_packets_http': self.total_packets_http(),
                    'passed_packets_dns': self.passed_packets_dns(),
                    'flagged_packets_dns': self.flagged_packets_dns(),
                    'passed_packets_http': self.passed_packets_http(),
                    'flagged_packets_http': self.flagged_packets_http(),
                    'query_rate_flagged': len(self.time_query_ratio_list),
                    'whitelist_passed': len(self.time_whitelist_list),
                    'blacklist_flagged': len(self.time_blacklist_list),
                    'dga_flagged': len(self.time_dga_flag_list),
                    'dga_passed': len(self.time_dga_pass_list),
                    'ml_passed': len(self.time_ml_flag_list),
                    'ml_flagged': len(self.time_ml_pass_list),
                    'time': {
                        'whitelist': self.time_whitelist_list,
                        'blacklist': self.time_blacklist_list,
                        'query_rate': self.time_query_ratio_list,
                        'dga_flag': self.time_dga_flag_list,
                        'dga_pass': self.time_dga_pass_list,
                        'ml_flag': self.time_ml_flag_list,
                        'ml_pass': self.time_ml_pass_list,
                        'http_pass': self.time_http_pass_list,
                        'http_flag': self.time_http_flag_list
                    },
                    'domains': {
                        'whitelist': self.whitelist_domains,
                        'blacklist': self.blacklist_domains,
                        'query_rate': self.query_rate_flag_domains,
                        'dga_flag': self.dga_flagged_domains,
                        'dga_pass': self.dga_passed_domains,
                        'ml_flag': self.ai_flagged_domains,
                        'ml_pass': self.ai_passed_domains,
                        'http_pass': self.http_passed_domains,
                        'http_flag': self.http_flagged_domains
                    },
        }

            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=4)
                return True
        except Exception as e:
            print(e)        
            return False

    def load_stats(self, path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f) 
                #General Information
                self.model = data['model_name']
                self.total = data['total_packets']
                self.total_dns = data['total_packets_dns']
                self.total_http = data['total_packets_http']
                #Time information
                self.time_whitelist_list = data['time']['whitelist']
                self.time_blacklist_list = data['time']['blacklist']
                self.time_query_ratio_list = data['time']['query_rate']
                self.time_dga_flag_list = data['time']['dga_flag']
                self.time_dga_pass_list = data['time']['dga_pass']
                self.time_ml_flag_list = data['time']['ml_flag']
                self.time_ml_pass_list = data['time']['ml_pass']
                self.time_http_flag_list = data['time']['http_flag']
                self.time_http_pass_list = data['time']['http_pass']

                #Domain information
                self.whitelist_domains = data['domains']['whitelist']
                self.blacklist_domains= data['domains']['blacklist']
                self.query_rate_flag_domains = data['domains']['query_rate']
                self.dga_flagged_domains = data['domains']['dga_flag']
                self.dga_passed_domains = data['domains']['dga_pass']
                self.ai_flagged_domains = data['domains']['ml_flag']
                self.ai_passed_domains = data['domains']['ml_pass']
                self.http_flagged_domains = data['domains']['http_flag']
                self.http_passed_domains = data['domains']['http_pass']
            return True
        except Exception as e:
            print(e)
            return False

    def dict_merge(self, dict1, dict2):
        res = {**dict1, **dict2}
        return res
        

    
