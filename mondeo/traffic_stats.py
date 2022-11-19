from datetime import datetime
import numpy as np

class StatCounter:

    def __init__(self, load_path = None) -> None:
        self.reset_stats() 

        #Alternatively we can directly load the model into the traffic instance
        if load_path is not None:
            self.load_stats(load_path)

    def reset_stats(self):
        #Model Name and info
        self.model_name = 'undefined'
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

    def __repr__(self):#TODO fix repr and Load
        return self.print_stats()

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
            self.time_http_pass_list.append(time)
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
            with open(path, 'w') as f:
                #Header
                f.write(','.join(['timestamp', 'model_name', 'total_packets', 'total_packets_dns', 'total_packets_http','passed_packets_dns', 'flagged_packets_dns', 'passed_packets_http', 'flagged_packets_http' 'query_rate_flagged', 'whitelist_passed', 'blacklist_flagged', 'dga_flagged', 'dga_passed', 'ml_flagged', 'ml_passed']))
                f.write('\n')
                #General Info
                data = [str(datetime.now().strftime("%Y_%m_%d-%I:%M:%S_%p")), self.model_name, str(self.total_packets()), str(self.total_packets_dns()), str(self.total_packets_http()), str(self.passed_packets_dns()), str(self.flagged_packets_dns()), str(self.passed_packets_http()), str(self.flagged_packets_http()), str(len(self.time_query_ratio_list)), str(len(self.time_whitelist_list)), str(len(self.time_blacklist_list)), str(len(self.time_dga_flag_list)), str(len(self.time_dga_pass_list)), str(len(self.time_ml_flag_list)), str(len(self.time_ml_pass_list))]
                f.write(','.join(data))
                f.write('\n')
                #Write the lists down
                f.write(','.join(list(map(str, self.time_whitelist_list))))
                f.write('\n')
                f.write(','.join(list(map(str, self.time_blacklist_list))))
                f.write('\n')
                f.write(','.join(list(map(str, self.time_query_ratio_list))))
                f.write('\n')
                f.write(','.join(list(map(str, self.time_dga_flag_list))))
                f.write('\n')
                f.write(','.join(list(map(str, self.time_dga_pass_list))))
                f.write('\n')
                f.write(','.join(list(map(str, self.time_ml_flag_list))))
                f.write('\n')
                f.write(','.join(list(map(str, self.time_ml_pass_list))))
                f.write('\n')
                f.write(','.join(list(map(str, self.time_http_pass_list))))
                f.write('\n')
                f.write(','.join(list(map(str, self.time_http_flag_list))))
                f.write('\n')
                #Domains
                f.write(','.join(self.whitelist_domains))
                f.write('\n')
                f.write(','.join(self.blacklist_domains))
                f.write('\n')
                f.write(','.join(self.query_rate_flag_domains))
                f.write('\n')
                f.write(','.join(self.dga_flagged_domains))
                f.write('\n')
                f.write(','.join(self.dga_passed_domains))
                f.write('\n')
                f.write(','.join(self.ai_flagged_domains))
                f.write('\n')
                f.write(','.join(self.ai_passed_domains))
                f.write('\n')
                f.write(','.join(self.http_passed_domains))
                f.write('\n')
                f.write(','.join(self.http_flagged_domains))
            return True
        except Exception as e:
            print(e)        
            return False

    def load_stats(self, path):
        res = False
        try:
            with open(path, 'r') as f: #TODO: FINISH LOAD ALL STATS
                data = f.readlines()
                print(len(data))
                #General Information
                info = data[1].split(',') 
                self.model = info[1]
                self.total = int(info[2])
                self.total_dns = int(info[3])
                self.total_http = int(info[4])
                #Time information
                self.time_whitelist_list = [element for element in data[2].split(',')]
                self.time_blacklist_list = [element for element in data[3].split(',')]
                self.time_query_ratio_list = [element for element in data[4].split(',')]
                self.time_dga_flag_list = [element for element in data[5].split(',')]
                self.time_dga_pass_list = [element for element in data[6].split(',')]
                self.time_ml_flag_list = [element for element in data[7].split(',')]
                self.time_ml_pass_list = [element for element in data[8].split(',')]
                self.time_http_pass_list = [element for element in data[9].split(',')]
                self.time_http_flag_list = [element for element in data[10].split(',')]

                ##Convert to float
                self.time_whitelist_list = [] if self.time_whitelist_list == ['\n'] else list(map(float, self.time_whitelist_list))
                self.time_blacklist_list = [] if self.time_blacklist_list == ['\n']  else list(map(float, self.time_blacklist_list))
                self.time_query_ratio_list = [] if self.time_query_ratio_list == ['\n'] else list(map(float, self.time_query_ratio_list))
                self.time_dga_flag_list = [] if self.time_dga_flag_list == ['\n'] else list(map(float, self.time_dga_flag_list))
                self.time_dga_pass_list = [] if self.time_dga_pass_list == ['\n'] else list(map(float, self.time_dga_pass_list))
                self.time_ml_flag_list = [] if self.time_ml_flag_list == ['\n'] else list(map(float, self.time_ml_flag_list))
                self.time_ml_pass_list = [] if self.time_ml_pass_list == ['\n'] else list(map(float, self.time_ml_pass_list))
                self.time_http_pass_list = [] if self.time_http_pass_list == ['\n'] else list(map(float, self.time_http_pass_list))
                self.time_http_flag_list = [] if self.time_http_flag_list == ['\n'] else list(map(float, self.time_http_flag_list))
                #Domain information
                self.whitelist_domains = [element for element in data[11].split(',')]
                self.blacklist_domains= [element for element in data[12].split(',')]
                self.query_rate_flag_domains = [element for element in data[13].split(',')]
                self.dga_flagged_domains = [element for element in data[14].split(',')]
                self.dga_passed_domains = [element for element in data[15].split(',')]
                self.ai_flagged_domains = [element for element in data[16].split(',')]
                self.ai_passed_domains = [element for element in data[17].split(',')]
                self.http_passed_domains = [element for element in data[18].split(',')]
                self.http_flagged_domains = [element for element in data[19].split(',')]
            #print(self.__repr__())
            return True
        except Exception as e:
            print(e)
            return False

    def dict_merge(self, dict1, dict2):
        res = {**dict1, **dict2}
        return res
        

    
