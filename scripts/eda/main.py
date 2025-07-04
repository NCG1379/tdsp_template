import pandas as pd
import time
import json
import dvc
import os

import scripts.data_acquisition.main as dtaq

from time import localtime, strftime
from IPython import get_ipython
from dotenv import load_dotenv
from pathlib import Path

current_dir = Path(__file__).resolve().parent
dotenv_path = current_dir.parent.parent / '.env'

load_dotenv(dotenv_path=dotenv_path)


with open("../credentials.json") as f:
    os.environ["GDRIVE_CREDENTIALS_DATA"] = f.read()


class DataGeneration(dtaq.IOCValidatedModel):

    def generation_API_call(self):
        """Function to evaluate the data of APIs using a document to extract information to analyze the
        behaviour of information that is brought by each CTI web tool"""

        ioc_value, ioc_type = self.ioc
        if ioc_type == "ip":
            ## Virus Total:
            virustotal = dtaq.VirusTotal(ioc=self.ioc)

            ## AbuseIPDB
            abuseipdb = dtaq.AbuseIPDB(ioc=self.ioc).check_ip()
            
            ## Whois
            whois_adap = dtaq.WHOIS_RDAP(ioc=self.ioc)

            ## Shodan IP
            shodan = dtaq.ShodanIO(ioc=self.ioc).search_data_in_shodan()

            return self.dataframe_report(self, ioc_value, virustotal, abuseipdb, whois_adap, shodan)


        elif ioc_type == "domain":

            ## Virus Total:
            virustotal = dtaq.VirusTotal(ioc=self.ioc)
            ## AbuseIPDB
            abuseipdb = "No aplica"
            ## Whois
            whois_adap = "No aplica"
            ## Shodan Domain
            shodan = dtaq.ShodanIO(ioc=self.ioc).search_data_in_shodan()

            return self.dataframe_report(self, ioc_value, virustotal, abuseipdb, whois_adap, shodan)
            

    def dataframe_report(self, ioc_value, virustotal, abuseipdb, whois_adap, shodan):
        """Function to complete the pandas data frame of responses base on iocs present in a document"""
        
        report = pd.DataFrame(columns=["IoC", "VirusTotal", "AbuseIPDB", "Whois_rdap", "Shodan.io", "Data_Time"])
     
        report["IoC"]   =  ioc_value
        report["VirusTotal"]  = virustotal
        report["AbuseIPDB"]   = abuseipdb
        report["Whois_rdap"]  = whois_adap
        report["Shodan.io"]   = shodan
        report["Data_Time"]   = self.time_report_generation()

        return report
    
    def time_report_generation(self):
        
        s = strftime("%a %d %b %Y %H:%M:%S", localtime(time.time()))

        return s
    
    
    def createreport_toexcel(self, data):

        return data.to_excel("Reporte_APIs_validation_" + str(self.time_report_generation()), sheet_name="Reporte_APIs")


def __main__():

    #
    data = pd.read_excel("", sheet_name="").head(4)
    df = pd.DataFrame()

    #
    for i, row in data.iterrows():
        datageneration = DataGeneration(ioc=row["IoC"][i])

        register = datageneration.generation_API_call()

        df = pd.concat([df, register], axis = 1)

    datageneration.createreport_toexcel(df)

    #
    