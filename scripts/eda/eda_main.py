import pandas as pd
import time
import json
import dvc
import sys
import gc
import os

from time import localtime, strftime
from IPython import get_ipython
from dotenv import load_dotenv
from pathlib import Path

current_dir = Path(__file__).resolve().parent
dotenv_path = current_dir.parent.parent / '.env'

load_dotenv(dotenv_path=dotenv_path)


with open("credentials.json") as f:
    os.environ["GDRIVE_CREDENTIALS_DATA"] = f.read()


try:
    from ..data_acquisition import dtaq_main as dtaq
except NameError:
    from scripts.data_acquisition import dtaq_main as dtaq
except ImportError:
    # Agrega el directorio del módulo al sys.path
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data_acquisition')))

    import dtaq_main as dtaq


class DataGeneration(dtaq.IOCValidatedModel):

    def generation_API_call(self):
        """Function to evaluate the data of APIs using a document to extract information to analyze the
        behaviour of information that is brought by each CTI web tool"""

        ioc_value, ioc_type = self.ioc
        if ioc_type == "ip":
            ## Virus Total:
            virustotal = dtaq.VirusTotal(ioc=ioc_value).display_ip_info()

            ## AbuseIPDB
            abuseipdb = dtaq.AbuseIPDB(ioc=ioc_value).check_ip()
            
            ## Whois
            whois_adap = dtaq.WHOIS_RDAP(ioc=ioc_value).get_whois_data()

            ## Shodan IP
            shodan = dtaq.ShodanIO(ioc=ioc_value).search_data_in_shodan()

            return self.dataframe_report(ioc_value, virustotal, abuseipdb, whois_adap, shodan)


        elif ioc_type == "domain":

            ## Virus Total:
            virustotal = dtaq.VirusTotal(ioc=ioc_value).display_domain_info()
            ## AbuseIPDB
            abuseipdb = "No aplica"
            ## Whois
            whois_adap = "No aplica"
            ## Shodan Domain
            shodan = dtaq.ShodanIO(ioc=ioc_value).search_data_in_shodan()

            return self.dataframe_report(ioc_value, virustotal, abuseipdb, whois_adap, shodan)
        
        else:
            ## Virus Total:
            virustotal = dtaq.VirusTotal(ioc=ioc_value)

            ## AbuseIPDB
            abuseipdb = dtaq.AbuseIPDB(ioc=ioc_value).check_ip()
            
            ## Whois
            whois_adap = dtaq.WHOIS_RDAP(ioc=ioc_value).get_whois_data()

            ## Shodan IP
            shodan = dtaq.ShodanIO(ioc=ioc_value).search_data_in_shodan()
            ## Shodan Domain
            if shodan == {}:
                shodan = dtaq.ShodanIO(ioc=ioc_value).search_data_in_shodan()

            return self.dataframe_report(ioc_value, virustotal, abuseipdb, whois_adap, shodan)

            

    def dataframe_report(self, ioc_value, virustotal, abuseipdb, whois_adap, shodan):
        """Function to complete the pandas data frame of responses base on iocs present in a document"""
        
        report = pd.DataFrame([{"IoC": str(ioc_value), "VirusTotal": str(virustotal), "AbuseIPDB": str(abuseipdb), "Whois_rdap": str(whois_adap), "Shodan.io": str(shodan), "Data_Time": str(self.time_report_generation())}], index=[0])

        # print(type(virustotal))
        """
        report["IoC"]   =  str(ioc_value)
        report["VirusTotal"]  = str(virustotal)
        report["AbuseIPDB"]   = str(abuseipdb)
        report["Whois_rdap"]  = str(whois_adap)
        report["Shodan.io"]   = str(shodan)
        report["Data_Time"]   = str(self.time_report_generation())
        """
        # print(report)

        return report
    
    def time_report_generation(self):
        
        s = strftime("%a_%d_%b_%Y %H-%M", localtime(time.time()))

        return s
    
    
    def createreport_toexcel(self, data):

        if not os.path.exists("scripts\\eda\\data"):
            os.makedirs("scripts\\eda\\data")

        return data.to_excel("scripts\\eda\\data\\Reporte_APIs_validation_" + str(self.time_report_generation()) + ".xlsx", sheet_name="Reporte_APIs")


def __main__():

    #
    data = pd.read_excel("scripts\\eda\\Validacion.xlsx", sheet_name="Hoja1").head(5)
    df = pd.DataFrame(columns=["IoC", "VirusTotal", "AbuseIPDB", "Whois_rdap", "Shodan.io", "Data_Time"])

    #
    
    for i in range(len(data)):
        datageneration = DataGeneration(ioc=data.loc[i, "IoC"].strip())        

        register = datageneration.generation_API_call()
        # print(register)

        df = pd.concat([df, register], axis = 0)
    
    df.reset_index(drop=True, inplace=True)
    datageneration.createreport_toexcel(df)
    gc.collect()


__main__()
    