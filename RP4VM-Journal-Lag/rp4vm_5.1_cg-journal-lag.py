import sys
import json
import requests
import os
from collections import defaultdict
from datetime import date,datetime
from prettytable import PrettyTable
from getpass import getpass

###Adding 'color' class to be used for printing the errors
class color:
   PURPLE = '\033[95m'
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[91m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'

# Declaring the variables
BASE_5_1_FAPI_REST_URL_PATH = "/fapi/rest/5_1/"
HTTP_REQUEST_HEADERS = {"Content-Type": "application/json"}
CG_IDs_list = []
CG_names_list = []
journal_lag_list = []
CG_state_list = []
init_percentage_list = []

requests.packages.urllib3.disable_warnings()
req = requests.session()


# Get Input from user
print ("Enter the Cluster IP of RP4VM Cluster")
cluster_ip_rp4vm = input() ##This only works with Python version 3.x
print ("Enter Username: ")
usrname = input() ##This only works with Python version 3.x
passwd = getpass("Enter Password: ")

path = ['groups/information', '/statistics']

datestring = datetime.strftime(datetime.now(), '%Y-%m-%d_%H-%M-%S')
daily_journal_lag_report = open("RP4VM_Journal_Lag_" + datestring + ".txt", "w+")
daily_journal_lag_report.write("Script Version: 1.0 \n")
daily_journal_lag_report.write("Author: Nishant Konduru \n \n")
daily_journal_lag_report.write("########################################################################################################### \n \n")
print ("########################################################################################################### \n")
start_date_str = ("=-=-=-=-=-=-=-= Today is - " + datestring + " =-=-=-=-=-=-=-= \n \n")
daily_journal_lag_report.write(start_date_str + "\n")



t = PrettyTable()
t.field_names = ['CG-Name', 'CG-ID', 'CG-State', 'Init %', 'Journal Lag in MB']

for item in path:
    url = "https://" + cluster_ip_rp4vm + BASE_5_1_FAPI_REST_URL_PATH + item

    requests.packages.urllib3.disable_warnings()
    req = requests.session()
    #Set Authentication username or pwd
    req.auth = (usrname, passwd)
    req.headers.update(HTTP_REQUEST_HEADERS)

    if item == 'groups/information':
        try:
            print (url)
            daily_journal_lag_report.write(url + "\n")
            response_groups_info = req.get(url, verify=False)
            json_groups_info = response_groups_info.json()
            if response_groups_info.status_code == 200:
                if json_groups_info['innerSet'] == []:
                    print ("There are no VMs protected on this RP4VM cluster")
                    daily_journal_lag_report.write("There are no VMs protected on this RP4VM cluster \n")
                    break
                else:
                    for itm in json_groups_info['innerSet']:
                        GroupUID = itm['groupUID']['id']
                        GroupName = itm['name']
                        CG_IDs_list.append(GroupUID)
                        CG_names_list.append(GroupName)
        except Exception as e:
            if response_groups_info.status_code == 401:
                print ("401 - User not authorized. Please check your credentials and run the script again! \n")
                daily_journal_lag_report.write("401 - User not authorized. Please check your credentials and run the script again! \n \n")
                break

    elif item == '/statistics':
        for itm in CG_IDs_list:
            url = "https://" + cluster_ip_rp4vm + BASE_5_1_FAPI_REST_URL_PATH + "groups/" + str(itm) + item
            if req.verify:
                response_group_statistics = req.get(url, verify=False)
                json_response_group_statistics = response_group_statistics.json()
                if json_response_group_statistics['consistencyGroupCopyStatistics']:
                    for no_item in range(len(json_response_group_statistics['consistencyGroupCopyStatistics'])):
                        if json_response_group_statistics['consistencyGroupCopyStatistics'][no_item]['journalStatistics']:
                            journal_lag_bytes = json_response_group_statistics['consistencyGroupCopyStatistics'][no_item]['journalStatistics']['journalLagInBytes']
                            journal_lag_MB = (journal_lag_bytes)/1000000
                            journal_lag_MB = float(format(journal_lag_MB, '.2f'))
                            journal_lag_list.append(journal_lag_MB)
                else:
                    journal_lag_MB = 0
                    journal_lag_list.append(journal_lag_MB)

                if json_response_group_statistics['consistencyGroupLinkStatistics']:
                    for no_item in range(len(json_response_group_statistics['consistencyGroupLinkStatistics'])):
                        if json_response_group_statistics['consistencyGroupLinkStatistics'][no_item]['initStatistics']:
                            init_ratio = json_response_group_statistics['consistencyGroupLinkStatistics'][no_item]['initStatistics']['initCompletionPortion']
                            init_ratio = float(format(init_ratio, '.2f'))
                            init_percentage = init_ratio * 100
                            init_percentage = str(init_percentage) + '%'
                            init_percentage_list.append(init_percentage)
                else:
                    init_percentage = '-'
                    init_percentage_list.append(init_percentage)

for itm in CG_IDs_list:
    url = "https://" + cluster_ip_rp4vm + BASE_5_1_FAPI_REST_URL_PATH + "groups/" + str(itm) + "/state"
    if req.verify:
        response_group_state = req.get(url, verify=False)
        json_response_group_state = response_group_state.json()
        cg_state = json_response_group_state['linksState'][0]['pipeState']
        CG_state_list.append(cg_state)

for i in range(len(CG_IDs_list)):
    t.add_row([CG_names_list[i], CG_IDs_list[i], CG_state_list[i], init_percentage_list[i], journal_lag_list[i]])

print(t)
print(color.BOLD + color.RED + "Note that if the Journal Lag for a CG is 0 then that CG might be INITIALIZING or in a DISABLED state" + color.END + "\n")
print("########################################################################################################### \n \n")

table_data = t.get_string() #Changing the data to string to be written to the PrettyTable
daily_journal_lag_report.write(table_data + "\n \n")
daily_journal_lag_report.write("*****Note that if the Journal Lag for a CG is 0 then that CG might be be INITIALIZING or in a DISABLED state***** \n \n")
daily_journal_lag_report.write("########################################################################################################### \n \n")
daily_journal_lag_report.close()
