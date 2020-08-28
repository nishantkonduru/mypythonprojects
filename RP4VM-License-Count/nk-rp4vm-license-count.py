import sys
import json
import requests
import os
from collections import defaultdict
from datetime import date,datetime
from prettytable import PrettyTable

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

#Initialzing the variables
protected_vm_list = []

# Read the input file for API calls
file_in = open("file_input_2.txt", "r")
data_from_file = file_in.readlines()
#print(type(data_from_file))
file_in.close()

######
# Create a daily report file
datestring = datetime.strftime(datetime.now(), '%Y-%m-%d_%H-%M-%S')
daily_report = open("RP4VM_License_report_" + datestring + ".txt", "w+")
start_date_str = ("=-=-=-=-=-=-=-= Today is - " + datestring + " =-=-=-=-=-=-=-=")
daily_report.write(start_date_str)

path = ['settings', 'groups/information']

for line in data_from_file:
    connections_params = line.split()
    vCenter_list_IPs = []
    vCenter_list_names = [] #Initializing the vCenters list
    vCenter_list_uuids = []

    if line in ['\r\n']:
        continue
    usrname = connections_params[0]
    passwd = connections_params[1]
    ip_1 = connections_params[2]
    vm_count = 0 #Initializing VMs protected to 0
    t = PrettyTable()
    t.field_names = ['VM Name', 'vCenter UUID', 'Group Name', 'Group UID', 'RP4VM Cluster ID']

    for item in path:
        url = "https://" + ip_1 + BASE_5_1_FAPI_REST_URL_PATH + item
        #print (url)
        # daily_report.write('\n \n')
        #daily_report.write(url)
        #URL Request to pull JSON
        #Ignore SSL warming
        requests.packages.urllib3.disable_warnings()
        req = requests.session()
        #Set Authentication username or pwd
        req.auth = (usrname, passwd)
        req.headers.update(HTTP_REQUEST_HEADERS)

        if item == 'settings':
            if req.verify:
                print ("Session Established \n")
                response_settings = req.get(url, verify=False)
                json_settings = response_settings.json()

            for itm in json_settings['systemSettings']['clustersSettings']:
                VC_IP = itm['vcenterServers'][0]['vcenterServerUID']['ip']
                vCenter_list_IPs.append(VC_IP)
                for itm2 in itm['ampsSettings']:
                    if itm2['type'] == 'VC':
                        VC_name = itm2['managedArrays'][0]['name']
                        VC_serial = itm2['managedArrays'][0]['serialNumber']
                vCenter_list_names.append(VC_name)
                vCenter_list_uuids.append(VC_serial)
            print (vCenter_list_IPs)
            print (vCenter_list_names)
            print (vCenter_list_uuids)

        elif item == 'groups/information':
            if req.verify:
                print ("Session Established \n")
                print ("URL is " + url)
                daily_report.write('\n \n')
                daily_report.write("Session Established")
                daily_report.write('\n \n')
                daily_report.write("URL is " + url)
                daily_report.write('\n \n')
                response_group_info = req.get(url, verify=False)
                json_groups_info = response_group_info.json()
                if json_groups_info['innerSet'] == []:
                    print (color.BOLD + color.RED + "There are no VMs protected on this RP4VM cluster" + color.END + "\n")
                    daily_report.write("There are no VMs protected on this RP4VM cluster \n")
                    break
                else:
                    for itm in json_groups_info['innerSet']:
                        GroupUID = itm['groupUID']['id']
                        GroupName = itm['name']
                        for itm2 in itm['groupCopiesInformation']:
                            if itm2['role'] == 'ACTIVE':
                                for itm3 in itm2['vmsInformation']:
                                    SourceVMName = itm3['vmName']
                                    vm_count += 1
                                    SourcevCenterUUID = itm2['vmsInformation'][0]['vmUID']['virtualCenterUID']['uuid']
                                    protected_vm_list.append(SourceVMName)
                                    RP4VMClusterID = itm2['groupCopyUID']['globalCopyUID']['clusterUID']['id']
                                    t.add_row([SourceVMName, SourcevCenterUUID, GroupName, GroupUID, RP4VMClusterID])

            print (color.BOLD + color.CYAN + "Total Protected VMs count is = %s " % str(vm_count) + color.END + "\n")
            print ("Following are the VMs that are protected using RP4VM:")
            print (t)
            print('\n')
            table_data = t.get_string()
            daily_report.write("Total Protected VMs count is = %s \n \n" % str(len(protected_vm_list)))
            daily_report.write("Following are the VMs that are protected using RP4VM: \n")
            daily_report.write(table_data)
