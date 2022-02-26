###### This script is suited for Rubriks manufactured using Cisco M4 servers #######
## This script prints the following information,
# 1. Cluster Name
# 2. Rubrik Cluster ID
# 3. Cluster Version
# 4. Timezone
# 5. DNS Information
# 6. NTP Information
# 7. Total number of Briks in the Rubrik Cluster
# 8. Individual Brik Information (id, brikId, IP Address, Status, Support Tunnel Status)
# 9. Total number of disks in the Rubrik Cluster
# 10.Individual disk information (Disk Type, Status, Encrypted - True or False, Capacity)
# 11.Number of HDDs (PASS if 12 and FAIL if less than 12)
# 12.Number of SSDs (PASS if 4 and FAIL if less than 4)

import re ###Used for Regular Expressions
import json
import requests
import sys
from getpass import getpass
# import datetime
from collections import defaultdict
from datetime import date,datetime

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

requests.packages.urllib3.disable_warnings()
req = requests.session()
HTTP_REQUEST_HEADERS = {"Content-Type": "application/json"}

#Get Input from user
print ("Enter the Cluster Management IP of Rubrik Cluster")
mip_rubrik = input() ##This only works with Python version 3.x
print ("Enter Username: ")
usrname = input() ##This only works with Python version 3.x
passwd = getpass("Enter Password: ")

req.auth = (usrname, passwd)
req.headers.update(HTTP_REQUEST_HEADERS)

print ("########################################################################################################### \n")

#Declaring the API End Point for Rubrik using its 'mip'
CLUSTER_API_ENDPOINT_BASE = "https://" + mip_rubrik + "/api/v1/"
CLUSTER_API_ENDPOINT_BASE_INTERNAL = "https://" + mip_rubrik + "/api/internal/"

datestring = datetime.strftime(datetime.now(), '%Y-%m-%d_%H-%M-%S')
qa_report = open("Rubrik_QA_output_" + mip_rubrik + "_" + datestring + ".txt", "w+")
print ("Report ran on %s \n" % datestring)
qa_report.write("Report ran at %s \n \n" % datestring)

####Declaring the individual API URLs required####
CLUSTER_ME = CLUSTER_API_ENDPOINT_BASE + "cluster/me" #This API endpoint is used to get the Rubrik Cluster name, ID, Version and Time Zone
rubrik_id = " " #Declaring the Rubrik ID

print (color.BOLD + "***************************** Cluster Information for Rubrik: %s *****************************\n " % mip_rubrik + color.END)
qa_report.write("***************************** Cluster Information for Rubrik: %s ***************************** \n \n" % mip_rubrik)

try:
    ##########GetClusterInfo##########
    response_cluster_info = req.get(CLUSTER_ME, headers=HTTP_REQUEST_HEADERS, verify=False)
    cluster_info_json = response_cluster_info.json()
    if response_cluster_info.status_code == 200:
        print ("200 OK - Session Established \n")
        qa_report.write("200 OK - Session Established \n \n")
        print ("Cluster Name: %s" % cluster_info_json['name'])
        rubrik_id = cluster_info_json['id']
        print ("Rubrik Cluster ID: %s" % cluster_info_json['id'])
        print ("Cluster Version: %s" % cluster_info_json['version'])
        print ("Time Zone: %s \n" % cluster_info_json['timezone']['timezone'])
        qa_report.write("Cluster Name: %s \n" % cluster_info_json['name'])
        qa_report.write("Rubrik Cluster ID : %s \n" % cluster_info_json['id'])
        qa_report.write("Cluster Version: %s \n" % cluster_info_json['version'])
        qa_report.write("Time Zone: %s \n \n" % cluster_info_json['timezone']['timezone'])
    elif response_cluster_info.status_code == 422:
        print ("422 - Incorrect username or Password. Please check your credentials and run the script again! \n")
        qa_report.write("422 - Incorrect username or Password. Please check your credentials and run the script again! \n \n")
        exit()
    else:
        print(response_cluster_info.status_code)
        print(response_cluster_info.text)
        exit()
except Exception as e:
    print (e)

##### DNS Settings of Rubrik Cluster #####
CLUSTER_DNS = CLUSTER_API_ENDPOINT_BASE_INTERNAL + "cluster/" + rubrik_id + "/dns_nameserver"
#print (CLUSTER_DNS)
try:
    response_dns_info = req.get(CLUSTER_DNS, headers=HTTP_REQUEST_HEADERS, verify=False)
    dns_info_json = response_dns_info.json()
    if response_dns_info.status_code == 200:
        index = 1
        value = 1
        print (color.BOLD + "DNS Information" + color.END)
        qa_report.write("~~~~~DNS Information~~~~~ \n")
        if value > 0:
            for itm in dns_info_json['data']:
                print ("DNS Server-%i: %s" % (index,itm))
                qa_report.write("DNS Server-%i: %s \n" % (index,itm))
                index += 1
                value -= 1
    elif response_dns_info.status_code == 422:
        print ("422 - Incorrect username or Password. Please check your credentials and run the script again! \n")
        qa_report.write("422 - Incorrect username or Password. Please check your credentials and run the script again! \n \n")
        exit()
    else:
        print(response_dns_info.status_code)
        print(response_cluster_info.text)
        exit()

except Exception as e:
    print (e)


##### NTP Settings of Rubrik Cluster #####
CLUSTER_NTP = CLUSTER_API_ENDPOINT_BASE_INTERNAL +"cluster/" + rubrik_id + "/ntp_server"
try:
    response_ntp_info = req.get(CLUSTER_NTP, headers=HTTP_REQUEST_HEADERS, verify=False)
    ntp_info_json = response_ntp_info.json()
    if response_ntp_info.status_code == 200:
        index = 1
        value = 1
        print ("\n")
        qa_report.write("\n")
        print (color.BOLD + "NTP Information" + color.END)
        qa_report.write("~~~~~ NTP Information ~~~~~ \n")
        if value > 0:
            for itm in ntp_info_json['data']:
                print ("NTP Server-%i: %s" % (index,itm))
                qa_report.write("NTP Server-%i: %s \n" % (index,itm))
                index += 1
                value -= 1
    elif response_ntp_info.status_code == 422:
        print ("422 - Incorrect username or Password. Please check your credentials and run the script again! \n")
        qa_report.write("422 - Incorrect username or Password. Please check your credentials and run the script again! \n \n")
        exit()
    else:
        print(response_ntp_info.status_code)
        print(response_ntp_info.text)
        exit()
except Exception as e:
    print (e)

##### List number of briks in Rubrik cluster #####
CLUSTER_BRIKS_COUNT = CLUSTER_API_ENDPOINT_BASE_INTERNAL + "cluster/" + rubrik_id + "/brik_count"
#print (color.BOLD + "Briks Information" + color.END)
try:
    response_briks_count = req.get(CLUSTER_BRIKS_COUNT, headers=HTTP_REQUEST_HEADERS, verify=False)
    cluster_briks_count_json = response_briks_count.json()
    if response_briks_count.status_code == 200:
        print ("\nTotal Number of Briks in this Rubrik Cluster: %s \n" % cluster_briks_count_json['count'])
        qa_report.write("\nTotal Number of Briks in this Rubrik Cluster: %s \n \n" % cluster_briks_count_json['count'])
    elif response_briks_count.status_code == 422:
        print ("422 - Incorrect username or Password. Please check your credentials and run the script again! \n")
        qa_report.write("422 - Incorrect username or Password. Please check your credentials and run the script again! \n \n")
        exit()
    else:
        print(response_briks_count.status_code)
        print(response_briks_count.text)
        exit()
except Exception as e:
    print (e)

##### List information of individual briks #####
CLUSTER_NODE_INFO = CLUSTER_API_ENDPOINT_BASE_INTERNAL + "cluster/" + rubrik_id + "/node"
try:
    response_node_info = req.get(CLUSTER_NODE_INFO, headers=HTTP_REQUEST_HEADERS, verify=False)
    node_info_json = response_node_info.json()
    if response_node_info.status_code == 200:
        number_of_nodes = node_info_json['total']
        i = 1
        for itm in (node_info_json['data']):
            print (color.BOLD + "~~~~~ Brik - %s Information ~~~~~" % str(i) + color.END)
            qa_report.write("~~~~~ Brik - %s Information ~~~~~ \n" % str(i))
            i +=1
            print ("id: %s" % itm['id'])
            qa_report.write("id: %s \n" % itm['id'])
            print ("brikId: %s" % itm['brikId'])
            qa_report.write("brikId: %s\n" % itm['brikId'])
            print ("IP Address: %s" % itm['ipAddress'])
            qa_report.write("IP Address: %s \n" % itm['ipAddress'])
            print ("Status: %s" % itm['status'])
            qa_report.write("Status: %s \n" % itm['status'])
            if itm['supportTunnel']['isTunnelEnabled'] == False:
                print (color.BOLD + color.GREEN + "Support Tunnel Enabled? %s \n" % itm['supportTunnel']['isTunnelEnabled'] + color.END)
                qa_report.write("Support Tunnel Enabled? %s \n \n" % itm['supportTunnel']['isTunnelEnabled'])
            elif itm['supportTunnel']['isTunnelEnabled'] == True:
                print (color.BOLD + color.RED + "Support Tunnel Enabled? %s \n" % itm['supportTunnel']['isTunnelEnabled'] + color.END)
                qa_report.write("Support Tunnel Enabled? %s \n \n" % itm['supportTunnel']['isTunnelEnabled'])
    elif response_briks_count.status_code == 422:
        print ("422 - Incorrect username or Password. Please check your credentials and run the script again! \n")
        qa_report.write("422 - Incorrect username or Password. Please check your credentials and run the script again!")
        exit()
    else:
        print(response_node_info.status_code)
        print(response_node_info.text)
        exit()
except Exception as e:
    print (e)

##### List disk information of the Rubrik Cluster #####
CLUSTER_DISK_INFO = CLUSTER_API_ENDPOINT_BASE_INTERNAL + "cluster/" + rubrik_id + "/disk"
number_of_hdd_disks = 0
number_of_flash_disks = 0
try:
    response_disk_info = req.get(CLUSTER_DISK_INFO, headers=HTTP_REQUEST_HEADERS, verify=False)
    disk_info_json = response_disk_info.json()
    if response_disk_info.status_code == 200:
        i = 1
        print (color.BOLD + "***************************** Disk Configuration of Rubrik Cluster: %s ***************************** \n" % mip_rubrik + color.END)
        qa_report.write("***************************** Disk Configuration of Rubrik Cluster: %s ***************************** \n \n" % mip_rubrik)
        print ("Total number of disks in the Rubrik Cluster = %s \n" % disk_info_json['total'])
        qa_report.write("Total number of disks in the Rubrik Cluster = %s \n \n" % disk_info_json['total'])

        for itm in (disk_info_json['data']):
            print (color.BOLD + "~~~~~ Disk - %s Information ~~~~~" % str(i) + color.END)
            qa_report.write("~~~~~ Disk - %s Information ~~~~~ \n" % str(i))
            i +=1
            print ("Disk Type: %s" % itm['diskType'])
            qa_report.write("Disk Type: %s \n" % itm['diskType'])
            if itm['diskType'] == 'HDD':
                number_of_hdd_disks += 1
            elif itm['diskType'] == 'FLASH':
                number_of_flash_disks += 1
            print ("Status: %s" % itm['status'])
            qa_report.write("Status: %s \n" % itm['status'])
            if itm['isEncrypted'] == True:
                print (color.BOLD + color.GREEN + "Encrypted? %s" % itm['isEncrypted'] + color.END)
                qa_report.write("Encrypted? %s \n" % itm['isEncrypted'])
            elif itm['isEncrypted'] == False:
                print (color.BOLD + color.RED + "Encrypted? %s" % itm['isEncrypted'] + color.END)
                qa_report.write("Encrypted? %s \n" % itm['isEncrypted'])
            if itm['capacityBytes'] == 9921898119168:
                print ("Capacity: %s \n" % '10TB')
                qa_report.write("Capacity: %s \n \n" % '10TB')
            elif itm['capacityBytes'] == 1574597586944:
                print ("Capacity: %s \n" % '1.6TB')
                qa_report.write("Capacity: %s \n \n" % '1.6TB')
        qa_report.write("\n")
        if number_of_hdd_disks < 12:
            print(color.BOLD + color.RED + "Number of HDDs = %s --> FAIL" % str(number_of_hdd_disks) + color.END)
            qa_report.write("Number of HDDs = %s --> FAIL \n" % str(number_of_hdd_disks))
        else:
            print(color.BOLD + color.GREEN + "Number of HDDs = %s --> PASS" % str(number_of_hdd_disks) + color.END)
            qa_report.write("Number of HDDs = %s --> PASS \n" % str(number_of_hdd_disks))
        if number_of_flash_disks < 4:
            print(color.BOLD + color.RED + "Number of SSDs = %s --> FAIL \n" % str(number_of_flash_disks) + color.END)
            qa_report.write("Number of SSDs = %s --> FAIL \n" % str(number_of_flash_disks))
        else:
            print(color.BOLD + color.GREEN + "Number of SSDs = %s --> PASS\n" % str(number_of_flash_disks) + color.END)
            qa_report.write("Number of SSDs = %s --> PASS \n \n" % str(number_of_flash_disks))

    elif response_disk_info.status_code == 422:
        print ("422 - Incorrect username or Password. Please check your credentials and run the script again! \n")
        qa_report.write("422 - Incorrect username or Password. Please check your credentials and run the script again! \n \n")
        exit()
    else:
        print(response_disk_info.status_code)
        print(response_disk_info.text)
        exit()
except Exception as e:
    print (e)

##### List the vCenters connected to the Rubrik Cluster #####
CLUSTER_VC_INFO = CLUSTER_API_ENDPOINT_BASE + "vmware/vcenter"
i = 1 #Initialize the number of vCenters connected to Rubrik to 0.
try:
    response_vc_info = req.get(CLUSTER_VC_INFO, headers=HTTP_REQUEST_HEADERS, verify=False)
    vc_info_json = response_vc_info.json()
    if response_vc_info.status_code == 200:
        print (color.BOLD + "***************************** List of vCenters connected to Rubrik Cluster: %s ***************************** \n \n" % mip_rubrik + color.END)
        qa_report.write("***************************** List of vCenters connected to Rubrik Cluster: %s ***************************** \n \n" % mip_rubrik)
        for itm in vc_info_json['data']:
            print (color.BOLD + "vCenter-%s: " % str(i) + color.END)
            qa_report.write("vCenter-%s: \n" % str(i))
            print ("Name- %s" % itm['name'])
            qa_report.write("Name- %s \n" % itm['name'])
            print ("vCenter Id as per Rubrik- %s \n" % itm['id'])
            qa_report.write("vCenter Id as per Rubrik- %s \n \n" % itm['id'])
            i += 1
    elif response_vc_info.status_code == 422:
        print ("422 - Incorrect username or Password. Please check your credentials and run the script again! \n")
        qa_report.write("422 - Incorrect username or Password. Please check your credentials and run the script again! \n \n")
        exit()
    else:
        print(response_vc_info.status_code)
        print(response_vc_info.text)
        exit()
except Exception as e:
    print (e)

print (color.BOLD + "***************************** Summary for Rubrik Cluster: %s ***************************** \n" % mip_rubrik + color.END)
qa_report.write("***************************** Summary for Rubrik Cluster: %s ***************************** \n \n" % mip_rubrik)

print ("Please check for anything in " + color.BOLD + color.RED + "RED" + color.END + ".\n")
print ("Make sure that the DNS and NTP servers are setup, Support Tunnel is Disabled and Encryption has been enabled.")
qa_report.write("Make sure that the DNS and NTP servers are setup, Support Tunnel is Disabled and Encryption has been enabled \n \n")

print ("########################################################################################################### \n \n")
qa_report.write("########################################################################################################### \n \n")
qa_report.close()
