#import re ###Used for Regular Expressions
import json
import requests
#import sys
from getpass import getpass
#from collections import defaultdict
#from datetime import date,datetime

###Adding 'color' class to be used for printing in color
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
print ("Enter the MVIP of SolidFire Cluster")
#mvip_solidfire = raw_input() ##This only works with Python version 2.7
mvip_solidfire = input() ##This only works with Python version 3.x
print ("Enter Username: ")
#usrname = raw_input() ##This only works with Python version 2.7
usrname = input() ##This only works with Python version 3.x
passwd = getpass("Enter Password: ")

req.auth = (usrname, passwd)
req.headers.update(HTTP_REQUEST_HEADERS)

print ("########################################################################################################### \n")
print ("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~SolidFire IOPS Availability Script for %s~~~~~~~~~~~~~~~~~~~~ \n" % mvip_solidfire)
print ("########################################################################################################### \n")
#Declaring the API End Point for SolidFire using its 'mvip'
CLUSTER_API_ENDPOINT = "https://" + mvip_solidfire + "/json-rpc/10.0" ### For ElementOS version 11.0. This URL will work for 10.0 too
#datestring = datetime.strftime(datetime.now(), '%Y-%m-%d_%H-%M-%S')
#iops_avail_report = open("SolidFire_IOPS_Availability_" + mvip_solidfire + "_" + datestring + ".txt", "w+")

#Declaring the payloads required
list_all_nodes_payload = {"method": "ListAllNodes", "params":{}, "id": 1}
list_active_volumes_payload = {"method": "ListActiveVolumes", "params":{"includeVirtualVolumes": "false"}, "id": 1}

#Initializing the nodes variables
nodes_19210 = 0
nodes_38410 = 0
nodes_H610S_1 = 0
nodes_H610S_2 = 0
nodes_H610S_4 = 0
nodes_H400 = 0
nodes_SF4805 = 0
nodes_SF9605 = 0

try:
    ##########GetNodeInfo##########
    response_node_info = req.post(CLUSTER_API_ENDPOINT, data=json.dumps(list_all_nodes_payload), headers=HTTP_REQUEST_HEADERS, verify=False)
    node_info_json = response_node_info.json()
    #print (node_info_json)
    if response_node_info.status_code == 200:
        print ("200 OK - Session Established \n")
        print (color.UNDERLINE + color.BOLD + "Node Information:" + color.END)
except Exception as e:
    if response_node_info.status_code == 401:
        print ("401 - User not authorized. Please check your credentials and run the script again! \n")

for itm in node_info_json['result']['nodes']:
    print ("Node Name: %s" % itm['name'])
    print ("Node Type: %s \n" % itm['platformInfo']['nodeType'])
    if itm['platformInfo']['nodeType'] == "SF19210":
        nodes_19210 += 1
    elif itm['platformInfo']['nodeType'] == "SF38410":
        nodes_38410 += 1
    elif itm['platformInfo']['nodeType'] == "H610S1":
        nodes_H610S_1 += 1
    elif itm['platformInfo']['nodeType'] == "H610S2":
        nodes_H610S_2 += 1
    elif itm['platformInfo']['nodeType'] == "H610S4":
        nodes_H610S_4 += 1
    elif itm['platformInfo']['nodeType'] == "H400":
        nodes_H400 += 1
    elif itm['platformInfo']['nodeType'] == "SF4805":
        nodes_SF4805 += 1
    elif itm['platformInfo']['nodeType'] == "SF9605":
        nodes_SF9605 += 1

print ("\nTotal Number of SF19210 nodes = %s" % str(nodes_19210))
print ("Total Number of SF38410 nodes = %s" % str(nodes_38410))
print ("Total Number of H610S-1 nodes = %s" % str(nodes_H610S_1))
print ("Total Number of H610S-2 nodes = %s" % str(nodes_H610S_2))
print ("Total Number of H610S-4 nodes = %s" % str(nodes_H610S_4))
print ("Total Number of H400 nodes = %s" % str(nodes_H400))
print ("Total Number of SF4805 nodes = %s" % str(nodes_SF4805))
print ("Total Number of SF9605 nodes = %s \n" % str(nodes_SF9605))

#Creating a list with nodetype and counts
nodes = [nodes_19210, nodes_38410, nodes_H610S_1, nodes_H610S_2, nodes_H610S_4, nodes_H400, nodes_SF4805, nodes_SF9605]
node_iops_limit = [180000, 180000, 315000, 315000, 315000, 150000, 90000, 90000]
total_iops_allowed = (nodes_19210 * node_iops_limit[0]) + (nodes_38410 * node_iops_limit[1]) + (nodes_H610S_1 * node_iops_limit[2]) + (nodes_H610S_2 * node_iops_limit[3]) + (nodes_H610S_4 * node_iops_limit[4]) + (nodes_H400 * node_iops_limit[5]) + (nodes_SF4805 * node_iops_limit[6]) + (nodes_SF9605 * node_iops_limit[7])
print ("Total IOPS Allowed = %s \n" % str(total_iops_allowed))
total_iops_provisioned = 0 #Initializing Total IOPS provisioned to 0.
try:
    ##########GetListActiveVolumes##########
    response_active_volumes_info = req.post(CLUSTER_API_ENDPOINT, data=json.dumps(list_active_volumes_payload), headers=HTTP_REQUEST_HEADERS, verify=False)
    list_volumes_json = response_active_volumes_info.json()
    if response_active_volumes_info.status_code == 200:
        print ("200 OK - Session Established \n")
except Exception as e:
    if response_active_volumes_info.status_code == 401:
        print ("401 - User not authorized. Please check your credentials and run the script again! \n")
for itm in list_volumes_json['result']['volumes']:
    total_iops_provisioned = total_iops_provisioned + int(itm['qos']['maxIOPS'])
print ("Total IOPS Provisioned = %s \n" % str(total_iops_provisioned))
##Total IOPS Available
total_iops_available = total_iops_allowed - total_iops_provisioned
if (total_iops_available >= 0):
    print (color.GREEN + color.BOLD + "Total IOPS Available = %s \n \n" % str(total_iops_available) + color.END)
    x = int((total_iops_available)/75000)
    y = int((total_iops_available)/68000)
    z = int((total_iops_available)/52000)
    print (color.UNDERLINE + color.BOLD + "Following are the recommendations based on the Total Available IOPS at the moment:" + color.END)
    print (color.PURPLE + color.BOLD + "You can create %s PIOPS volumes or" % str(x) + color.END)
    print (color.CYAN + color.BOLD + "You can create %s HP volumes or" % str(y) + color.END)
    print (color.BLUE + color.BOLD + "You can create %s STD-ECO volumes \n" % str(z) + color.END)
elif (total_iops_available < 0) and (total_iops_available + 20000) == 0: #Allowing for oversubscription on the cluster. The oversubscription limit here is 20000 IOPS.
    print (color.RED + color.BOLD + "There are no available IOPS to provision new volumes. \n" + color.END)
else:
    print (color.RED + color.BOLD + "The cluster is oversubscribed at the moment. \n \n" + color.END)

print (color.BOLD + "NOTE-->" + color.END + "  Following are the current design guidelines for your reference:")
print (" 1)For PIOPS Volume, the max IOPS = 75,000")
print (" 2)For HP Volume, the max IOPS = 68,000")
print (" 3)For STD-ECO Volume, the max IOPS = 52,000 ")
print ("########################################################################################################### \n")
