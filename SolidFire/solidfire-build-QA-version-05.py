import re ###Used for Regular Expressions
import json
import requests
import sys
import paramiko
#import urllib.request
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
print ("Enter the MVIP of SolidFire Cluster")
#mvip_solidfire = raw_input() ##This only works with Python version 2.7
mvip_solidfire = input() ##This only works with Python version 3.x
print ("Enter Username: ")
#usrname = raw_input() ##This only works with Python version 2.7
usrname = input() ##This only works with Python version 3.x
passwd = getpass("Enter Password: ")

##Get input from user: IP Address of the SolidFire Management Node.
##This is needed to get the public IP of the management node, which will be used to confirm if this SolidFire cluster is added to ActiveIQ
print ("Enter the IP Address of the SolidFire Management Node")
mgmt_node_ip_solidfire = input()
print ("Enter Username for the SolidFire Management Node: ")
usrname_mgmt_node = input()
passwd_mgmt_node = getpass("Enter Password for the SolidFire Management Node:")

req.auth = (usrname, passwd)
req.headers.update(HTTP_REQUEST_HEADERS)

print ("########################################################################################################### \n")

#Declaring the API End Point for SolidFire using its 'mvip'
CLUSTER_API_ENDPOINT = "https://" + mvip_solidfire + "/json-rpc/10.0"

datestring = datetime.strftime(datetime.now(), '%Y-%m-%d_%H-%M-%S')
qa_report = open("SolidFire_QA_output_" + mvip_solidfire + "_" + datestring + ".txt", "w+")
print ("Script Version --> 05 \n")
print ("Script last modified on 12/06/19 \n")
print ("Author: Nishant Konduru \n")
qa_report.write("Script Version --> 05 \n")
qa_report.write("Script last modified on 12/06/19 \n")
qa_report.write("Author: Nishant Konduru \n")


#Declaring the payloads required
list_volumes_payload = {"method": "ListActiveVolumes", "params":{"includeVirtualVolumes": "false"}, "id": 1}
cluster_info_payload = {"method": "GetClusterInfo", "params":{}, "id": 1}
cluster_version_payload = {"method": "GetClusterVersionInfo", "params":{}, "id": 1}
list_active_nodes_payload = {"method": "ListActiveNodes", "params":{}, "id": 1}
volume_accessgroups_payload = {"method": "ListVolumeAccessGroups", "params":{}, "id": 1}
get_node_nw_config_payload = {"method": "GetNetworkConfig", "params":{}, "id": 1}
get_drives_per_node_payload = {"method": "GetDriveConfig", "params":{}, "id": 1}


print ("***************************** Cluster Information for SolidFire: %s *****************************\n " % mvip_solidfire)
qa_report.write("***************************** Cluster Information for SolidFire: %s ***************************** \n \n" % mvip_solidfire)

try:
    ##########GetClusterInfo##########
    response_cluster_info = req.post(CLUSTER_API_ENDPOINT, data=json.dumps(cluster_info_payload), headers=HTTP_REQUEST_HEADERS, verify=False)
    cluster_info_json = response_cluster_info.json()
    ##########GetClusterVersionInfo##########
    response_cluster_version = req.post(CLUSTER_API_ENDPOINT, data=json.dumps(cluster_version_payload), headers=HTTP_REQUEST_HEADERS, verify=False)
    cluster_version_json = response_cluster_version.json()
    if response_cluster_info.status_code == 200:
        print ("200 OK - Session Established \n")
        qa_report.write("200 OK - Session Established \n \n")
except Exception as e:
    if response_cluster_info.status_code == 401:
        print ("401 - User not authorized. Please check your credentials and run the script again! \n")
        qa_report.write("401 - User not authorized. Please check your credentials and run the script again! \n \n")
print ("Cluster Name: %s" % cluster_info_json['result']['clusterInfo']['name'])
print ("Cluster Version: %s" % cluster_version_json['result']['clusterVersion'])
qa_report.write("Cluster Name: %s \n" % cluster_info_json['result']['clusterInfo']['name'])
solidfire_cluster_name = cluster_info_json['result']['clusterInfo']['name']
qa_report.write("Cluster Version: %s \n" % cluster_version_json['result']['clusterVersion'])

if (cluster_info_json['result']['clusterInfo']['encryptionAtRestState']) == "enabled":
    print (color.GREEN + color.BOLD + "Encryption at Rest State: %s -----> PASS \n" % cluster_info_json['result']['clusterInfo']['encryptionAtRestState'] + color.END)
    qa_report.write("Encryption at Rest State: %s -----> PASS \n" % cluster_info_json['result']['clusterInfo']['encryptionAtRestState'])
else:
    print (color.RED + color.BOLD + "Encryption at Rest State: %s -----> FAIL \n" % cluster_info_json['result']['clusterInfo']['encryptionAtRestState'] + color.END)
    qa_report.write("Encryption at Rest State: %s -----> FAIL \n" % cluster_info_json['result']['clusterInfo']['encryptionAtRestState'])
qa_report.write('\n \n')

print ("########################################################################################################### \n")
qa_report.write("########################################################################################################### \n \n")

print  ("***************************** Node Information for SolidFire: %s ***************************** \n" % mvip_solidfire)
qa_report.write("***************************** Node Information for SolidFire: %s ***************************** \n \n" % mvip_solidfire)

nodes = [] #Initializing the nodes variable
number_of_fc_nodes = 0 #Initializing the number of FC Nodes variable to 0. We will increment it for every FC node encountered in the SolidFire Cluster.
try:
    ##########GetNodeInfo##########
    response_node_info = req.post(CLUSTER_API_ENDPOINT, data=json.dumps(list_active_nodes_payload), headers=HTTP_REQUEST_HEADERS, verify=False)
    node_info_json = response_node_info.json()
    if response_node_info.status_code == 200:
        print ("200 OK - Session Established \n")
        qa_report.write("200 OK - Session Established \n \n")
except Exception as e:
    if response_node_info.status_code == 401:
        print ("401 - User not authorized. Please check your credentials and run the script again! \n")
        qa_report.write("401 - User not authorized. Please check your credentials and run the script again! \n \n")
for itm in node_info_json['result']['nodes']:
    print ("Node Name: %s" % itm['name'])
    print ("Management IP of Node(1G): %s" % itm['mip'])
    print ("Storage IP of Node(10G): %s" % itm['cip'])
    print ("Node Type: %s" % itm['platformInfo']['nodeType'])
    nodes.append(itm['mip'])
    qa_report.write("Node Name: %s" % itm['name'])
    qa_report.write('\n')
    qa_report.write("Management IP of Node(1G): %s" % itm['mip'])
    qa_report.write('\n')
    qa_report.write("Storage IP of Node(10G): %s" % itm['cip'])
    qa_report.write('\n')
    qa_report.write("Node Type: %s" % itm['platformInfo']['nodeType'])
    if itm['platformInfo']['nodeType'] == "FCN*":
        number_of_fc_nodes += 1
    print ("\n")
    qa_report.write('\n \n')
print ("########################################################################################################### \n")
qa_report.write("########################################################################################################### \n \n")

print ("***************************** Network Configuration of Nodes on SolidFire: %s ***************************** \n" % mvip_solidfire)
qa_report.write("***************************** Network Configuration of Nodes on SolidFire: %s ***************************** \n \n" % mvip_solidfire)

for i in range(len(nodes) - number_of_fc_nodes):
    #print 'NODE-%s: %s' % (i+1,nodes[i])
    print (color.BOLD + "NODE-%s: %s" % (i+1,nodes[i]) + color.END)
    qa_report.write("NODE-%s: %s \n" % (i+1,nodes[i]))
    #Declaring the API End Point for SolidFire Nodes using its 'mip'
    NODE_API_ENDPOINT = "https://" + nodes[i] + ":442" + "/json-rpc/10.0"
    try:
        ###################GetNetworkConfig per Node########################
        response_node_nw_config = req.post(NODE_API_ENDPOINT, data=json.dumps(get_node_nw_config_payload), headers=HTTP_REQUEST_HEADERS, verify=False)
        node_nw_config_json = response_node_nw_config.json()
        if response_node_nw_config.status_code == 200:
            print ("200 OK - Session Established \n \n")
            qa_report.write("200 OK - Session Established \n \n")
    except Exception as e:
        if response_node_nw_config.status_code == 401:
            print ("401 - User not authorized. Please check your credentials and run the script again! \n")
            qa_report.write("401 - User not authorized. Please check your credentials and run the script again! \n \n")
    #Printing the network config of 1G Bond of each node
    print ("a)BOND-1G: ")
    print ("    Up And Running? -----> %s" % node_nw_config_json['result']['network']['Bond1G']['physical']['upAndRunning'])
    print ("    Address: %s" % node_nw_config_json['result']['network']['Bond1G']['address'])
    print ("    Bond Slaves: %s" % node_nw_config_json['result']['network']['Bond1G']['bond-slaves'])
    print ("    Bond Mode: %s" % node_nw_config_json['result']['network']['Bond1G']['bond-mode'])
    print ("    Gateway: %s" % node_nw_config_json['result']['network']['Bond1G']['gateway'])
    print ("    MTU: %s" % node_nw_config_json['result']['network']['Bond1G']['mtu'])
    print ("    Netmask: %s" % node_nw_config_json['result']['network']['Bond1G']['netmask'])
    print ("    DNS Server: %s \n" % node_nw_config_json['result']['network']['Bond1G']['dns-nameservers'])
    #Writing the network config of 10G Bond of each node to the Solidfire Build-QA report file
    qa_report.write("a)BOND-1G: \n")
    qa_report.write("   Up And Running? -----> %s \n" % node_nw_config_json['result']['network']['Bond1G']['physical']['upAndRunning'])
    qa_report.write("   Address: %s \n" % node_nw_config_json['result']['network']['Bond1G']['address'])
    qa_report.write("   Bond Slaves: %s \n" % node_nw_config_json['result']['network']['Bond1G']['bond-slaves'])
    qa_report.write("   Bond Mode: %s \n" % node_nw_config_json['result']['network']['Bond1G']['bond-mode'])
    qa_report.write("   Gateway: %s \n" % node_nw_config_json['result']['network']['Bond1G']['gateway'])
    qa_report.write("   MTU: %s \n" % node_nw_config_json['result']['network']['Bond1G']['mtu'])
    qa_report.write("   Netmask: %s \n" % node_nw_config_json['result']['network']['Bond1G']['netmask'])
    qa_report.write("   DNS Server: %s \n \n" % node_nw_config_json['result']['network']['Bond1G']['dns-nameservers'])
    #Printing the network config of 10G Bond of each node
    print ("b)BOND-10G: ")
    print ("    Up And Running? -----> %s" % node_nw_config_json['result']['network']['Bond10G']['physical']['upAndRunning'])
    print ("    Address: %s" % node_nw_config_json['result']['network']['Bond10G']['address'])
    print ("    Bond Slaves: %s" % node_nw_config_json['result']['network']['Bond10G']['bond-slaves'])
    print ("    Bond Mode: %s" % node_nw_config_json['result']['network']['Bond10G']['bond-mode'])
    print ("    Gateway: %s" % node_nw_config_json['result']['network']['Bond10G']['gateway'])
    print ("    MTU: %s" % node_nw_config_json['result']['network']['Bond10G']['mtu'])
    print ("    Netmask: %s" % node_nw_config_json['result']['network']['Bond10G']['netmask'])
    print ("    DNS Server: %s" % node_nw_config_json['result']['network']['Bond10G']['dns-nameservers'])
    print ("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
    #Writing the network config of 10G Bond of each node to the Solidfire Build-QA report file
    qa_report.write("b)Bond-10G \n")
    qa_report.write("   Up And Running? -----> %s \n" % node_nw_config_json['result']['network']['Bond10G']['physical']['upAndRunning'])
    qa_report.write("   Address: %s \n" % node_nw_config_json['result']['network']['Bond10G']['address'])
    qa_report.write("   Bond Slaves: %s \n" % node_nw_config_json['result']['network']['Bond10G']['bond-slaves'])
    qa_report.write("   Bond Mode: %s \n" % node_nw_config_json['result']['network']['Bond10G']['bond-mode'])
    qa_report.write("   Gateway: %s \n" % node_nw_config_json['result']['network']['Bond10G']['gateway'])
    qa_report.write("   MTU: %s \n" % node_nw_config_json['result']['network']['Bond10G']['mtu'])
    qa_report.write("   Netmask: %s \n" % node_nw_config_json['result']['network']['Bond10G']['netmask'])
    qa_report.write("   DNS Server: %s \n \n" % node_nw_config_json['result']['network']['Bond10G']['dns-nameservers'])
    qa_report.write("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n \n")

print ("########################################################################################################### \n")
qa_report.write("########################################################################################################### \n \n")

print ("***************************** Drive Information on SolidFire: %s ***************************** \n" % mvip_solidfire)
qa_report.write("***************************** Drive Information on SolidFire: %s ***************************** \n \n" % mvip_solidfire)

for i in range((len(nodes))-2):
    #print 'NODE-%s: %s' % (i+1,nodes[i])
    print (color.BOLD + "NODE-%s: %s" % (i+1,nodes[i]) + color.END)
    qa_report.write("NODE-%s: %s \n" % (i+1,nodes[i]))
    #Declaring the API End Point for SolidFire Nodes using its 'mip'
    NODE_API_ENDPOINT = "https://" + nodes[i] + ":442" + "/json-rpc/10.0"
    try:
        #GetDriveConfig per SolidFire Node. ####Here we don't check the number of drives on FC nodes as they won't have any drives on it
        response_drives_per_node = req.post(NODE_API_ENDPOINT, data=json.dumps(get_drives_per_node_payload), headers=HTTP_REQUEST_HEADERS, verify=False)
        drives_per_node_json = response_drives_per_node.json()
        if response_drives_per_node.status_code == 200:
            print ("200 OK - Session Established")
            qa_report.write("200 OK - Session Established \n")
    except Exception as e:
        if response_drives_per_node.status_code == 401:
            print ("401 - User not authorized. Please check your credentials and run the script again!")
            qa_report.write("401 - User not authorized. Please check your credentials and run the script again! \n \n")
    # z = drives_per_node_json['result']['driveConfig']['drives']
    expected_nodes = drives_per_node_json['result']['driveConfig']['numTotalExpected']
    actual_nodes = drives_per_node_json['result']['driveConfig']['numTotalActual']
    if expected_nodes == actual_nodes:
        print (color.GREEN + color.BOLD + "Number of Drives = %s -----> PASS since expected and actual node count is %s \n" %(actual_nodes,actual_nodes) + color.END)
        qa_report.write("Number of Drives = %s -----> PASS since expected and actual node count is %s \n \n" %(actual_nodes,actual_nodes))
    else:
        print (color.RED + color.BOLD + "Number of Drives = %s -----> FAIL since the expected nodes should be %s \n" %(actual_nodes,expected_nodes) + color.END)
        qa_report.write("Number of Drives = %s -----> FAIL since the expected nodes should be %s \n \n" %(actual_nodes,expected_nodes))

print ("########################################################################################################### \n")
qa_report.write("########################################################################################################### \n \n")

print ("***************************** Volume Access Groups on SolidFire: %s ***************************** \n" % mvip_solidfire)
qa_report.write("***************************** Volume Access Groups on SolidFire: %s ***************************** \n \n" % mvip_solidfire)

try:
    ##########ListVolumeAccessGroups##########
    response_volume_accessgroups = req.post(CLUSTER_API_ENDPOINT, data=json.dumps(volume_accessgroups_payload), headers=HTTP_REQUEST_HEADERS, verify=False)
    volume_accessgroups_json = response_volume_accessgroups.json()
    if response_volume_accessgroups.status_code == 200:
        print ("200 OK - Session Established \n")
        qa_report.write("200 OK - Session Established \n \n")
except Exception as e:
    if response_volume_accessgroups.status_code == 401:
        print ("401 - User not authorized. Please check your credentials and run the script again! \n")
        qa_report.write("401 - User not authorized. Please check your credentials and run the script again! \n \n")
for itm in volume_accessgroups_json['result']['volumeAccessGroups']:
    print ("Volume Access Group: %s" % itm['name'])
    qa_report.write("Volume Access Group: %s \n" % itm['name'])
    print ("Volume Access GroupID: %s" % itm['volumeAccessGroupID'])
    qa_report.write("Volume Access GroupID: %s \n \n" % itm['volumeAccessGroupID'])
    print ("\n")
    #qa_report.write('\n \n')

print ("########################################################################################################### \n")
qa_report.write("########################################################################################################### \n \n")

print ("***************************** Volumes Information on SolidFire: %s ***************************** \n \n" % mvip_solidfire)
qa_report.write("***************************** Volumes Information on SolidFire: %s ***************************** \n \n" % mvip_solidfire)

try:
    ##########ListActiveVolumes##########
    response_volumes = req.post(CLUSTER_API_ENDPOINT, data=json.dumps(list_volumes_payload), headers=HTTP_REQUEST_HEADERS, verify=False)
    list_volumes_json = response_volumes.json()
    if response_volumes.status_code == 200:
        print ("200 OK - Session Established \n")
        qa_report.write("200 OK - Session Established \n \n")
except Exception as e:
    if response_volumes.status_code == 401:
        print ("401 - User not authorized. Please check your credentials and run the script again! \n")
        qa_report.write("401 - User not authorized. Please check your credentials and run the script again! \n \n")
print ("Total Active Volumes: %i \n" % len(list_volumes_json['result']['volumes']))
qa_report.write("Total Active Volumes: %i \n \n" % len(list_volumes_json['result']['volumes']))
for itm in list_volumes_json['result']['volumes']:
    print ("Volume Name: %s" % itm['name'])
    qa_report.write("Volume Name: %s" % itm['name'])
    qa_report.write('\n')
    qa_report.write("VolumeID: %s" % itm['volumeID'])
    qa_report.write('\n')
    for itm2 in itm['volumeAccessGroups']:
        print ("VolumeAccessGroupID: %s" % itm2)
        qa_report.write("VolumeAccessGroupID: %s" % itm2)
    qa_report.write('\n')
    if itm['enable512e'] == True:
        print (color.GREEN + color.BOLD + "Enabled-512e: %s -----> PASS" % itm['enable512e'] + color.END)
        qa_report.write("Enabled-512e: %s -----> PASS" % itm['enable512e'])
    else:
        print (color.RED + color.BOLD + "Enabled-512e: %s -----> FAIL" % itm['enable512e'] + color.END)
        qa_report.write("Enabled-512e: %s -----> FAIL" % itm['enable512e'])
    qa_report.write('\n')
    if (itm['qos']['maxIOPS']) == 75000:
        print (color.GREEN + color.BOLD + "Max IOPS: %s -----> PASS for PIOPS" % itm['qos']['maxIOPS'] + color.END)
        qa_report.write("Max IOPS: %s -----> PASS for PIOPS" % itm['qos']['maxIOPS'])
    elif (itm['qos']['maxIOPS']) == 68000:
        print (color.GREEN + color.BOLD + "Max IOPS: %s -----> PASS for HP" % itm['qos']['maxIOPS'] + color.END)
        qa_report.write("Max IOPS: %s -----> PASS for HP" % itm['qos']['maxIOPS'])
    elif (itm['qos']['maxIOPS']) == 52000:
        print (color.GREEN + color.BOLD + "Max IOPS: %s -----> PASS for STD-ECO" % itm['qos']['maxIOPS'] + color.END)
        qa_report.write("Max IOPS: %s -----> PASS for STD-ECO" % itm['qos']['maxIOPS'])
    else:
        print (color.RED + color.BOLD + "Max IOPS: %s -----> FAIL" % itm['qos']['maxIOPS'] + color.END)
        qa_report.write("Max IOPS: %s -----> FAIL" % itm['qos']['maxIOPS'])
    qa_report.write('\n')
    if (itm['qos']['minIOPS']) == 1000:
        print (color.GREEN + color.BOLD + "Min IOPS: %s -----> PASS" % itm['qos']['minIOPS'] + color.END)
        qa_report.write("Min IOPS: %s -----> PASS" % itm['qos']['minIOPS'])
    else:
        print (color.RED + color.BOLD + "Min IOPS: %s -----> FAIL" % itm['qos']['minIOPS'] + color.END)
        qa_report.write("Min IOPS: %s -----> FAIL" % itm['qos']['minIOPS'])
    print ("\n")
    qa_report.write('\n \n')
print ("########################################################################################################### \n \n")
qa_report.write("########################################################################################################### \n \n")

print ("***************************** PublicIP Information for SolidFire: %s ***************************** \n \n" % mvip_solidfire)
qa_report.write("***************************** PublicIP Information for SolidFire: %s ***************************** \n \n" % mvip_solidfire)

ssh = paramiko.SSHClient()
ssh.load_system_host_keys()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
##### Printing the Public IP of the SolidFire Management Node
try:
    ssh.connect(hostname=mgmt_node_ip_solidfire, username=usrname_mgmt_node, password=passwd_mgmt_node)
    print ("SSH connection established to the Management Node \n")
    qa_report.write("SSH connection established to the Management Node \n \n")
    stdin,stdout,stderr = ssh.exec_command("publicip")
    for line in stdout.readlines():
        # if line.strip() == "nameserver*":
        #     print ("Existing DNS info for Management Node: %s" % line.strip())
        # else:
        #     print (line.strip())
        print (color.BLUE + color.BOLD + "Public IP Address: %s \n" % line.strip() + color.END)
        print (color.BOLD + "Use the above Public IP address to have the SolidFire cluster: %s added to ActiveIQ \n" % solidfire_cluster_name + color.END)
        #
        # #print ("Existing DNS info for Management Node: %s" % line.strip())
        qa_report.write("Public IP Address: %s \n \n" % line.strip()) #Writing the response from publicip command to the text file
        qa_report.write("Use the above Public IP address to have the SolidFire cluster: %s added to ActiveIQ \n \n" % solidfire_cluster_name)
    ssh.close()
except paramiko.AuthenticationException:
    print ("Authentication Failed \n")
    qa_report.write("Authentication Failed \n \n")
    quit()
except:
    print("Unknown Error \n")
    qa_report.write("Unknown Error \n \n")
    quit()
print ("########################################################################################################### \n \n")
qa_report.write("########################################################################################################### \n \n")

print ("***************************** Existing DNS Servers of SolidFire Management Node: %s ***************************** \n \n" % mgmt_node_ip_solidfire)
qa_report.write("***************************** Existing DNS Servers of SolidFire Management Node: %s ***************************** \n \n" % mgmt_node_ip_solidfire)
##### Printing the DNS Information of the SolidFire Management Node
try:
    ssh.connect(hostname=mgmt_node_ip_solidfire, username=usrname_mgmt_node, password=passwd_mgmt_node)
    #print ("SSH connection established to the Management Node of the SolidFire Cluster: %s  \n" % mgmt_node_ip_solidfire)
    print ("SSH connection established to the Management Node \n")
    #qa_report.write("SSH connection established to the Management Node of the SolidFire Cluster: %s  \n \n" % mgmt_node_ip_solidfire)
    qa_report.write("SSH connection established to the Management Node \n \n")
    stdin,stdout,stderr = ssh.exec_command("cat /etc/resolv.conf")
    for line in stdout.readlines():
         if re.search(r'nameserver', line):
             print (color.BLUE + color.BOLD + line + color.END)
             qa_report.write(line)
             qa_report.write('\n')
    ssh.close()
except paramiko.AuthenticationException:
    print ("Authentication Failed \n")
    qa_report.write("Authentication Failed \n \n")
    quit()
except:
    print("Unknown Error \n")
    qa_report.write("Unknown Error \n \n")
    quit()
print ("\n")
qa_report.write('\n \n')
print ("########################################################################################################### \n \n")
qa_report.write("########################################################################################################### \n \n")
qa_report.close()
