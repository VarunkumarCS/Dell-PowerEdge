import argparse,getpass,logging,requests,sys,warnings
from tabulate import tabulate

warnings.filterwarnings("ignore")

parser = argparse.ArgumentParser(description="Python script using Redfish API to get the Health Information of the Server")
parser.add_argument('-ips', help='Pass in iDRAC IP addresses (comma-separated)', required=True)
parser.add_argument('-u', help='Pass in iDRAC username', required=True)
parser.add_argument('-p', help='Pass in iDRAC password. If not passed in, script will prompt to enter password which will not be echoed to the screen', required=False)
parser.add_argument('--ssl', help='Verify SSL certificate for all Redfish calls, pass in "true". This argument is optional, if you do not pass in this argument, all Redfish calls will ignore SSL cert checks.', required=False)
parser.add_argument('-x', help='Pass in iDRAC X-auth token session ID to execute all Redfish calls instead of passing in username/password', required=False)
parser.add_argument('--script-examples', help='Get executing script examples', action="store_true", dest="script_examples", required=False)
parser.add_argument('--information', help='Get all health information of the server', action="store_true", required=False)
parser.add_argument('--bios', help='Get all bios information of the server', action="store_true", required=False)
parser.add_argument('--firmware', help='Get all firmware information of the server', action="store_true", required=False)
parser.add_argument('--snmp', help='Get all snmp information of the server', action="store_true", required=False)
parser.add_argument('--snmp1', help='Get all snmp information of the server', action="store_true", required=False)
parser.add_argument('--all', help='Get all information of the server', action="store_true", required=False)

args = vars(parser.parse_args())
logging.basicConfig(format='%(message)s', stream=sys.stdout, level=logging.INFO)

def script_examples():
    print("""\n- python3 firmware.py -ips 10.2.57.101,10.2.57.102,10.2.57.103,10.2.57.104,10.2.57.105,10.2.57.106,10.2.57.107,10.2.57.108,10.2.57.109,10.2.57.110,10.2.57.111,10.2.57.112,10.2.57.113,10.2.57.114,10.2.57.115,10.2.57.116,10.2.57.117,10.2.57.118,10.2.57.119,10.2.57.120,10.2.57.121 -u USERID -p Chase123! --all, 
          this will get the information of the Servers.""")
    sys.exit(0)

def make_request(url, ip):
    headers = {'X-Auth-Token': args["x"]} if args["x"] else None
    auth = None if args["x"] else (idrac_username, idrac_password)

    response = requests.get(url, verify=verify_cert, headers=headers, auth=auth)
    return response

def check_supported_idrac_version(ip):
    response = make_request(f'https://{ip}/redfish/v1', ip)
    data = response.json()
    if response.status_code == 401:
        logging.warning(f"\n- WARNING, status code 401 detected for {ip}, check iDRAC username/password credentials")
        sys.exit(0)
    elif response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to validate iDRAC creds for {ip}, status code {response.status_code} returned.")
        logging.warning(data)
        sys.exit(0)

def information_of_server(ip):
    response = make_request(f'https://{ip}/redfish/v1/Managers/1/EthernetInterfaces/1', ip)
    data = response.json()

    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data)
        sys.exit(0)

    response = make_request(f'https://{ip}/redfish/v1/Systems/1/', ip)
    data1 = response.json()

    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data1)
        sys.exit(0)

    response = make_request(f'https://{ip}/redfish/v1/Managers/1/LicenseService/1', ip)
    data2 = response.json()

    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data2)
        sys.exit(0)

    response = make_request(f'https://{ip}/redfish/v1/Systems/1/', ip)
    data3 = response.json()

    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data3)
        sys.exit(0)

    response = make_request(f'https://{ip}/redfish/v1/Chassis/1', ip)
    data4 = response.json()
    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data4)
        sys.exit(0)

    return [data['IPv4Addresses'][0]['Address'], data1['SerialNumber'],data4['PowerState'],data2['ConfirmationRequest']['EON']['LicenseKey'],data3['Oem']['Hpe']['AggregateHealthStatus']['Processors']['Status']['Health'],
              data3['Oem']['Hpe']['AggregateHealthStatus']['Memory']['Status']['Health'],data3['Oem']['Hpe']['AggregateHealthStatus']['PowerSupplies']['Status']['Health'],
              data3['Oem']['Hpe']['AggregateHealthStatus']['Storage']['Status']['Health'],
              data3['Oem']['Hpe']['AggregateHealthStatus']['Fans']['Status']['Health'],data3['Oem']['Hpe']['AggregateHealthStatus']['Temperatures']['Status']['Health']]

def bios_information(ip):
    response = make_request(f'https://{ip}/redfish/v1/Managers/1/EthernetInterfaces/1', ip)
    data1 = response.json()

    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data1)
        sys.exit(0)

    response = make_request(f'https://{ip}/redfish/v1/systems/1/bios/settings/', ip)
    data3 = response.json()

    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data3)
        sys.exit(0)

    response = make_request(f'https://{ip}/redfish/v1/Managers/1/GUIService', ip)
    data4 = response.json()

    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data4)
        sys.exit(0)

    response = make_request(f'https://{ip}/redfish/v1/Systems/1/BootOptions/1', ip)
    data5 = response.json()

    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data5)
        sys.exit(0)

    return [data1['IPv4Addresses'][0]['Address'],data5['DisplayName'], data3['Attributes']['PostF1Prompt'], data3['Attributes']['RedundantPowerSupplySystemDomain'], 
              data3['Attributes']['PostAsr'], data4['TreeList'][8]['Text'], data3['Attributes']['BootOrderPolicy']]

def firmware_information(ip):
    response = make_request(f'https://{ip}/redfish/v1/Managers/1/EthernetInterfaces/1', ip)
    data1 = response.json()
    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data1)
        sys.exit(0)

    response = make_request(f'https://{ip}/redfish/v1/Systems/1/', ip)
    data2 = response.json()
    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data2)
        sys.exit(0)

    response = make_request(f'https://{ip}/redfish/v1/UpdateService/FirmwareInventory/1', ip)
    data3 = response.json()
    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data3)
        sys.exit(0)

    response = make_request(f'https://{ip}/redfish/v1/UpdateService/FirmwareInventory/2', ip)
    data4 = response.json()
    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data4)
        sys.exit(0)

    response = make_request(f'https://{ip}/redfish/v1/UpdateService/FirmwareInventory/16', ip)
    data5 = response.json()
    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data5)
        sys.exit(0)

    response = make_request(f'https://{ip}/redfish/v1/UpdateService/FirmwareInventory/17', ip)
    data6 = response.json()
    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data6)
        sys.exit(0)

    response = make_request(f'https://{ip}/redfish/v1/UpdateService/FirmwareInventory/18', ip)
    data7 = response.json()
    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data7)
        sys.exit(0)
    
    return [data1['IPv4Addresses'][0]['Address'],data2['SerialNumber'],data3['Version'],data4['Version'],data5['Version'],data6['Version'],data7['Version']]
       
def snmp_information(ip):
    response = make_request(f'https://{ip}/redfish/v1/Managers/1/EthernetInterfaces/1', ip)
    data1 = response.json()
    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data1)
        sys.exit(0)

    response = make_request(f'https://{ip}/redfish/v1/Managers/1/SnmpService', ip)
    data2 = response.json()
    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data2)
        sys.exit(0)

    return [data1['IPv4Addresses'][0]['Address'],data2['SNMPv1Enabled'],data2['AlertsEnabled'],data2['AlertDestinations'],data2['ReadCommunities']]

def snmp1_information(ip):
    response = make_request(f'https://{ip}/redfish/v1/Managers/1/EthernetInterfaces/1', ip)
    data1 = response.json()
    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data1)
        sys.exit(0)

    response = make_request(f'https://{ip}/redfish/v1/Managers/1/SnmpService', ip)
    data2 = response.json()
    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data2)
        sys.exit(0)

    response = make_request(f'https://{ip}/redfish/v1/Managers/1', ip)
    data3 = response.json()
    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data3)
        sys.exit(0)

    response = make_request(f'https://{ip}/redfish/v1/Managers/1/EthernetInterfaces/1/', ip)
    data4 = response.json()
    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data2)
        sys.exit(0)

    response = make_request(f'https://{ip}/redfish/v1/Chassis/1/NetworkAdapters/DE07A000/NetworkDeviceFunctions/0', ip)
    data5 = response.json()
    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data2)
        sys.exit(0)

    return[data1['IPv4Addresses'][0]['Address'],data2['TrapCommunities'],data3['Oem']['Hpe']['VirtualNICEnabled'],data4['DHCPv4']['UseNTPServers'],data4['DHCPv6']['UseNTPServers'],data5['BootMode']]

if __name__ == "__main__":
    if args["script_examples"]:
        script_examples()

    if args["ips"] and (args["u"] or args["x"]):
        idrac_ips = args["ips"].split(',')
        idrac_username = args["u"]

        if args["p"]:
            idrac_password = args["p"]
        elif not args["p"] and not args["x"] and args["u"]:
            idrac_password = getpass.getpass(f"\n- Argument -p not detected, pass in iDRAC user {args['u']} password: ")

        verify_cert = args["ssl"].lower() == "true" if args["ssl"] else False

        table = [["IP Address", "Serial Number","AutoPowerOn","License Key","CPU Health","Memory Health","PSU Health","Drive Health","Fan Health","Temperature Health"]]
        table1 = [["IP Address","PXEDevice","PostF1Prompt","PowerSupplySystem Domain", "PostAsrStatus","iLOPort", "BootOrderPolicy"]]
        table2 = [["IP Address","Serial Number","iLo Version","Bios Version","PCI Ethernet 10/25Gb","OCP Ethernet 10/25Gb","NS204I-U (Bootable card)"]]
        table3 = [["IP Address","SNMP","Alerts","Destination","Read"]]
        table4= [["IP Address","Trap Communities","iLO Virtual NIC","DHCPv4 SuppliedTimeSettings","DHCPv6 SuppliedTimeSettings","Boot Mode"]]

        for ip in idrac_ips:
            check_supported_idrac_version(ip)
            if args["information"]:
                table.append(information_of_server(ip))
            if args["bios"]:
                table1.append(bios_information(ip))
            if args["firmware"]:
                table2.append(firmware_information(ip))
            if args["snmp"]:
                table3.append(snmp_information(ip))
            if args["snmp1"]:
                table4.append(snmp1_information(ip))
            if args["all"]:
                table.append(information_of_server(ip))
                table1.append(bios_information(ip))
                table2.append(firmware_information(ip))
                table3.append(snmp_information(ip))
                table4.append(snmp1_information(ip))

        print()
        print("=================== INFORMATION OF THE SERVERS ===================")
        print(tabulate(table, headers="firstrow", tablefmt="pretty"))
        print()

        print("=================== BIOS INFORMATION OF THE SERVERS ===================")
        print(tabulate(table1, headers="firstrow", tablefmt="pretty"))
        print()

        print("=================== FIRMWARE INFORMATION OF THE SERVERS ===================")
        print(tabulate(table2, headers="firstrow", tablefmt="pretty"))
        print()
        
        print("=================== SNMP INFORMATION OF THE SERVERS ===================")
        print(tabulate(table3, headers="firstrow", tablefmt="pretty"))
        print()
        print(tabulate(table4, headers="firstrow", tablefmt="pretty"))

    else:
        logging.error("\n- FAIL, invalid argument values or not all required parameters passed in. See help text or argument --script-examples for more details.")
        sys.exit(0)