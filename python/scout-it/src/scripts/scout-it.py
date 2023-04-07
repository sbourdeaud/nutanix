import json
import requests
from datetime import datetime
from argparse import ArgumentParser
from platform import node
from os import cpu_count
import jsonschema
from wmi import WMI
from snipeit import Assets, Licenses
from winapps import list_installed
from getmac import get_mac_address
from psutil import virtual_memory


class bcolors:
    """Used for colored output formatting.
    """
    OK = '\033[92m' #GREEN
    SUCCESS = '\033[96m' #CYAN
    DATA = '\033[097m' #WHITE
    WARNING = '\033[93m' #YELLOW
    FAIL = '\033[91m' #RED
    STEP = '\033[95m' #PURPLE
    RESET = '\033[0m' #RESET COLOR


def load_software_exclusion_list(exclusion_file):
    '''Loads the software exclusion list.  Any software item in that list 
    will be ignored when sending software inventory to the snipeit server. 
        Args:
            exclusion_file: path to the software exlcusion json file.
                            schema for this file is included in this
                            function.
        Returns: software_exclusion_list (dictionary representing the
                content of the json file).
    '''
    schema = {
        "$schema":"http://json-schema.org/draft-04/schema#",
        "title":"SoftwareExclusionFile",
        "description":"scout-it software exclusion file json schema.",
        "type":"object",
        "properties": {
            "exclusion_list": {
                "description":"list of softwares to exclude.",
                "type":"array",
                "items":{
                    "description":"String of the software name to exclude",
                    "type":"string"
                }       
            }
        }
    }
    
    with open(exclusion_file, 'r', encoding="UTF8") as file:
        software_exclusion_list = json.load(file)
        
    try:
        jsonschema.validate(instance=software_exclusion_list, schema=schema)
        print(f"{bcolors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Software exclusion file is valid.{bcolors.RESET}")
    except jsonschema.exceptions.ValidationError as err:
        print(f"{bcolors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] Software exclusion file is invalid: {err}{bcolors.RESET}")
        
    return software_exclusion_list


def get_snipeit_information(api_server, api_key):
    '''Gets existing assets and licenses from the snipeit server.
        Args:
            api_server: URL string to snipe-it server instance.
            api_key: String with the API token to use for
                    authentication with the snipe-it server.
        Returns: assets, licenses.
    '''
    assets_object = Assets()
    assets = assets_object.get(api_server, api_key)
    licenses_object = Licenses()
    licenses = licenses_object.get(api_server, api_key)
    return assets, licenses


def get_inventory():
    '''Gets the operating system, hostname, hardware configuration, 
    mac address of the first network adapter and list of installed software
        Args:
        Returns: inventory
    '''
    inventory = {"operating_system":"", "hostname":"", "cpu_count":"", 
                 "ram_gb":"", "mac_address":"", "installed_software":[]}
    wmi_object = WMI()
    operating_system_information = wmi_object.Win32_OperatingSystem()[0]
    inventory['operating_system'] = operating_system_information.Caption
    inventory['hostname'] = node()
    inventory['cpu_count'] = cpu_count()
    inventory['ram_gb'] = round(virtual_memory().total /1024 /1024 /1024, 0)
    inventory['mac_address'] = get_mac_address()
    installed_software = list_installed()
    for software in installed_software:
        inventory['installed_software'].append({"name": software.name,"version":software.version,"publisher":software.publisher})
    return inventory


def process_asset(api_server, api_key, assets, inventory):
    '''Creates or updates asset.
        Args:
            api_server: URL string to snipe-it server instance.
            api_key: String with the API token to use for
                    authentication with the snipe-it server.
            assets: assets bytes object obtained from a assets get
                    call using the snipeit python module.
            inventory: dictionary obtained from the get_inventory
                    function.
        Returns: asset_id
    '''
    #* find our asset if it already exists
    for asset in json.loads(assets.decode('utf-8'))['rows']:
        if asset['asset_tag'] == inventory['mac_address']:
            print(f"{bcolors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Found asset {asset['name']} with tag {asset['asset_tag']} which matches MAC address {inventory['mac_address']}.{bcolors.RESET}")
            asset_id = asset['id']
            #todo: need to add logic here to update asset if necessary
            return asset_id
    #* our asset does not already exist, so let's create it
    payload = {
        "model_id":1,
        "status_id":4,
        "name":inventory['hostname'],
        "asset_tag":inventory['mac_address']
    }
    asset = Assets()
    response = asset.create(api_server, api_key, json.dumps(payload))
    if json.loads(response)['status'] == "error":
        print(f"{bcolors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] Could not create asset: {json.loads(response)['messages']}{bcolors.RESET}")
        return
    else:
        asset_id = json.loads(response)['payload']['id']
        print(f"{bcolors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Successfully created asset with id {asset_id}.{bcolors.RESET}")
        return asset_id


def process_software_inventory(api_server, api_key, asset_id, licenses, inventory, software_exclusion_list):
    '''Creates and/or checks out licenses.
        Args:
            api_server: URL string to snipe-it server instance.
            api_key: String with the API token to use for
                    authentication with the snipe-it server.
            asset_id: Id of the snipeit asset which we will be assigning
                    software licenses to in snipe-it.
            licenses: Bytes object obtained from a licenses get call using
                    the snipeit Python module.
            inventory: dictionary obtained from the get_inventory function.
            software_exclusion_list: dictionary obtained from the
                    load_software_exclusion_list function.
        Returns: nothing.
    '''
    for installed_software in inventory['installed_software']:
        if installed_software['name'] in software_exclusion_list['exclusion_list']:
            print(f"{bcolors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Software {bcolors.DATA}{installed_software['name']}{bcolors.OK} is in the software exclusion list: {bcolors.WARNING}ignoring{bcolors.RESET}")
            continue
        software_license = next((item for item in json.loads(licenses.decode('utf-8'))['rows'] if item['name'] == installed_software['name']), False)
        if software_license is False:
            print(f"{bcolors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Software {bcolors.DATA}{installed_software['name']}{bcolors.OK} does not already exist in the snipe-it server.{bcolors.RESET}")
            license_object = Licenses()
            payload = {
                "name": installed_software['name'],
                "seats": 1,
                "category_id": "1"
            }
            response = license_object.create(api_server, api_key, json.dumps(payload))
            if json.loads(response)['status'] == "error":
                print(f"{bcolors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] Could not create license: {json.loads(response)['messages']}{bcolors.RESET}")
            else:
                software_license = json.loads(response)['payload']
                print(f"{bcolors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Successfully created license with id {software_license['id']}.{bcolors.RESET}")
            
        license_seats = get_license_seats(api_server, api_key, software_license['id'])
        installed_software_seat = False
        for seat in license_seats['rows']:
            if seat['assigned_asset']:
                if seat['assigned_asset']['id'] == asset_id:
                    installed_software_seat = seat
        if installed_software_seat:
            print(f"{bcolors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Asset id {asset_id} has already checked out license {bcolors.DATA}{installed_software['name']}{bcolors.OK}: {bcolors.WARNING}skipping{bcolors.RESET}")
            continue
        else:
            installed_software_seat = next((item for item in license_seats['rows'] if item['user_can_checkout'] is True), False)
            if installed_software_seat:
                print(f"{bcolors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Found available seat {bcolors.DATA}{installed_software_seat['id']}{bcolors.OK} so checking out license {bcolors.DATA}{installed_software['name']}{bcolors.OK} for asset id {bcolors.DATA}{asset_id}{bcolors.RESET}")
                response = checkout_license(api_server, api_key, software_license['id'], installed_software_seat['id'], asset_id)
            else:
                print(f"{bcolors.WARNING}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] Could not find an available seat for license {bcolors.DATA}{installed_software['name']}{bcolors.WARNING} for asset id {bcolors.DATA}{asset_id}{bcolors.RESET}")
                response = increase_license_seat_count(api_server, api_key, software_license['id'], software_license)
                assets, licenses = get_snipeit_information(api_server,api_key)
                print(f"{bcolors.OK}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [INFO] Successfully updated license with id {software_license['id']} and added a seat.{bcolors.RESET}")
                license_seats = get_license_seats(api_server, api_key, software_license['id'])
                installed_software_seat = next((item for item in license_seats['rows'] if item['user_can_checkout'] is True), False)
                response = checkout_license(api_server, api_key, software_license['id'], installed_software_seat['id'], asset_id)


def get_license_seats(api_server, api_key, license_id):
    '''Retrieve license seats details for a specified license id.
        Args:
            api_server: URL string to snipe-it server instance.
            api_key: String with the API token to use for
                    authentication with the snipe-it server.
            license_id: Id string of the license.
        Returns: license_seats (dictionary object with API response content).
    '''
    api_endpoint = f"/api/v1/licenses/{license_id}/seats"
    url = f"{api_server}{api_endpoint}"
    headers = {'Authorization': f'Bearer {api_key}'}
    response = requests.get(url,headers=headers,timeout=30)
    if response.ok:
        license_seats = json.loads(response.content)
        return license_seats


def checkout_license(api_server, api_key, license_id, seat_id, asset_id):
    '''Retrieve license seats details for a specified license id.
        Args:
            api_server: URL string to snipe-it server instance.
            api_key: String with the API token to use for
                    authentication with the snipe-it server.
            license_id: Id string of the license.
            seat_id: Id string of the seat to use for checkout.
            asset_id: Id string of the asset checking out the license seat.
        Returns: API response content as dictionary.
    '''
    #checkout?checkout_to_type=asset&asset_id=7
    api_endpoint = f"/api/v1/licenses/{license_id}/seats/{seat_id}"
    url = f"{api_server}{api_endpoint}"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {api_key}'
    }
    payload = {"asset_id": asset_id}
    response = requests.put(url,headers=headers,data=json.dumps(payload),timeout=30)
    if response.ok:
        print(f"{bcolors.SUCCESS}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [SUCCESS] Checked out license {bcolors.DATA}{license_id}{bcolors.SUCCESS} for asset id {bcolors.DATA}{asset_id}{bcolors.SUCCESS} using seat {bcolors.DATA}{seat_id}{bcolors.RESET}")
        return json.loads(response.content)
    else:
        print(f"{bcolors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [SUCCESS] Could not checkout license: {response}{bcolors.RESET}")


def increase_license_seat_count(api_server, api_key, license_id, license_details):
    '''Updates the specified license by increasing its seat count by 1.
        Args:
            api_server: URL string to snipe-it server instance.
            api_key: String with the API token to use for
                    authentication with the snipe-it server.
            license_id: Id string of the license.
            license_details: Disctionary of the license object payload. 
        Returns: API response content as dictionary.
    '''
    #checkout?checkout_to_type=asset&asset_id=7
    api_endpoint = f"/api/v1/licenses/{license_id}"
    url = f"{api_server}{api_endpoint}"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {api_key}'
    }
    license_details['seats'] = license_details['seats'] + 1
    license_details['serial'] = license_details['product_key']
    license_details.pop('product_key',None)
    response = requests.put(url,headers=headers,data=json.dumps(license_details),timeout=30)
    if response.ok:
        print(f"{bcolors.SUCCESS}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [SUCCESS] Added 1 seat to license {bcolors.DATA}{license_id}{bcolors.RESET}")
        return json.loads(response.content)
    else:
        print(f"{bcolors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [SUCCESS] Could update license: {response}{bcolors.RESET}")


def main(api_server,api_key,exclusion_file='./software_exclusion_file.json'):
    '''Gets information about this asset and registers this information
    with the snipe-it server.
        Args:
            api_server: URL string to snipe-it server instance.
            api_key: String with the API token to use for
                    authentication with the snipe-it server.
            exclusion_file: path to the software exclusion json file.
        Returns:
    '''

    #* getting all the information we need
    software_exclusion_list = load_software_exclusion_list(exclusion_file)
    assets, licenses = get_snipeit_information(api_server,api_key)
    inventory = get_inventory()

    #* dealing with the asset itself
    asset_id = process_asset(api_server, api_key, assets, inventory)

    #* dealing with the software inventory
    process_software_inventory(api_server, api_key, asset_id, licenses, inventory, software_exclusion_list)



if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("-s", "--snipeit_server", help="URL for the snipe-it server.")
    parser.add_argument("-k", "--key", help="API key to use for authentication with the snipe-it server.")
    parser.add_argument("-x", "--exclusion_file", help="Path to the software exclusion list file.")
    args = parser.parse_args()
    main(api_server=args.snipeit_server,api_key=args.key,exclusion_file=args.exclusion_file)
