# region headers
"""
# escript-template v20190611 / stephane.bourdeaud@nutanix.com
# * author:     stephane.bourdeaud@nutanix.com
# * version:    v2.0/20210503 - cita-starter version
# task_name:    PhpIPAMGetSubnet
# description:  Given a php-ipam server ip/fqdn, and a subnet id, return
#               information about that subnet (mask, gateway, used IPs, 
#               total IPs, free IPs). It assumes the gateway and nameservers
#               have been defined on the subnet.
# output vars:  phpipam_subnet_mask, phpipam_subnet_bitmask,  
#               phpipam_subnet_gateway, phpipam_subnet_total_ips,
#               phpipam_subnet_nameservers
"""
# endregion

# region capture Calm variables
# * Capture variables here. This makes sure Calm macros are not referenced
# * anywhere else in order to improve maintainability.
username = '@@{phpipam.username}@@'
username_secret = "@@{phpipam.secret}@@"
api_server = "@@{phpipam_ip}@@"
phpipam_app_id = "@@{phpipam_app_id}@@"
phpipam_subnet_id = "@@{phpipam_subnet_id}@@"
# endregion

# region prepare variables
api_server_port = "443"
secure_calls=True
# endregion

# region API call function
import requests

def process_request(url, method, user, password, headers, payload=None, secure=secure_calls):
    """
    Processes a web request and handles result appropriately with retries.
    Returns the content of the web request if successfull.
    """
    if payload is not None:
        payload = json.dumps(payload)

    #configuring web request behavior
    timeout=10
    retries = 5
    sleep_between_retries = 5

    while retries > 0:
        try:

            if method is 'GET':
                response = requests.get(
                    url,
                    headers=headers,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method is 'POST':
                response = requests.post(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method is 'PUT':
                response = requests.put(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method is 'PATCH':
                response = requests.patch(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method is 'DELETE':
                response = requests.delete(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )

        except requests.exceptions.HTTPError as error_code:
            print ("Http Error!")
            print("status code: {}".format(response.status_code))
            print("reason: {}".format(response.reason))
            print("text: {}".format(response.text))
            print("elapsed: {}".format(response.elapsed))
            print("headers: {}".format(response.headers))
            if payload is not None:
                print("payload: {}".format(payload))
            print(json.dumps(
                json.loads(response.content),
                indent=4
            ))
            exit(response.status_code)
        except requests.exceptions.ConnectionError as error_code:
            print ("Connection Error!")
            if retries == 1:
                print('Error: {c}, Message: {m}'.format(c = type(error_code).__name__, m = str(error_code)))
                exit(1)
            else:
                print('Error: {c}, Message: {m}'.format(c = type(error_code).__name__, m = str(error_code)))
                sleep(sleep_between_retries)
                retries -= 1
                print ("retries left: {}".format(retries))
                continue
            print('Error: {c}, Message: {m}'.format(c = type(error_code).__name__, m = str(error_code)))
            exit(1)
        except requests.exceptions.Timeout as error_code:
            print ("Timeout Error!")
            if retries == 1:
                print('Error: {c}, Message: {m}'.format(c = type(error_code).__name__, m = str(error_code)))
                exit(1)
            print('Error! Code: {c}, Message: {m}'.format(c = type(error_code).__name__, m = str(error_code)))
            sleep(sleep_between_retries)
            retries -= 1
            print ("retries left: {}".format(retries))
            continue
        except requests.exceptions.RequestException as error_code:
            print ("Error!")
            exit(response.status_code)
        break

    if response.ok:
        return response
    if response.status_code == 401:
        print("status code: {0}".format(response.status_code))
        print("reason: {0}".format(response.reason))
        exit(response.status_code)
    elif response.status_code == 500:
        print("status code: {0}".format(response.status_code))
        print("reason: {0}".format(response.reason))
        print("text: {0}".format(response.text))
        exit(response.status_code)
    else:
        print("Request failed!")
        print("status code: {0}".format(response.status_code))
        print("reason: {0}".format(response.reason))
        print("text: {0}".format(response.text))
        print("raise_for_status: {0}".format(response.raise_for_status()))
        print("elapsed: {0}".format(response.elapsed))
        print("headers: {0}".format(response.headers))
        if payload is not None:
            print("payload: {0}".format(payload))
        print(json.dumps(
            json.loads(response.content),
            indent=4
        ))
        exit(response.status_code)

# endregion


#* get auth token
# region get auth token

# region prepare api call
#! note that if your app security in php-ipam is set to 'none'
#! you will have to change the port to 80 and url to http.
api_server_endpoint = "/api/{}/user".format(phpipam_app_id)
url = "https://{}:{}{}".format(
    api_server,
    api_server_port,
    api_server_endpoint
)
method = "POST"
headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}
# endregion

# region make api call
# make the API call and capture the results in the variable called "resp"
print("Making a {} API call to {}".format(method, url))
resp = process_request(url, method, username, username_secret, headers)

# deal with the result/response
if resp.ok:
    print("Request was successful. Status code: {}".format(resp.status_code))
    phpipam_token=json.loads(resp.content)['data']['token']
else:
    exit(1)
# endregion

# endregion

#* get subnet details
#region get subnet details

# region prepare api call
#! note that if your app security in php-ipam is set to 'none'
#! you will have to change the port to 80 and url to http.
api_server_endpoint = "/api/{}/subnets/{}/".format(phpipam_app_id,phpipam_subnet_id)
url = "https://{}:{}{}".format(
    api_server,
    api_server_port,
    api_server_endpoint
)
method = "GET"
headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'token' : phpipam_token
}
# endregion

# region make api call
# make the API call and capture the results in the variable called "resp"
print("Making a {} API call to {}".format(method, url))
resp = process_request(url, method, username, username_secret, headers)

# deal with the result/response
if resp.ok:
    print("Request was successful. Status code: {}".format(resp.status_code))
    #print('Response: {}'.format(json.dumps(json.loads(resp.content), indent=4)))
    dns_servers=json.loads(resp.content)['data']['nameservers']['namesrv1']
    dns_servers=dns_servers.split(';')
    print("subnet_mask= {}".format(json.loads(resp.content)['data']['calculation']['Subnet netmask']))
    print("subnet_mask_bits= {}".format(json.loads(resp.content)['data']['calculation']['Subnet bitmask']))
    print("gateway= {}".format(json.loads(resp.content)['data']['gateway']['ip_addr']))
    print("dns1= {}".format(dns_servers[0]))
    print("dns2= {}".format(dns_servers[1]))
else:
    exit(1)
# endregion

# endregion

#* revoke token
# region revoke auth token

# region prepare api call
#! note that if your app security in php-ipam is set to 'none'
#! you will have to change the port to 80 and url to http.
api_server_endpoint = "/api/{}/user".format(phpipam_app_id)
url = "https://{}:{}{}".format(
    api_server,
    api_server_port,
    api_server_endpoint
)
method = "DELETE"
headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'token' : phpipam_token
}
# endregion

# region make api call
# make the API call and capture the results in the variable called "resp"
print("Making a {} API call to {}".format(method, url))
resp = process_request(url, method, username, username_secret, headers)

# deal with the result/response
if resp.ok:
    print("Request was successful. Status code: {}".format(resp.status_code))
    print("Token was revoked")
else:
    exit(1)
# endregion

# endregion
