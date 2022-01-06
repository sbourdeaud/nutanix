# region headers
"""
# escript-template v20190611 / stephane.bourdeaud@nutanix.com
# TODO Fill in this section with your information
# * author:     stephane.bourdeaud@nutanix.com, igor.zecevic@nutanix.com
# * version:    v2.1/20210504 - cita-starter version
# task_name:    PhpIPAMGetFreeIp
# description:  Given a phpIPAM server ip/fqdn, a phpIPAM app id, a token
#               and a subnet id, return the first available IP address in 
#               that subnet. The current VM name and Calm user will be used
#               for ip registration with ipam.               
# outputvars:   phpipam_free_ip
"""
# endregion

# region capture Calm variables
username = '@@{phpipam.username}@@'
username_secret = "@@{phpipam.secret}@@"
api_server = "@@{phpipam_ip}@@"
phpipam_app_id = "@@{phpipam_app_id}@@"
phpipam_subnet_id = "@@{phpipam_subnet_id}@@"
hostname = "@@{vm_name}@@.@@{domain}@@"
owner = "@@{calm_username}@@" #* this is a built-in Calm macro which returns the Calm user username
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
    # print the content of the response (which should have the error message)
    print("Request failed!")
    print("status code: {}".format(resp.status_code))
    print("reason: {}".format(resp.reason))
    print("text: {}".format(resp.text))
    print("raise_for_status: {}".format(resp.raise_for_status()))
    print("elapsed: {}".format(resp.elapsed))
    print("headers: {}".format(resp.headers))
    print("payload: {}".format(payload))
    print(json.dumps(
        json.loads(resp.content),
        indent=4
    ))
    exit(1)
# endregion

# endregion

#* get free ip
#region get free ip

# region prepare api call
api_server_endpoint = "/api/{}/addresses/first_free/{}".format(phpipam_app_id,phpipam_subnet_id)
url = "https://{}:{}{}".format(
    api_server,
    api_server_port,
    api_server_endpoint
)
method = "POST"
headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'token' : phpipam_token
}

# Compose the json payload
payload = {
    "hostname": hostname, 
    "description": hostname,
    "owner": owner
}
# endregion

# region make api call
# make the API call and capture the results in the variable called "resp"
print("Making a {} API call to {}".format(method, url))
resp = process_request(url, method, username, username_secret, headers, payload)

# deal with the result/response
if resp.ok:
    print("Request was successful. Status code: {}".format(resp.status_code))
    print ("IP {} was registered for host {} with owner {}".format(json.loads(resp.content)['data'],hostname,owner))
    print('vm_ip= {}'.format(json.loads(resp.content)['data']))
else:
    exit(1)
# endregion

# endregion

#* revoke token
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
