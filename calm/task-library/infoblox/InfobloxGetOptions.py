# region headers
# escript-template v20190611 / stephane.bourdeaud@nutanix.com
# * author:     stephane.bourdeaud@nutanix.com
# * version:    2020/10/16, v1
# task_name:    InfobloxGetOptions
# description:  Given a network, get the DNS and default gateway options.
# input:        network (exp: 192.168.0.0/24)
# output:       dns, default_gateway
# endregion

# region capture Calm variables
# * Capture variables here. This makes sure Calm macros are not referenced
# * anywhere else in order to improve maintainability.
username = '@@{infoblox.username}@@'
username_secret = "@@{infoblox.secret}@@"
api_server = "@@{infoblox_ip}@@"
network = "@@{network}@@"
# endregion

# region prepare variables
api_server_port = "443"
# ! You may have to change the endpoint based on your Infoblox version
api_server_endpoint = "/wapi/v2.7.1/network?network={}&_return_fields=options".format(network)
base_url = "https://{}:{}{}".format(
    api_server,
    api_server_port,
    api_server_endpoint
)
headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}
# endregion

# region API call function
def process_request(url, method, user, password, headers, payload=None):
    if (payload is not None):
        payload = json.dumps(payload)
    r = urlreq(url, verb=method, auth="BASIC", user=user, passwd=password, params=payload, verify=False, headers=headers)
    return r
# endregion

# region get network options
dns=""
default_gateway=""
url=base_url
method = "GET"
print("Making a {} API call to {}".format(method, url))
resp = process_request(url, method, username, username_secret, headers)
if resp.ok:
    print("Request was successful. Processing results...")
    #print('Response: {}'.format(json.dumps(json.loads(resp.content), indent=4)))
    for option in json.loads(resp.content)[0]['options']:
        if option['name'] == 'domain-name-servers':
            dns = option['value']
        if option['name'] == 'routers':
            default_gateway = option['value']
else:
    #api call failed
    print("Request failed")
    print("Headers: {}".format(headers))
    print("Payload: {}".format(json.dumps(payload)))
    print('Status code: {}'.format(resp.status_code))
    print('Response: {}'.format(json.dumps(json.loads(resp.content), indent=4)))
    exit(1)

if dns:
    print("dns={}".format(dns))
else:
    print("No domain name server option found in network {}".format(network))
    exit(1)

if default_gateway:
    print("defualt_gateway={}".format(default_gateway))
else:
    print("No router option found in network {}".format(network))
    exit(1)

# endregion