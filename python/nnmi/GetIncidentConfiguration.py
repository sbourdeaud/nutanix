import requests,xml.etree.ElementTree,os

#region variables
api_server = "nnmi.emeagso.lab"
api_server_port = 80
user = os.getenv('NNMI_USERNAME')
password = os.getenv('NNMI_SECRET')
headers = {'Content-Type': 'application/xml', 'Accept': 'application/xml'}
#endregion

#region API call function
def process_request(url, method, user, password, headers, payload=None, secure=False):
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

            if method == 'GET':
                #print("secure is {}".format(secure))
                response = requests.get(
                    url,
                    headers=headers,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'POST':
                response = requests.post(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'PUT':
                response = requests.put(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'PATCH':
                response = requests.patch(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'DELETE':
                response = requests.delete(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )

        except requests.exceptions.HTTPError as error_code:
            print(f"{bcolors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] Http Error! Status code: {response.status_code}{bcolors.RESET}")
            print(f"{bcolors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] reason: {response.reason}{bcolors.RESET}")
            print(f"{bcolors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] text: {response.text}{bcolors.RESET}")
            print(f"{bcolors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] elapsed: {response.elapsed}{bcolors.RESET}")
            print(f"{bcolors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] headers: {response.headers}{bcolors.RESET}")
            if payload is not None:
                print(f"{bcolors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] payload: {payload}{bcolors.RESET}")
            print(json.dumps(
                json.loads(response.content),
                indent=4
            ))
            exit(response.status_code)
        except requests.exceptions.ConnectionError as error_code:
            if retries == 1:
                print(f"{bcolors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {type(error_code).__name__} {str(error_code)} {bcolors.RESET}")
                exit(1)
            else:
                print(f"{bcolors.WARNING}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] {type(error_code).__name__} {str(error_code)} {bcolors.RESET}")
                time.sleep(sleep_between_retries)
                retries -= 1
                print(f"{bcolors.WARNING}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] Retries left: {retries}{bcolors.RESET}")
                continue
        except requests.exceptions.Timeout as error_code:
            if retries == 1:
                print(f"{bcolors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {type(error_code).__name__} {str(error_code)} {bcolors.RESET}")
                exit(1)
            else:
                print(f"{bcolors.WARNING}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] {type(error_code).__name__} {str(error_code)} {bcolors.RESET}")
                time.sleep(sleep_between_retries)
                retries -= 1
                print(f"{bcolors.WARNING}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [WARNING] Retries left: {retries}{bcolors.RESET}")
                continue
        except requests.exceptions.RequestException as error_code:
            print(f"{bcolors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {response.status_code} {bcolors.RESET}")
            exit(response.status_code)
        break

    if response.ok:
        return response
    if response.status_code == 401:
        print(f"{bcolors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {response.status_code} {response.reason} {bcolors.RESET}")
        exit(response.status_code)
    elif response.status_code == 500:
        print(f"{bcolors.FAIL}{(datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {response.status_code} {response.reason} {response.text} {bcolors.RESET}")
        exit(response.status_code)
    else:
        print(f"{bcolors.FAIL}{(datetime.now()).strftime('%Y-%m-%d_%H:%M:%S')} [ERROR] Request failed! Status code: {response.status_code}{bcolors.RESET}")
        print(f"{bcolors.FAIL}{(datetime.now()).strftime('%Y-%m-%d_%H:%M:%S')} [ERROR] reason: {response.reason}{bcolors.RESET}")
        print(f"{bcolors.FAIL}{(datetime.now()).strftime('%Y-%m-%d_%H:%M:%S')} [ERROR] text: {response.text}{bcolors.RESET}")
        print(f"{bcolors.FAIL}{(datetime.now()).strftime('%Y-%m-%d_%H:%M:%S')} [ERROR] raise_for_status: {response.raise_for_status()}{bcolors.RESET}")
        print(f"{bcolors.FAIL}{(datetime.now()).strftime('%Y-%m-%d_%H:%M:%S')} [ERROR] elapsed: {response.elapsed}{bcolors.RESET}")
        print(f"{bcolors.FAIL}{(datetime.now()).strftime('%Y-%m-%d_%H:%M:%S')} [ERROR] headers: {response.headers}{bcolors.RESET}")
        if payload is not None:
            print(f"{bcolors.FAIL}{(datetime.now()).strftime('%Y-%m-%d_%H:%M:%S')} [ERROR] payload: {payload}{bcolors.RESET}")
        print(json.dumps(
            json.loads(response.content),
            indent=4
        ))
        exit(response.status_code)


def process_soap_request(url, method, headers, payload):
    r = requests.urlreq(url, verb=method, params=payload, verify=False, headers=headers)
    if r.ok:
        print("Request was successful")
        print("Status Code: {}".format(r))
    else:
        print("Request failed")
        print("Status Code: {}".format(r))
        print("Headers: {}".format(headers))
        print("Payload: {}".format(payload))
        print("Response: {}".format(r.text))
        resp_parse = ET.fromstring(r.text)
        for element in resp_parse.iter('*'):
          if "faultstring" in element.tag:
            print("")
            print("Error: {}".format(element.text))
            break
        exit(1)
    return r
#endregion

#region GET IncidentConfiguration service
ET = xml.etree.ElementTree

# making the call
api_server_endpoint = "/IncidentConfigurationBeanService/IncidentConfigurationBean?wsdl"
method = "GET"
url = "http://{}:{}{}".format(api_server, api_server_port, api_server_endpoint)

print("STEP: Fetching IncidentConfiguration service...")
print("Making a {} API call to {}".format(method, url))
resp = process_request(url, method, user, password, headers)

resp_parse = ET.fromstring(resp.text)
print(resp_parse)
#endregion
