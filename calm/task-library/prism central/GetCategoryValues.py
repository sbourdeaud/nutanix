# region headers
# escript-template v20190523 / stephane.bourdeaud@nutanix.com
# * author:       stephane.bourdeaud@nutanix.com, jeremie.moreau@nutanix.com
# * version:      2021/03/18
# task_name:      GetCategoryValues
# description:    This script returns all the values for a given
#                 category name.
# endregion

# region capture Calm macros
pc_user = "@@{prism_central.username}@@"
pc_password = "@@{prism_central.secret}@@"
category_name = "@@{category_name}@@"
pc_ip = "@@{prism_central_ip}@@"
# endregion

# region prepare variables
url = "https://{}:9440/api/nutanix/v3/categories/{}/list".format(
    pc_ip,
    category_name
)
headers = {
    'Accept': 'application/json',
    'Content-Type': 'application/json; charset=UTF-8'
}
# endregion


# region functions
def process_request(url, method, user, password, headers, payload=None):
    if payload is not None:
        payload = json.dumps(payload)
    r = urlreq(
            url,
            verb=method,
            auth="BASIC",
            user=user,
            passwd=password,
            params=payload,
            verify=False,
            headers=headers
        )
    return r
# endregion

# region get the cluster IP address
method = 'POST'
print("Making a {} API call to {}".format(method, url))
payload = {}
resp = process_request(url, method, pc_user, pc_password, headers, payload)
result = json.loads(resp.content)

if resp.ok:
    # print the content of the response
    print(json.dumps(
        json.loads(resp.content),
        indent=4
    ))
else:
    # print the content of the response (which should have the error message)
    print("Request failed", json.dumps(
        json.loads(resp.content),
        indent=4
    ))
    print("Headers: {}".format(headers))
    exit(1)
# endregion