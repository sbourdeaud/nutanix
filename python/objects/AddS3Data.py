import boto3
from botocore.exceptions import ClientError
import sys

session = boto3.session.Session()

# configuration for this connection
# in a "real" script, these values would not be hard-coded
configuration = {
    "endpoint_url": "[endpoint_url_here]",
    "access_key": "[access_key_here]",
    "secret_key": "[secret_key_here]",
    "bucket": "ntnxdev-uploads",
    "filename": "/tmp/hello_world.txt",
    "key": "hello_world.txt"
}

# create our s3c session using the variables above
# note "use_ssl=False", as outlined in the accompanying article
s3c = session.client(
    aws_access_key_id=configuration["access_key"],
    aws_secret_access_key=configuration["secret_key"],
    endpoint_url=configuration["endpoint_url"],
    service_name="s3",
    use_ssl=False,
)

# check if bucket exists
try:
    s3c.head_bucket(Bucket=configuration["bucket"])
    print(f"Bucket exists : {configuration['bucket']}")
except ClientError:
    print(f"Bucket {configuration['bucket']} does not exist.  "
          + "Attempting to create bucket ...")
    try:
        s3c.create_bucket(Bucket=configuration['bucket'])
    except Exception as err:
        print("An exception occurred while creating the "
              + f"{configuration['bucket']} bucket.  "
              + f"Details: {err}")
        sys.exit()

try:
    # create file handle and upload the file to Objects endpoint.
    print(f"Uploading file {configuration['filename']}, as object "
          + "{configuration['key']} in bucket {configuration['bucket']} ...")
    s3c.put_object(Bucket=configuration["bucket"],
                   Key=configuration["key"],
                   Body=configuration["filename"])

    # verify if file is uploaded
    print(f"Checking if {configuration['key']} exists ...")
    response = s3c.head_object(Bucket=configuration["bucket"],
                               Key=configuration["key"])
    print(f"Head Object Response : {response}")
except s3c.exceptions.NoSuchBucket:
    print(f"The {configuration['bucket']} bucket does not exist.  "
          + "Aborting ...")
except Exception as err:
    print("An unexpected exception occurred while attempting "
          + "file upload.  Details:")
    print(f"{err}")