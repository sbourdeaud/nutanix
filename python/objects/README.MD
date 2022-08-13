# About

The python script will upload random data in batch to an S3 bucket. Data files are processed in memory, one at a time, and will have a random size from a specified range.
See the **Dockerfile** for a list of environment variables to specify data size and count ranges.

# Building the container

From the **build** directory, with *docker* run:

 `docker build -t nutanix-objects-data-loader .`
 
 or if you use *podman*:

 `podman build -t nutanix-objects-data-loader:latest .`

 # Running the container

 Available environment variables are listed in the `dockerfile` file in the **build** directory.

 Example of *docker* command line:

 `docker run -d --name nutanix-objects-data-loader-1 -e ENDPOINT_URL="http://myobjectstore.local" -e ACCESS_KEY=myaccesskey -e SECRET_KEY=mysecretkey -e BUCKET="mybucket" nutanix-objects-data-loader`

 Example of *podman* command line:

`export SECRET_KEY=mysecretkeyhere`

`podman secret create --env SECRET_KEY SECRET_KEY`

`podman run -d -d --name nutanix-objects-data-loader-1 -e ENDPOINT_URL="http://myobjectstore.local" -e ACCESS_KEY=myaccesskey --secret SECRET_KEY,type=env -e BUCKET="mybucket" nutanix-objects-data-loader`

