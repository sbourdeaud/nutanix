# Building the container

From the **build** directory, run:

 `docker build -t nutanix-objects-data-loader .`

 # Running the container

 Available environment variables are listed in the `dockerfile` file in the **build** directory.

 Example of docker command line:

 `docker run -d --name nutanix-objects-data-loader-1 -e PRISM=192.168.0.10 -e PRISM_USERNAME=admin -e PRISM_SECRET=mysecret nutanix-prometheus-exporter`

