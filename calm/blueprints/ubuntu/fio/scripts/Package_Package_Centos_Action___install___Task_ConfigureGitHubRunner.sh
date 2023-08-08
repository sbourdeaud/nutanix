# update repositories
sudo sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*
sudo sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*
#sudo rpm -Uvh https://packages.microsoft.com/config/centos/7/packages-microsoft-prod.rpm
#sudo yum install aspnetcore-runtime-6.0 -y
#sudo yum install dotnet-runtime-6.0

# Create the runner and start the configuration experience
cd ~/actions-runner
sudo ./bin/installdependencies.sh
./config.sh --url @@{github_repo}@@ --token @@{github_repo_token}@@ --unattended --labels AMS