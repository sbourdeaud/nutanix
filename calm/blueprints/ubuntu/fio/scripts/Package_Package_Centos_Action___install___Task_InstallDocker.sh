sudo yum install -y yum-utils
sudo yum-config-manager \
    --add-repo \
    https://download.docker.com/linux/centos/docker-ce.repo
sudo yum install -y docker-ce docker-ce-cli containerd.io
sudo dnf install -y iptables
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker $USER
sudo chmod 666 /var/run/docker.sock