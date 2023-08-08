#install pre-reqs
sudo yum groupinstall 'development tools' -y
sudo yum install python3 python3-devel python3-wheel python3-pip make gcc openssl-devel -y
sudo pip3 install virtualenv

cd $home
git clone https://github.com/nutanix/calm-dsl.git
cd calm-dsl
make dev