cd ~/actions-runner
sudo ./svc.sh install
sudo sed -i 's/ExecStart=/ExecStart=\/bin\/bash /g' /etc/systemd/system/$(cat ~/actions-runner/.service)
sudo systemctl daemon-reload