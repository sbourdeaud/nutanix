# Create a folder
mkdir ~/actions-runner && cd ~/actions-runner
# Download the latest runner package
curl -o actions-runner-linux-x64-2.299.1.tar.gz -L https://github.com/actions/runner/releases/download/v2.299.1/actions-runner-linux-x64-2.299.1.tar.gz
# Extract the installer
tar xzf ./actions-runner-linux-x64-2.299.1.tar.gz