# Create the runner and start the configuration experience
cd ~/actions-runner
# sudo ./bin/installdependencies.sh
./config.sh --url @@{github_repo}@@ --token @@{github_repo_token}@@ --unattended --labels AMS