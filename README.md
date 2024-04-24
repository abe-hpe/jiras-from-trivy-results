# jiras-from-trivy-results
Scan a list of images with Trivy and raise JIRAs with results

To get started:

1 - Install Trivy

rpm -ivh https://github.com/aquasecurity/trivy/releases/download/v0.18.3/trivy_0.18.3_Linux-64bit.rpm

2 - Install Docker and jq

yum install -y docker jq

3 - Edit the jira.json template to meet your needs (adding labels and so on)

4 - Create a text file of images to scan, one per line - images.txt, for example

5 - export JIRAUSER=<your JIRA username>

6 - export JIRATOKEN=<your JIRA api token>

5 - Execute ./scan.sh images.txt
