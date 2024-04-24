#!/bin/bash

RED="\e[31m"
GREEN="\e[32m"
ENDCOLOR="\e[0m"

while read -r line; do
    IFS='/' read -a strarr <<< "$line"

    imgname=${strarr[-1]}
    echo "Scanning repo $line...."

    filename=`echo $imgname | sed 's/:/-/'`
    jsonfile=$filename.json
    tablefile=$filename.txt

    #scan the image in both table and json formats
    trivy image --severity=HIGH,CRITICAL $line > $tablefile
    trivy image -f json --severity=HIGH,CRITICAL $line > $jsonfile

    #check to see if Trivy returned any useful results
    grep -l LIBRARY $tablefile

    if [ $? -eq 0 ]
    then
      echo -e "${GREEN}Trivy found vulnerabilities in $imgname${ENDCOLOR} - opening a JIRA and attaching results..."
      #extract package names from JSON output
      jsonpackages=$(tail -n+`grep -an "^\[" $jsonfile | cut -d : -f 1` $jsonfile | jq ".[].Target")
      #strip double quotes and replace newlines with \n
      jsonpackages=$(echo "$jsonpackages" | sed 's%"%%g' | awk '{printf "%s\\n", $0}' | sed 's%\n%\\n%g')
      #echo "Got json packages list of \n$jsonpackages"

      data='{"fields":{"project":{ "key":"'$2'"},"summary": "Update '$line' to address high and critical vulnerabilities","description":"Please see attachment for scan report of this image. High and critical vulnerabilities were found in these packages in this image:'$jsonpackages'","issuetype": {"name":"Bug"},"labels": ["CVE"]}}'

      #data=$(sed "s#__REPO__#$line#" jira.json)
      #data=$(echo $data | sed "s%__PACKAGES__%$jsonpackages%")
      echo $data
            JIRA=$(curl -vvv -u $JIRAUSER:$JIRATOKEN --data-binary "$data"  -H "Content-Type: application/json" https://$JIRAURL/rest/api/2/issue/ | jq -r '.key')
      echo "Created $JIRA for $imgname"
      curl -u $JIRAUSER:$JIRATOKEN -H "X-Atlassian-Token: nocheck" -F "file=@$tablefile" https://$JIRAURL/rest/api/2/issue/$JIRA/attachments
    else
      echo -e "${RED}No Trivy results found for $line${ENDCOLOR}"
    fi
done < $1
