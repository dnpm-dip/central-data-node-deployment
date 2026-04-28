# DNPM - Central Clinical Data Node Deployment Setup


**WORK IN PROGRESS**

## How to deploy
After having checked out this repository into a folder on the server, run
"init.sh" to set up some folders, then run "docker compose up -d"

## How to extract site availability logs
With a running docker composite, call "docker compose run --rm siteLogDump". 
This creates a folder called "siteAvailabilityLogDump" inside the "ccdn-data"
docker volume and saves a .json dump named by todays date there.