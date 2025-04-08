This directory contains examples of script using the smc python library.

# requirements

- python 3.x
- smc-python dependencies installed

# running the examples

You can either use the script ./run_example.sh or do steps manually

## using the run_example.sh script

```
cd ${repo_base}/smc/examples
./run_example.sh <name_of_the_script>.py
```

Example to create a simple firewall:

```
./run_example.sh layer3_fw.py
```

On the first run, the script will:

- create a python3 virtual environment in ${repo_base}/smc/examples/.venv
- prompts you for connection informations
    - SMC_URL
    - WS_URL
    - API_KEY
    - API_VERSION
- create config file in ${repo_base}/smc_info.py

The SMC_URL is the url to access the smc management server. If you run
the tests on the local machine, the url will typically be
`http://localhost:8082` or `https://localhost:8082` depending if you
have configured tls on the management server.

The WS_URL is the url to access the websocket service (for logs and
monitoring). Typical value is 'ws://localhost:8082'

The API_KEY is obtained by creating a rest api client via the smc gui
(see configuration/admin menu in the gui)

The API_VERSION is 3 digits following the semantic versioning
format. Typically 6.10.0 or 7.0.0

to get the list of supported version (needs curl and jq)

```
curl -s http://localhost:8082/api|jq -r .version[].rel
6.10
6.11
7.0
```

## cleaning up

to remove the virtual env:

```
cd ${repo_base}/smc/examples
rm -rf .venv
```

to remove the config file:

```
cd ${repo_base}
rm smc_info.py
```

## running the script manually from git repo

you need to install the smc-python dependencies listed in setup.py

- pip3 install requests
- pip3 install pytz
- pip3 install websocket-client # only needed for monitoring

you need to create the config file 'smc_info.py' somewhere in your
PYTHONPATH, typically at the base of the repository

example:

```
cd ${repo_base}
cat smc_info.py
SMC_URL='http://localhost:8082'
WS_URL='ws://localhost:8082'
API_VERSION='7.0.0'
API_KEY='xxxxxxxxxxxxxxxxxxxx'
```

# troubleshooting

when using plain http, you can capture the http traffic using tcpflow:

```
sudo apt install tcpflow
sudo tcpflow -i any port 8082 -c|tee /tmp/flow.txt
```
