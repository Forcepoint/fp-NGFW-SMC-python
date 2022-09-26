#!/usr/bin/bash
#
# this script permits to run easily examples in smc/examples directory.
#
# During the first run, it will:
# - install a virtualenv with smc-python dependencies in .venv
# - prompt the user for SMC_URL, API_KEY and API_VERSION
#
# Requirements
#
# python3, pip3, virtualenv, git
#
# Example:
#
# cd <repo>/smc/examples && ./run_example.sh ./layer3_fw.py


if [ "$#" -ne 1 ]; then
    echo "usage $0 <example_name.py>"
    exit 1
fi

REPO=`git rev-parse --show-toplevel`
export VIRTUAL_ENV=.venv

if [[ ! -d "$VIRTUAL_ENV" ]]; then
    virtualenv -p python3 $VIRTUAL_ENV
    source $VIRTUAL_ENV/bin/activate
    pip3 install requests pytz websocket-client
else
    source $VIRTUAL_ENV/bin/activate
fi


if [[ ! -f "$REPO/smc_info.py" ]]; then

    read -e -p "Enter SMC_URL (default: http://localhost:8082) ? " SMC_URL
    read -e -p "Enter WS_URL (default: ws://localhost:8082) ? " WS_URL
    read -e -p "Enter API_KEY ? " API_KEY
    read -e -p "Enter API_VERSION (eg 6.10)? " API_VERSION

    if [[ -z "$API_KEY" ]]; then echo 'Error: API_KEY is empty. exiting'; exit 1; fi
    if [[ -z "$API_VERSION" ]]; then echo 'Error: API_VERSION is empty. exiting'; exit 1; fi
    if [[ -z "$SMC_URL" ]]; then SMC_URL="http://localhost:8082"; fi
    if [[ -z "$WS_URL" ]]; then WS_URL="ws://localhost:8082"; fi

echo "creating config file: $REPO/smc_info.py"

    echo "SMC_URL='$SMC_URL'
WS_URL='$WS_URL'
API_KEY='$API_KEY'
API_VERSION='$API_VERSION'
" >"$REPO/smc_info.py"
fi

echo "running script $*"
PYTHONPATH=$REPO:$REPO/smc-monitoring python3 $*
