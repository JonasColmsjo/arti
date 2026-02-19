#!/bin/bash
# Volatility 3 wrapper script
~/micromamba-volatility3/bin/python -c "from volatility3 import cli; import sys; cli.main()" "$@"
