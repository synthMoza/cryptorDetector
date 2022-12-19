#!/bin/bash

JSON_CFG_PATH="fanotify_config.json"
CFG_PATH="fanotify_detector.service"
SYSTEMD_PATH="/etc/systemd/system"
OUTDIR_PATH="/etc/synthmoza"

cp $CFG_PATH $SYSTEMD_PATH
cp $JSON_CFG_PATH $OUTDIR_PATH