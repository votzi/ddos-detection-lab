#!/usr/bin/env bash

service openvswitch-switch start

if [ $# -gt 0 ]
then
  if [ "$1" == "mn" ]
  then
    bash -c "$@"
  else
    mn "$@"
  fi
else
  bash
fi

service openvswitch-switch stop
