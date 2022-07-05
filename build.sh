#!/bin/bash

with_args=""
for module in */ ; do
  module=${module%/*}
  with_args="$with_args--with packetframe_$module=./$module "
done
xcaddy build $with_args
