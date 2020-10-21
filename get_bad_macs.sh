#!/usr/bin/env sh
# -*- coding: utf-8 -*-
# vim: noai:et:tw=80:ts=2:ss=2:sts=2:sw=2:ft=sh

# Title:            get_bad_macs.sh
# Description:      Uses 'macfinder' to get MACs for names in file.
# Author:           Ricky Laney
# Version:          0.1.0
# ==============================================================================

_res=./results.txt

if [[ -f $_res ]]
then
  rm $_res
fi
touch $_res

for line in $(cat ./bad_companies.txt)
do
  echo "Manufacturer: $line" >> $_res
  ./src/macfinder.py --name $line >> $_res
done

exit 0
