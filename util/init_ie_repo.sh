#!/usr/bin/env bash
# -*- coding: utf-8 -*-
# vim: noai:et:tw=80:ts=2:ss=2:sts=2:sw=2:ft=bash

# Title:            init_repo.sh
# ==============================================================================

_pwd=$(basename $PWD)
if [[ ${_pwd} =~ util ]]
then
  cd ../
  REPO=$(basename $PWD)
  cd ${_pwd}
else
  REPO=$_pwd
fi
echo "Initializing ${REPO} ..."
git commit -a "Initial commit to ${REPO}"
git remote add origin "git@github.com:IE-OnDemand/${REPO}"
git push -u orign master

