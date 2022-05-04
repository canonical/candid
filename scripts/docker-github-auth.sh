#!/bin/bash -e

if [[ ! -z "${GH_SSH_KEY}" ]]; then
  echo 'Using SSH auth ($GH_SSH_KEY)'
  mkdir $HOME/.ssh/
  echo "$GH_SSH_KEY" > $HOME/.ssh/id_rsa
  chmod 600 $HOME/.ssh/id_rsa
  touch $HOME/.ssh/known_hosts
  ssh-keyscan github.com >> $HOME/.ssh/known_hosts
  git config --global --add url."git@github.com:".insteadOf "https://github.com/"
elif [[ ! -z "${GH_USERNAME}" ]]; then
  echo 'Using basic auth ($GH_USERNAME and $GH_PASSWORD)'
  echo "machine github.com login $GH_USERNAME password $GH_PASSWORD" > $HOME/.netrc
  chmod 600 $HOME/.netrc
else
  echo 'No Github SSH or basic auth credentials. Doing nothing.'
fi
