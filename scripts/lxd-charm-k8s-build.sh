#!/bin/sh
# lxd-snap-build.sh - build Candid charm in a clean LXD environment

set -eu

charm_name=candid-k8s
image=${image:-ubuntu:20.04}
container=${container:-${charm_name}-charm-`uuidgen`}

lxd_exec() {
	lxc exec \
		--env http_proxy=${http_proxy:-} \
		--env https_proxy=${https_proxy:-${http_proxy:-}} \
		--env no_proxy=${no_proxy:-} \
		$container -- "$@"
}

lxd_exec_ubuntu() {
	lxc exec \
		--env HOME=/home/ubuntu \
		--env http_proxy=${http_proxy:-} \
		--env https_proxy=${https_proxy:-${http_proxy:-}} \
		--env no_proxy=${no_proxy:-} \
		--user 1000 \
		--group 1000 \
		--cwd=${cwd:-/home/ubuntu} \
		$container -- "$@"
}

lxc launch -e ${image} $container
trap "lxc stop $container" EXIT

lxd_exec sh -c 'while [ ! -f /var/lib/cloud/instance/boot-finished ]; do sleep 0.1; done'

lxd_exec apt-get update -q -y
lxd_exec apt-get upgrade -q -y
lxd_exec apt-get install -y build-essential autoconf python-dev-is-python3
if [ -n "${http_proxy:-}" ]; then
	lxd_exec snap set system proxy.http=${http_proxy:-}
	lxd_exec snap set system proxy.https=${https_proxy:-${http_proxy:-}}
	lxd_exec_ubuntu git config --global http.proxy ${http_proxy:-}
fi
lxd_exec snap install charmcraft --classic
echo "Push .netrc"
lxc file push --uid 1000 --gid 1000 --mode 600 ${NETRC:-$HOME/.netrc} $container/home/ubuntu/.netrc
echo "Create src"
lxd_exec_ubuntu mkdir -p /home/ubuntu/src
echo "Transfer data"
tar c -C `dirname $0`/.. . | cwd=/home/ubuntu/src lxd_exec_ubuntu tar x


echo "Charmcraft build"
cwd=/home/ubuntu/src/charms/candid-k8s lxd_exec_ubuntu sudo -E charmcraft pack --verbose --destructive-mode
echo "Find file"
charmfile=`lxd_exec_ubuntu find /home/ubuntu/src/charms/candid-k8s -name "${charm_name}_*.charm"| head -1`
echo "Pull file"
lxc file pull $container$charmfile .
