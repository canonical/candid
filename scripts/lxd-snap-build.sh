#!/bin/sh
# lxd-snap-build.sh - build Candid snap in a clean LXD environment

set -eu

snap_name=${snap_name:-candid}
image=${image:-ubuntu:20.04}
container=${container:-${snap_name}-snap-`uuidgen`}

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
if [ -n "${http_proxy:-}" ]; then
	lxd_exec snap set system proxy.http=${http_proxy:-}
	lxd_exec snap set system proxy.https=${https_proxy:-${http_proxy:-}}
	lxd_exec_ubuntu git config --global http.proxy ${http_proxy:-}
fi
lxd_exec snap install snapcraft --classic
lxc file push --uid 1000 --gid 1000 --mode 600 ${NETRC:-$HOME/.netrc} $container/home/ubuntu/.netrc
lxd_exec_ubuntu mkdir -p /home/ubuntu/src
tar c -C `dirname $0`/.. . | cwd=/home/ubuntu/src lxd_exec_ubuntu tar x
target=
if [ -n "${target_arch:-}" ]; then
	target="--target-arch ${target_arch}"
fi
cwd=/home/ubuntu/src lxd_exec_ubuntu snapcraft --destructive-mode $target
snapfile=`lxd_exec_ubuntu find /home/ubuntu/src -name "${snap_name}_*.snap"| head -1`
lxc file pull $container$snapfile .
echo $snapfile
