#!/bin/sh
set -e

NETNS_NAME=netd

_log_info() {
	printf "$(tput setaf 5)-->$(tput setaf 2) %s$(tput setaf 7)\n" "$@"
}

_log_error() {
	printf "$(tput setaf 6)-->$(tput setaf 9) %s$(tput setaf 7)\n" "$@"
	exit 1
}

[ "$(id -u)" != 0 ] && _log_error "This program must be run as root"

_usage() {
	prog=$(basename "$0")
	echo "Usage:"
	echo "    $prog [ c | create ] create the namespace"
	echo "    $prog [ e | enter ] enter the namespace"
	echo "    $prog [ d | delete ] delete the namespace"
	exit 1
}

_namespace_create() {
	if ip netns | grep "$NETNS_NAME"; then
		_log_info "The netns $NETNS_NAME is already created"
		return
	fi

	ip netns add "$NETNS_NAME"
}

_namespace_enter() {
	PS1="[netns:$NETNS_NAME] # " sudo ip netns exec "$NETNS_NAME" sh
}

_namespace_delete() {
	ip netns delete "$NETNS_NAME"
}

case $1 in
	c|create)  _namespace_create ;;
	e|enter)   _namespace_enter  ;;
	d|delete)  _namespace_delete ;;
	*)         _usage            ;;
esac
