#!/bin/bash

help_function()
{
	echo "This script checks for the internal names of vGPU profiles."
	echo
	echo "Usage: $0 [-h] [-p <[VGPU_NAME]|ALL>]"
	echo "Options:"
	echo "-h   Display the help page."
	echo "-p   Display selected VGPU_NAME or ALL profiles."
	exit 0;
}

process_id()
{
	echo "$(cat "$1"/name): $(basename "$1" | cut -d '/' -f 8)"
}

list_all_ids()
{
	for gpu in $(lspci -Dd 10de: -s 0 -n | awk '$2 ~ /030[02]/{print $1}'); do
		if [ -d "/sys/bus/pci/devices/$gpu/mdev_supported_types/" ]; then
			for gpu_type in /sys/bus/pci/devices/"$gpu"/mdev_supported_types/* ; do
				process_id "$gpu_type"
			done
			exit
		fi
	done
}

get_pciid()
{
	for gpu in $(lspci -Dd 10de: -s 0 -n | awk '$2 ~ /030[02]/{print $1}'); do
		if [ -d "/sys/bus/pci/devices/$gpu/mdev_supported_types/" ]; then
			if [ ! -z "$(grep -l "$1" /sys/bus/pci/devices/"$gpu"/mdev_supported_types/nvidia-*/name)" ]; then
				grep -l "$1" /sys/bus/pci/devices/"$gpu"/mdev_supported_types/nvidia-*/name | cut -d '/' -f 8
				exit
			fi
		fi
	done
}

while getopts ":p:" option; do
	case "${option}" in
		p)
			p=${OPTARG}
			;;
		*)
			help_function
			;;
   esac
done
shift $((OPTIND-1))

if [ -z "${p}" ]; then
	help_function
fi

if [ "$p" = "ALL" ]; then
	list_all_ids
else
	get_pciid "$p"
fi

exit 1
