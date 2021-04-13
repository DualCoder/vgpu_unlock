#!/bin/bash

# This file is part of the "vgpu_unlock" project, and is distributed under the MIT License.
# See the LICENSE file for more details.

help_func()
{
    echo "To make installing easier"
}

fixup_services()
{
    sed -i "s|ExecStart=/usr/bin/nvidia-vgpud|ExecStart=$PWD/vgpu_unlock /usr/bin/nvidia-vgpud|g" /lib/systemd/system/nvidia-vgpud.service
    sed -i "s|ExecStart=/usr/bin/nvidia-vgpu-mgr|ExecStart=$PWD/vgpu_unlock /usr/bin/nvidia-vgpu-mgr|g" /lib/systemd/system/nvidia-vgpu-mgr.service
    systemctl daemon-reload
    exit 1
}

fixup_driver()
{

}

while getopts ":v:" option; do
	case "${option}" in
		v)
			v=${OPTARG}
			;;
		*)
			help_function
			;;
   esac
done
shift $((OPTIND-1))
