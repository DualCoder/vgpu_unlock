# vgpu\_unlock

Unlock vGPU functionality for consumer grade GPUs.


## Important!

This tool is a work in progress. In the current state it does not work.


## Description

This tool enables the use of Geforce and Quadro GPUs with the NVIDIA vGPU
software. NVIDIA vGPU normally only supports a few Tesla GPUs but since some
Geforce and Quadro GPUs share the same physical chip as the Tesla this is only
a software limitation for those GPUs. This tool works by intercepting the ioctl
syscalls between the userspace nvidia-vgpud and nvidia-vgpu-mgr services and
the kernel driver. Doing this allows the script to alter the identification and
capabilities that the user space services relies on to determine if the GPU is
vGPU capable.


## Dependencies:

* This tool requires Python3, the latest version is recommended.
* The python package "frida" is required. `pip3 install frida`.
* The tool requires the NVIDIA GRID vGPU driver to be properly installed for it
  to do its job. This special driver is only accessible to NVIDIA enterprise
  customers. The script has only been tested with 11.3 for "KVM on Linux" and
  may or may not work on other versions.


## Installation:

The NVIDIA vGPU drivers will create an nvidia-vgpud and nvidia-vgpu-mgr 
systemd service. All we have to do is replace the path
/usr/bin/<executable> in /lib/systemd/system/nvidia-vgpud.service and
/lib/systemd/system/nvidia-vgpu-mgr.service with the path to the vgpu\_unlock
script and pass the original executable path as the first argument.

---
**NOTE**

This script will only work if there exists a vGPU compatible Tesla GPU that
uses the same physical chip as the actual GPU being used.
---
