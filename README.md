# vgpu\_unlock

Unlock vGPU functionality for consumer-grade Nvidia GPUs.


## Important!

This tool is not guarenteed to work out of the box in some cases, 
so use it at your own risk.


## Description

This tool enables the use of Geforce and Quadro GPUs with the NVIDIA vGPU
software. NVIDIA vGPU normally only supports a few datacenter Tesla and
professional Quadro GPUs by design, but not consumer graphics cards through a
software limitation. This vgpu_unlock tool aims to remove this limitation, thus
enabling most Maxwell, Pascal, Volta (untested), and Turing based GPUs to use
the vGPU technology. Ampere support is currently a work in progress.  
  
A community maintained Wiki written by Krutav Shah with a lot more information 
is [available here.](https://docs.google.com/document/d/1pzrWJ9h-zANCtyqRgS7Vzla0Y8Ea2-5z2HEi4X75d2Q/edit?usp=sharing)


## Dependencies:

* This tool requires Python3, the latest version is recommended.
* The python package "frida" is required. `pip3 install frida`.
* The tool requires the NVIDIA GRID vGPU driver.
* "dkms" is required as it simplifies the process of rebuilding the
  driver alot. Install DKMS with the package manager in your OS.


## Installation:

In the following instructions `<path_to_vgpu_unlock>` need to be replaced with
the path to this repository on the target system and `<version>` need to be
replaced with the version of the NVIDIA GRID vGPU driver.

Install the NVIDIA GRID vGPU driver, make sure to install it as a dkms module.
```
./nvidia-installer --dkms
```

Modify the line begining with `ExecStart=` in `/lib/systemd/system/nvidia-vgpud.service`
and `/lib/systemd/system/nvidia-vgpu-mgr.service` to use `vgpu_unlock` as
executable and pass the original executable as the first argument. Ex:
```
ExecStart=<path_to_vgpu_unlock>/vgpu_unlock /usr/bin/nvidia-vgpud
```

Reload the systemd daemons:
```
systemctl daemon-reload
```

Modify the file `/usr/src/nvidia-<version>/nvidia/os-interface.c` and add the
following line after the lines begining with `#include` at the beginning of the
file.
```
#include "<path_to_vgpu_unlock>/vgpu_unlock_hooks.c"
```

Modify the file `/usr/src/nvidia-<version>/nvidia/nvidia.Kbuild` and add the
following line at the bottom of the file.
```
ldflags-y += -T <path_to_vgpu_unlock>/kern.ld
```

Remove the nvidia kernel module using dkms:
```
dkms remove -m nvidia -v <version> --all
```

Rebuild and reinstall the nvidia kernel module using dkms:
```
dkms install -m nvidia -v <version>
```

Reboot.

---
**NOTE**

This script only works with graphics cards in the same generation as their professional Tesla counterparts.
As a result, only Maxwell and newer generation Nvidia GPUs are supported. It is not designed to be used with
low end graphics card models, so not all cards are guarenteed to work smoothly with vGPU. For the best experience,
it is recommended to use graphics cards with the same chip model as the Tesla cards. The same applies to the
operating system as well, as certain bleeding-edge Linux distributions may not work well with vGPU software.

---

## How it works

### vGPU supported?

In order to determine if a certain GPU supports the vGPU functionality the
driver looks at the PCI device ID. This identifier together with the PCI vendor
ID is unique for each type of PCI device. In order to enable vGPU support we
need to tell the driver that the PCI device ID of the installed GPU is one of
the device IDs used by a vGPU capable GPU.

### Userspace script: vgpu\_unlock

The userspace services nvidia-vgpud and nvidia-vgpu-mgr uses the ioctl syscall
to communicate with the kernel module. Specifically they read the PCI device ID
and determines if the installed GPU is vGPU capable.

The python script vgpu\_unlock intercepts all ioctl syscalls between the
executable specified as the first argument and the kernel. The script then
modifies the kernel responses to indicate a PCI device ID with vGPU support
and a vGPU capable GPU.

### Kernel module hooks: vgpu\_unlock\_hooks.c

In order to exchange data with the GPU the kernel module maps the physical
address space of the PCI bus into its own virtual address space. This is done
using the ioremap\* kernel functions. The kernel module then reads and writes
data into that mapped address space. This is done using the memcpy kernel
function.

By including the vgpu\_unlock\_hooks.c file into the os-interface.c file we can
use C preprocessor macros to replace and intercept calls to the iormeap and
memcpy functions. Doing this allows us to maintain a view of what is mapped
where and what data that is being accessed.

### Kernel module linker script: kern.ld

This is a modified version of the default linker script provided by gcc. The
script is modified to place the .rodata section of nv-kernel.o into .data
section instead of .rodata, making it writable. The script also provide the
symbols `vgpu_unlock_nv_kern_rodata_beg` and `vgpu_unlock_nv_kern_rodata_end`
to let us know where that section begins and ends.

### How it all comes together

After boot the nvidia-vgpud service queries the kernel for all installed GPUs
and checks for vGPU capability. This call is intercepted by the vgpu\_unlock
python script and the GPU is made vGPU capable. If a vGPU capable GPU is found
then nvidia-vgpu creates an MDEV device and the /sys/class/mdev\_bus directory
is created by the system.

vGPU devices can now be created by echoing UUIDs into the `create` files in the
mdev bus representation. This will create additional structures representing
the new vGPU device on the MDEV bus. These devices can then be assigned to VMs,
and when the VM starts it will open the MDEV device. This causes nvidia-vgpu-mgr
to start communicating with the kernel using ioctl. Again these calls are
intercepted by the vgpu\_unlock python script and when nvidia-vgpu-mgr asks if
the GPU is vGPU capable the answer is changed to yes. After that check it
attempts to initialize the vGPU device instance.

Initialization of the vGPU device is handled by the kernel module and it
performs its own check for vGPU capability, this one is a bit more complicated.

The kernel module maps the physical PCI address range 0xf0000000-0xf1000000 into
its virtual address space, it then performs some magical operations which we
don't really know what they do. What we do know is that after these operations
it accesses a 128 bit value at physical address 0xf0029624, which we call the
magic value. The kernel module also accessses a 128 bit value at physical 
address 0xf0029634, which we call the key value.

The kernel module then has a couple of lookup tables for the magic value, one
for vGPU capable GPUs and one for the others. So the kernel module looks for the
magic value in both of these lookup tables, and if it is found that table entry
also contains a set of AES-128 encrypted data blocks and a HMAC-SHA256
signature.

The signature is then validated by using the key value mentioned earlier to
calculate the HMAC-SHA256 signature over the encrypted data blocks. If the
signature is correct, then the blocks are decrypted using AES-128 and the same
key.

Inside of the decrypted data is once again the PCI device ID.

So in order for the kernel module to accept the GPU as vGPU capable the magic
value will have to be in the table of vGPU capable magic values, the key has
to generate a valid HMAC-SHA256 signature and the AES-128 decrypted data blocks
has to contain a vGPU capable PCI device ID. If any of these checks fail, then
the error code 0x56 "Call not supported" is returned.

In order to make these checks pass the hooks in vgpu\_unlock\_hooks.c will look
for a ioremap call that maps the physical address range that contain the magic
and key values, recalculate the addresses of those values into the virtual
address space of the kernel module, monitor memcpy operations reading at those
addresses, and if such an operation occurs, keep a copy of the value until both
are known, locate the lookup tables in the .rodata section of nv-kernel.o, find
the signature and data bocks, validate the signature, decrypt the blocks, edit
the PCI device ID in the decrypted data, reencrypt the blocks, regenerate the
signature and insert the magic, blocks and signature into the table of vGPU
capable magic values. And that's what they do.

