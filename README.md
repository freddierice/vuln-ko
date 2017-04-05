# vuln-ko
A vulnerable kernel module for facilitating the testing of exploits. 

## how it works
The `vuln.ko` module creates a character device at `/dev/vuln` with permissions `0666`. To interface with the kernel module, make `ioctl` calls to the file. Here are some key ioctl calls: 
 - `VULN_SET_FUNC` sets the function pointer that will get called by the kernel module.
 - `VULN_SET_ARG1` sets the first argument to the function set in `VULN_SET_FUNC`.
 - `VULN_GET_DATA` returns a pointer to a page of space in the kernel.
 - `VULN_SET_DATA` allows a userspace program to write up to a page of bytes to memory that lies in the kernel at the address pointed by `VULN_GET_DATA`. This is particularly useful for testing ROP payloads.
 - `VULN_GET_ROOT` returns a pointer to a function that calls `commit_creds(prepare_kernel_cred(0))`.
 - `VULN_TRIGGER` calls the function pointer set by `VULN_SET_FUNC` on the arguments set by `VULN_SET_ARG1` through `VULN_SET_ARG4`.

## run example 
```
make
sudo insmod ./module/vuln.ko
./example/example
current uid: 1000
triggering exploit...
current uid: 0
```
