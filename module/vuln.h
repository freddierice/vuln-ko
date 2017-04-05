#ifndef __VULN_H__
#define __VULN_H__

// vuln ioctl codes
#define VULN_SET_FUNC	0x100 // void *func
#define VULN_SET_ARG1	0x101 // void *arg1
#define VULN_SET_ARG2	0x102 // void *arg2
#define VULN_SET_ARG3	0x103 // void *arg3
#define VULN_SET_ARG4	0x104 // void *arg4
#define VULN_GET_DATA	0x105 // void *data
#define VULN_GET_ROOT   0x106 // void *func
#define VULN_SET_DATA   0x107 // char data[PAGE_SIZE]
#define VULN_TRIGGER    0x108 // 

#endif
