/*
 Modified from tools/linux/module.c
 These are the different struct verions for Linux kernel versions 3.0 - 3.14. The plugins should also work for
 older and newer kernel versions, these are just the ones I collected struct information for.
 Each struct version is labeled with the first kernel version in which it appears. The hash_cell struct is the 
 same for all of these kernel versions. 

dm-crypt structs
| struct        | 3.0 | 3.1 | 3.2 | 3.3 | 3.4 | 3.5 | 3.6 | 3.7 | 3.8 | 3.9 | 3.10 | 3.11 | 3.12 | 3.13 | 3.14 |
| dm_table      | 3.0                                                       | 3.10                             |
| mapped_device | 3.0       | 3.2                                                  | 3.11^                     |
| crypt_config  | 3.0                               | 3.6                                        | 3.13        |

dm-linear only relies on the linear_c struct which does not change for Linux versions 3.0 - 3.14

^The mapped device struct changes in version 3.8, but it doesn't affect the elements we care about.

*/ 

#include <linux/version.h>

// for dm_dev, target_type
#include <linux/device-mapper.h>

// for hd_struct, gendisk
#include <linux/genhd.h>

/*********** structs only in C files ***********/
#include "include/hash_cell.h"

// first make sure the version is supported
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0) || LINUX_VERSION_CODE > KERNEL_VERSION(3,14,0)
#error Only Linux versions 3.0.0 - 3.14.0 are currenly supported
#endif

// dm_table from drivers/md/dm-table.c
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#include "include/dm_table-3.0.h"
#else
#include "include/dm_table-3.10.h"
#endif

//mapped_device from drivers/md/dm.c
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)
#include "include/mapped_device-3.0.h"
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
#include "include/mapped_device-3.2.h"
#else
#include "include/mapped_device-3.11.h"
#endif

//crypt_config from drivers/md/dm-crypt.c
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
#include "include/crypt_config-3.0.h"
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
#include "include/crypt_config-3.6.h"
#else
#include "include/crypt_config-3.13.h"
#endif

//lincear_c from drivers/md/dm-linear.c
#include "include/linear_c.h"

//make sure our structs get included
struct hash_cell hash_cell;
struct gendisk;
struct dm_table dm_table;
struct mapped_device mapped_device;
struct crypt_config crypt_config;
struct linear_c linear_c;