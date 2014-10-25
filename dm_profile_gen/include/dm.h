//taken from http://lxr.free-electrons.com/source/drivers/md/dm.c?v=3.5
#include <linux/bio.h>
#include <linux/hdreg.h>
/*
 * Work processed by per-device workqueue.
 */
struct __attribute__((__packed__))mapped_device {
        struct rw_semaphore io_lock;
        struct mutex suspend_lock;
        rwlock_t map_lock;
        atomic_t holders;
        atomic_t open_count;

        unsigned long flags;

        struct request_queue *queue;
        unsigned type;
        /* Protect queue and type against concurrent access. */
        struct mutex type_lock;

        struct target_type *immutable_target_type;

        struct gendisk *disk;
        char name[16];

        void *interface_ptr;

        /*
         * A list of ios that arrived while we were suspended.
         */
        atomic_t pending[2];
        wait_queue_head_t wait;
        struct work_struct work;
        struct bio_list deferred;
        spinlock_t deferred_lock;

        /*
         * Processing queue (flush)
         */
        struct workqueue_struct *wq;

        /*
         * The current mapping.
         */
        struct dm_table *map;

        /*
         * io objects are allocated from here.
         */
        mempool_t *io_pool;
        mempool_t *tio_pool;

        struct bio_set *bs;

        /*
         * Event handling.
         */
        atomic_t event_nr;
        wait_queue_head_t eventq;
        atomic_t uevent_seq;
        struct list_head uevent_list;
        spinlock_t uevent_lock; /* Protect access to uevent_list */

        /*
         * freeze/thaw support require holding onto a super block
         */
        struct super_block *frozen_sb;
        struct block_device *bdev;

        /* forced geometry settings */
        struct hd_geometry geometry;

        /* sysfs handle */
        struct kobject kobj;

        /* zero-length flush that will be cloned and submitted to targets */
        struct bio flush_bio;
};
