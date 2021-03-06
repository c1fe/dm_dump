//from http://lxr.free-electrons.com/source/drivers/md/dm-table.c?v=3.0#L42
#define MAX_DEPTH 16
struct dm_table {
        struct mapped_device *md;
        atomic_t holders;
        unsigned type;

        /* btree table */
        unsigned int depth;
        unsigned int counts[MAX_DEPTH]; /* in nodes */
        sector_t *index[MAX_DEPTH];

        unsigned int num_targets;
        unsigned int num_allocated;
        sector_t *highs;
        struct dm_target *targets;

        unsigned discards_supported:1;
        unsigned integrity_supported:1;

        /*
         * Indicates the rw permissions for the new logical
         * device.  This should be a combination of FMODE_READ
         * and FMODE_WRITE.
         */
        fmode_t mode;

        /* a list of devices used by this table */
        struct list_head devices;

        /* events get handed up using this callback */
        void (*event_fn)(void *);
        void *event_context;

        struct dm_md_mempools *mempools;

        struct list_head target_callbacks;
};