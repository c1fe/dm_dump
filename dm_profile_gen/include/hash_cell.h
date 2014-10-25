//from http://lxr.free-electrons.com/source/drivers/md/dm-ioctl.c?v=3.5

struct dm_table;

struct hash_cell {
        struct list_head name_list;
		struct list_head uuid_list;
        char *name;
        char *uuid;
        struct mapped_device *md;
        struct dm_table *new_map;
};
