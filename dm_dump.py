# Copyright 2014 Curtis Carmony curtis.carmony@gmail.com

import binascii
from volatility import dwarf

import volatility.plugins.linux.common as linux_common
import volatility.obj as obj

"""
The purpose of this plugin is identify disks on the target system which were
mounted using the device-mapper framework. The modules supported by this
provided the default mechanism for full disk encryption (dm-crypt), the backend
for LVM (dm-linear), and others. Currently only these two targets are
explicitly supported, but the plugin will generate the device name,
target type, and size for every device-mapper instance on the system.

Once these disks are identified by the plugin, the information needed
to re-mount dm-crypt and dm-linear disks on a different system is extracted,
and presented in a format compatible with dmsetup's create command. You should
be able to take the output of this plugin verbatim, and pass it the the dmsetup
command, changing only the device name if different on the new system, and
successfully mount the device with a command like:

dmsetup create <mapper name> --table "<plugin output>"

For example, the Ubuntu 12.04 - 14.04 installers, when asked to setup full
disk encryption will setup dm-crypt target on top of the disk, and then setup
two dm-linear targets on top of that for the root and swap partitions. On such
a system this plugin will output (with the key removed for readability):

sda5_crypt: 0 16269312 crypt aes-xts-plain64 <key> 0 /dev/sda5 4096
ubuntu--vg-swap_1: 0 1040384 linear /dev/dm-0 15163776
ubuntu--vg-root: 0 15163392 linear /dev/dm-0 384

Assuming the the disk from the target system was placed in another and mapped
to /dev/sdb, we could remount the original filesystem with the following
commands:

sudo dmsetup create target_sda5_crypt --table "0 16269312 crypt aes-xts-plain64 <key> 0 /dev/sda5 4096"
sudo dmsetup create target_ubuntu--vg-root --table "0 15163392 linear /dev/dm-0 384"
sudo mount /device/mapper/target_ubuntu--vg-root /mnt

The original filesystem would then be accessible under /mnt/. Note: when
dmsetup creates a new device it uses the next available name of the form
"/dev/dm-". If you already have device mapper targets on your system you would
have to substitute "/dev/dm-0" in the second command with the correct name
given to the device created in the first.

In order to use this plugin you generate additional profile information with
the tool included in the dm_profile_gen directory. The mechanism used for
generating this profile is identical to the one used to generate the main
Linux profile except for that you don't need to compress the .dwarf file into
a .zip. You must specify the path to this file with the " --dm_profile" flag.

See https://code.google.com/p/cryptsetup/wiki/DMCrypt for more information
about the dm-crypt module, the dmsetup command, and it's table formats.

"""

class linux_dm_dump(linux_common.AbstractLinuxIntelCommand):
    """Traverses device-mapper data structures to look for devices mounted
    using that module and prints configuration strings to remount the found
    devices using dmsetup"""

    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args,
                                                   **kwargs)
        config.add_option("DM_PROFILE", default=None,
                          help="The profile containing the related dmtable "
                                "offset information.")

    # add the vtypes for this kernel and arch
    def _add_vtyptes(self):
        dwarf_file = open(self._config.DM_PROFILE)
        dwarf_data = dwarf_file.read()
        dm_vtypes = dwarf.DWARFParser(dwarf_data).finalize()
        self.addr_space.profile.vtypes.update(dm_vtypes)
        self.addr_space.profile.compile()

    def _dev_name(self, dev):
        # basically bdevname(), except for that we check to see if
        # c.dev.bdev.bd_disk.minors != 1, which indicates that the disk
        # can be partitioned before we add the partition number (this prevents
        # printing device strings like "/dev/dm-00"
        # http://lxr.free-electrons.com/source/block/partition
        # -generic.c?v=3.16#L46
        # http://lxr.free-electrons.com/source/include/linux/genhd.h
        # ?v=3.16#L165

        disk = "/dev/" + str(obj.Object(
            "String",
            offset=dev.bdev.bd_disk.disk_name.obj_offset,
            vm=self.addr_space,
            length=6
        ))

        if dev.bdev.bd_disk.minors != 1:
            disk += str(dev.bdev.bd_part.partno)

        return disk

    def calculate(self):
        # load the address space
        linux_common.set_plugin_members(self)
        # update the vtypes
        self._add_vtyptes()

        name_buckets = self.addr_space.profile.get_symbol("_name_buckets")

        for i in range(64):
            # compute the location in the array of our list_head
            nb_offset = i * self.addr_space.profile.get_obj_size(
                "list_head") + name_buckets

            # instantiate the list_head
            listHead = obj.Object("list_head", offset=nb_offset,
                                   vm=self.addr_space)

            cur = obj.Object("list_head", offset=listHead.next,
                             vm=self.addr_space)

            # if list_head.next == list_head, the list is empty
            while cur != listHead:
                # get the hash_cell struct that this list_head is embedded in
                hc = obj.Object("hash_cell", offset=cur.obj_offset,
                                vm=self.addr_space)

                hc_name = str(obj.Object(
                    "String",
                    offset=hc.name.v(),
                    vm=self.addr_space,
                    length=32
                ))

                type_name = str(obj.Object(
                    "String",
                    offset=hc.md.map.targets.type.name.v(),
                    vm=self.addr_space,
                    length=16
                ))

                # we use these fields in every case to get the start and size
                # of the mapping
                start = hc.md.map.targets.begin
                ssize = hc.md.map.targets.len

                if type_name == "crypt":
                    c = obj.Object(
                        "crypt_config",
                        offset=hc.md.map.targets.private.v(),
                        vm=self.addr_space
                    )

                    device = self._dev_name(c.dev)

                    # turn the key into ASCII hex
                    key = binascii.hexlify(bytearray(self.addr_space.read(
                        addr=c.key.obj_offset, length=c.key_size)))

                    cipher_string = str(obj.Object(
                        "String",
                        offset=c.cipher_string.v(),
                        vm=self.addr_space,
                        length=16
                    ))

                    # format is:
                    # start size target cipher_string key iv_offset device offset
                    # start is always 0, offset = c.start
                    yield "{}: {} {} crypt {} {} {} {} {}".format(
                        hc_name,
                        start,
                        ssize,
                        cipher_string,
                        key,
                        c.iv_offset,
                        device,
                        c.start,
                    )

                elif type_name == "linear":
                    l = obj.Object(
                        "linear_c",
                        offset=hc.md.map.targets.private.v(),
                        vm=self.addr_space
                    )

                    device = self._dev_name(l.dev)

                    # format is:
                    # start size target device offset
                    yield "{}: {} {} {} {} {}".format(
                        hc_name,
                        start,
                        ssize,
                        type_name,
                        device,
                        l.start
                    )

                # generic type
                else:
                    yield "{}: {} {} {}".format(
                        hc_name,
                        start,
                        ssize,
                        type_name
                    )

                cur = obj.Object("list_head", offset=cur.next,
                                 vm=self.addr_space)

    def render_text(self, outfd, data):
        for d in data:
            outfd.write(d + "\n")