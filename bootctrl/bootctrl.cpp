/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hardware/hardware.h>
#include <hardware/boot_control.h>
#include <android-base/logging.h>
#include <cutils/properties.h>
#define LOG_TAG "bootctrlHAL"
#include <log/log.h>

#include "bootctrl.h"
#include "recovery.h"

#if !defined(ARCH_X86)
#include "headers/ufs-mtk-ioctl.h"
#include "headers/mmc-mtk-ioctl.h"
#include <sys/ioctl.h>
#endif
#include <fstab.h>
#include "avb/libavb/avb_util.h"
#include <bootloader_message/bootloader_message.h>

using android::fs_mgr::Fstab;
using android::fs_mgr::GetEntryForMountPoint;
using android::fs_mgr::ReadDefaultFstab;

static char *blk_dev_path = NULL;

static int bootctrl_read_metadata(AvbABData *bctrl)
{
    int fd, err;
    ssize_t sz, size;
    char *buf = (char *)bctrl;

    fd = open(blk_dev_path, O_RDONLY);
    if (fd < 0) {
        err = errno;
        ALOGE("%s Error opening metadata file: %s\n", __func__ ,strerror(errno));
        return -err;
    }
    if (lseek(fd, OFFSETOF_SLOT_SUFFIX, SEEK_SET) < 0) {
        err = errno;
        ALOGE("%s Error seeking to metadata offset: %s\n", __func__ ,strerror(errno));
        close(fd);
        return -err;
    }
    size = sizeof(AvbABData);

    do {
        sz = read(fd, buf, size);
        if (sz == 0) {
            break;
        } else if (sz < 0) {
            if (errno == EINTR) {
                continue;
            }
            err = -errno;
            ALOGE("%s Error reading metadata file\n", __func__);
            close(fd);
            return err;
        }
        size -= sz;
        buf += sz;
    } while(size > 0);

    close(fd);

    /* Check bootctrl magic number */
    if (memcmp(bctrl->magic , AVB_AB_MAGIC, AVB_AB_MAGIC_LEN) != 0) {
        ALOGE("metadata is not initialised or corrupted.\n");
        return -EIO;
    }
    return 0;
}

static int bootctrl_read_metadata_offset(boot_ctrl_t *bctrl,int offset)
{
    int fd, err;
    ssize_t sz, size;
    char *buf = (char *)bctrl;

    fd = open(blk_dev_path, O_RDONLY);
    if (fd < 0) {
        err = errno;
        ALOGE("%s Error opening metadata file: %s\n", __func__ ,strerror(errno));
        return -err;
    }
    if (lseek(fd, OFFSETOF_SLOT_SUFFIX + offset, SEEK_SET) < 0) {
        err = errno;
        ALOGE("%s Error seeking to metadata offset: %s\n", __func__ ,strerror(errno));
        close(fd);
        return -err;
    }
    size = sizeof(boot_ctrl_t);

    do {
        sz = read(fd, buf, size);
        if (sz == 0) {
            break;
        } else if (sz < 0) {
            if (errno == EINTR) {
                continue;
            }
            err = -errno;
            ALOGE("%s Error reading metadata file\n", __func__);
            close(fd);
            return err;
        }
        size -= sz;
        buf += sz;
    } while(size > 0);

    close(fd);

    /* Check bootctrl magic number */
    if (bctrl->magic == BOOTCTRL_MAGIC) {
        ALOGE("backup exist, need restore.\n");
        return 1;
    }
    return 0;
}
static int bootctrl_write_metadata_bootctrv1(boot_ctrl_t *bctrl)
{
    int fd, err;
    ssize_t sz, size;
    char *buf = (char *)bctrl;

    fd = open(blk_dev_path, O_RDWR);
    if (fd < 0) {
        err = errno;
        ALOGE("%s Error opening metadata file: %s\n", __func__,strerror(errno));
        return -err;
    }

    if (lseek(fd, OFFSETOF_SLOT_SUFFIX, SEEK_SET) < 0) {
        err = errno;
        ALOGE("%s Error seeking to metadata offset: %s\n", __func__ ,strerror(errno));
        close(fd);
        return -err;
    }
    size = sizeof(boot_ctrl_t);
    do {
        sz = write(fd, buf, size);
        if (sz == 0) {
            break;
        } else if (sz < 0) {
            if (errno == EINTR) {
                continue;
            }
            err = -errno;
            ALOGE("%s Error Writing metadata file\n",__func__);
            close(fd);
            return err;
        }
        size -= sz;
        buf += sz;
    } while(size > 0);

    close(fd);
    return 0;
}


static int bootctrl_write_metadata(AvbABData *bctrl)
{
    int fd, err;
    ssize_t sz, size;
    char *buf = (char *)bctrl;

    fd = open(blk_dev_path, O_RDWR);
    if (fd < 0) {
        err = errno;
        ALOGE("%s Error opening metadata file: %s\n", __func__,strerror(errno));
        return -err;
    }

    if (lseek(fd, OFFSETOF_SLOT_SUFFIX, SEEK_SET) < 0) {
        err = errno;
        ALOGE("%s Error seeking to metadata offset: %s\n", __func__ ,strerror(errno));
        close(fd);
        return -err;
    }
    size = sizeof(AvbABData);
    bctrl->crc32 = avb_htobe32(
             avb_crc32((const uint8_t*)bctrl, sizeof(AvbABData) - sizeof(uint32_t)));
    do {
        sz = write(fd, buf, size);
        if (sz == 0) {
            break;
        } else if (sz < 0) {
            if (errno == EINTR) {
                continue;
            }
            err = -errno;
            ALOGE("%s Error Writing metadata file\n",__func__);
            close(fd);
            return err;
        }
        size -= sz;
        buf += sz;
    } while(size > 0);

    close(fd);
    return 0;
}

void bootctrl_init(boot_control_module_t *module __unused)
{
    static Fstab fstab;
    ALOGI("boot control HAL init");

    if(blk_dev_path == NULL) {
        /* Initial read fstab */
        if(!ReadDefaultFstab(&fstab)) {
            ALOGE("bootctrl read fstab fail\n");
            return;
        }

        auto v = GetEntryForMountPoint(&fstab, "/misc");
        if (v == nullptr) {
            LOG(ERROR)<<"failed to get block device path by mount point";
            return;
        }

        blk_dev_path = strdup(v->blk_device.c_str());
    }

    ALOGI("%s misc blk device path = %s\n", __func__ ,blk_dev_path);
}

unsigned bootctrl_get_number_slots(boot_control_module_t *module __unused)
{
    return 2;
}

int bootctrl_get_active_slot()
{
    int fd, err, slot;
    ssize_t size = COMMAND_LINE_SIZE, sz;
    char *buf, *ptr;
    char *str;

    fd = open(COMMAND_LINE_PATH, O_RDONLY);
    if (fd < 0) {
        err = -errno;
        ALOGE("%s error reading commandline\n", __func__);
        return err;
    }
    ptr = buf = (char *)malloc(size);
    if (!buf) {
        err = -errno;
        ALOGE("%s Error allocating memory\n", __func__);
        close(fd);
        return err;
    }
    do {
        sz = read(fd, buf, size);
        if (sz == 0) {
            break;
        } else if (sz < 0) {
            if (errno == EINTR) {
                continue;
            }
            err = -errno;
            ALOGE("%s Error reading file\n",__func__);
            free(ptr);
            close(fd);
            return err;
        }
        size -= sz;
        buf += sz;
    } while(size > 0);
    str = strstr((char *)ptr, SLOT_SUFFIX_STR);
    if (!str) {
        err = -EIO;
        ALOGE("%s cannot find %s in kernel commandline.\n", __func__ , SLOT_SUFFIX_STR);
        free(ptr);
        close(fd);
        return err;
    }
    str += sizeof(SLOT_SUFFIX_STR);
    slot = (*str == 'a') ? 0 : 1;
    free(ptr);
    close(fd);

    return slot;
}

static int mmc_read_extcsd(int fd, __u8 *ext_csd)
{
    int ret = 0;
    struct mmc_ioc_cmd mmc_ioctl_cmd;

    memset(ext_csd, 0, sizeof(__u8) * 512);
    memset(&mmc_ioctl_cmd, 0, sizeof(mmc_ioctl_cmd));
    mmc_ioctl_cmd.blocks = 1;
    mmc_ioctl_cmd.blksz = 512;
    mmc_ioctl_cmd.opcode = MMC_SEND_EXT_CSD;
    mmc_ioctl_cmd.flags = MMC_CMD_ADTC | MMC_RSP_R1;
    mmc_ioc_cmd_set_data(mmc_ioctl_cmd, ext_csd);

    ret = ioctl(fd, MMC_IOC_CMD, &mmc_ioctl_cmd);

    if (ret)
        ALOGE("ioctl error, mmc_read_extcsd fail, ret = %d\n", ret);
    return ret;
}

static int mmc_switch_bootpart(int fd, __u8 *ext_csd, __u8 bootpart)
{
    int ret = 0;
    struct mmc_ioc_cmd mmc_ioctl_cmd;
    __u8 val;

    val = (ext_csd[EXT_CSD_PART_CONFIG] & ~(0x38)) | (bootpart << 3);
    memset(&mmc_ioctl_cmd, 0, sizeof(mmc_ioctl_cmd));
    mmc_ioctl_cmd.opcode = MMC_SWITCH;

    mmc_ioctl_cmd.arg = (MMC_SWITCH_MODE_WRITE_BYTE << 24)
        | (EXT_CSD_PART_CONFIG << 16)
        | val << 8
        | EXT_CSD_CMD_SET_NORMAL;
    mmc_ioctl_cmd.flags = MMC_CMD_AC | MMC_RSP_R1B;
    mmc_ioc_cmd_set_data(mmc_ioctl_cmd, ext_csd);

    ret = ioctl(fd, MMC_IOC_CMD, &mmc_ioctl_cmd);
    if (ret)
        ALOGE("ioctl error, mmc_switch_bootpart fail ret = %d\n", ret);
    return ret;
}

static int emmc_set_active_boot_part(int bootpart)
{
    __u8 ext_csd[512];
    __u8 cur_bootpart;
    int ret;
    int fd= open("/dev/block/mmcblk0", O_RDWR);
    if (fd >= 0) {
        ret = mmc_read_extcsd(fd, ext_csd);
        if (ret) {
            ALOGE("Could not read EXT_CSD, error=%d\n", ret);
            close(fd);
            return 1;
        }

        /* check current boot part */
        cur_bootpart = (ext_csd[EXT_CSD_PART_CONFIG] >> 3) & 0x7;
        if (cur_bootpart == bootpart)
        {
            ALOGI("Current boot part is boot%d, no neeed switch\n", cur_bootpart);
            printf("Current boot part is boot%d, no neeed switch\n", cur_bootpart);
        } else {
            ALOGI("Current boot part is boot%d, need switch to %d\n",cur_bootpart, bootpart);
            printf("Current boot part is boot%d, need switch to %d\n",cur_bootpart, bootpart);
            ret = mmc_switch_bootpart(fd, ext_csd, bootpart);
                if(ret) {
                    ALOGE("Could not switch boot part, error=%d\n", ret);
                    close(fd);
                    return 1;
                }
        }
        close(fd);
        return 0;
        } else {
            ALOGE("open /dev/block/mmcblk0 fail\n");
            return 1;
        }
}

static int ufs_set_active_boot_part(int boot)
{
    struct ufs_ioctl_query_data idata;
    unsigned char buf[1];
    int fd, ret = 0;

    fd = open("/dev/block/sdc", O_RDWR);

    if (fd < 0) {
        printf("%s: open device failed, err: %d\n", __func__, fd);
        ret = -1;
        goto out;
    }

    buf[0] = boot;           /* 1: BootLU A, 2: BootLU B */

    idata.opcode = UPIU_QUERY_OPCODE_WRITE_ATTR;
    idata.idn = QUERY_ATTR_IDN_BOOT_LUN_EN;
    idata.idx = 0;
    idata.buf_ptr = &buf[0];
    idata.buf_byte = 1;

    ret = ioctl(fd, UFS_IOCTL_QUERY, &idata);
    if(ret < 0)
        printf("ufs_set boot_part fail: %s\n", strerror(errno));
out:
    if(fd >= 0)
        close(fd);
    return ret;
}

static int get_boot_type(void) {
    int fd;
    size_t s;
    char boot_type[4] = {'0'};

    fd = open("/sys/class/BOOT/BOOT/boot/boot_type", O_RDONLY);
    if (fd < 0) {
        ALOGE("fail to open: %s\n", "/sys/class/BOOT/BOOT/boot/boot_type");
        return -1;
    }

    s = read(fd, boot_type, sizeof(boot_type) - 1);
    close(fd);

    if (s <= 0) {
        ALOGE("could not read boot type sys file\n");
        return -1;
    }

    boot_type[s] = '\0';

    return atoi(boot_type);
}

static int set_ota_result(int result, int offset) {

    if (blk_dev_path == NULL) {
      printf("Error: blk_dev_path is NULL\n");
      return -1;
    }

    int dev = -1;
    int count;

    dev = open(blk_dev_path, O_WRONLY | O_SYNC);
    if (dev < 0)  {
        printf("Can't open %s\n(%s)\n", blk_dev_path, strerror(errno));
        return -1;
    }

    if (lseek(dev, offset, SEEK_SET) == -1) {
        printf("Failed seeking %s\n(%s)\n", blk_dev_path, strerror(errno));
        close(dev);
        return -1;
    }

    count = write(dev, &result, sizeof(result));
    if (count != sizeof(result)) {
        printf("Failed writing %s\n(%s)\n", blk_dev_path, strerror(errno));
        close(dev);
        return -1;
    }
    if (close(dev) != 0) {
        printf("Failed closing %s\n(%s)\n", blk_dev_path, strerror(errno));
        return -1;
    }
    sync();
    return 1;
}


static int SetOTAResultForDMVerity(void) {

    int ota_result_offset, ret = -1;
    ota_result_offset = sizeof(bootloader_message_ab);
    ret = set_ota_result(1, ota_result_offset);
    return ret;
}


int switch_pl_boot_part(unsigned slot)
{
    int ret = 0;
    int boot_part = 0;
    boot_ctrl_t metadata;
    slot_metadata_t *slotp;

    /* slot 0 is A , slot 1 is B */
    if (slot >= 2) {
        ALOGE("%s Wrong Slot value %u\n", __func__ , slot);
        return -1;
    }

    if(slot)
      boot_part = 2;
    else
      boot_part = 1;

    int mt_boot_type = get_boot_type();

    if(mt_boot_type  == -1) {
        ALOGI("Get boot type failed then use default device type\n");
        mt_boot_type = FS_TYPE_EMMC;
    }
    if(slot ==1)
    {
        //restore backup bootctrv1
        if(bootctrl_read_metadata_offset(&metadata,32))
        {
            slotp = &metadata.slot_info[1];
            slotp->successful_boot = 0;
            slotp->priority = 7;
            slotp->retry_count = 3;
            slotp->normal_boot = 1;
            slotp = &metadata.slot_info[0];
            slotp->successful_boot = 0;
            slotp->priority = 0;
            slotp->retry_count = 0;
            slotp->normal_boot = 0;
            bootctrl_write_metadata_bootctrv1(&metadata);
        }
    }

    /* EMMC */
    if(mt_boot_type == FS_TYPE_EMMC) {
        ALOGI("emmc_set_active_boot_part\n");
        ret = emmc_set_active_boot_part(boot_part);
        if(ret) {
            ALOGE("emmc set boot_part fail\n");
            return -1;
        }
        return 1;
    }

    /* UFS */
    if(mt_boot_type == FS_TYPE_UFS) {
        ALOGI ("boot_type is UFS\n");
        ret = ufs_set_active_boot_part(boot_part);
        if(ret) {
            ALOGE("ufs set boot_part fail\n");
            return -1;
        }
        return 1;
    }
    ALOGE("Un support phone type\n");
    return -1;
}

uint32_t bootctrl_get_current_slot(boot_control_module_t *module __unused)
{
    ALOGI("boot control bootctrl_get_current_slot\n");

    uint32_t slot = 0;

    slot = bootctrl_get_active_slot();

    ALOGI("bootctrl_get_current_slot %d\n", slot);
    return slot;
}

int bootctrl_mark_boot_successful(boot_control_module_t *module __unused)
{
    ALOGI("boot control bootctrl_mark_boot_successful\n");
    int ret;
    uint32_t slot = 0;
    AvbABData metadata;
    AvbABSlotData *slotp;

    ret = bootctrl_read_metadata(&metadata);
    if (ret < 0) {
        return ret;
    }

    slot = bootctrl_get_active_slot();
    if (slot < 0) {
        ALOGE("bootctrl_mark_boot_successful fail , slot = \n");
        return slot;
    }
    slotp = &metadata.slots[slot];
    slotp->successful_boot = 1;
    slotp->tries_remaining = 0;

    return bootctrl_write_metadata(&metadata);
}

int bootctrl_set_active_boot_slot(boot_control_module_t *module __unused,
    unsigned slot)
{
    ALOGI("boot control bootctrl_set_active_boot_slot , slot is %d\n", slot);
    int ret, slot2;
    AvbABData metadata;
    AvbABSlotData *slotp;

    if (slot >= 2) {
        ALOGE("%s Wrong Slot value %u\n", __func__ , slot);
        return -EINVAL;
    }
    ret = bootctrl_read_metadata(&metadata);
    if (ret < 0) {
        return ret;
    }
    /* Set highest priority and reset retry count */
    slotp = &metadata.slots[slot];
    slotp->successful_boot = 0;
    slotp->priority = AVB_AB_MAX_PRIORITY;
    slotp->tries_remaining = AVB_AB_MAX_TRIES_REMAINING;

    /* Ensure other slot doesn't have as high a priority. */
    slot2 = (slot == 0) ? 1 : 0;
    slotp = &metadata.slots[slot2];
    if(slotp->priority == AVB_AB_MAX_PRIORITY)
        slotp->priority = AVB_AB_MAX_PRIORITY - 1;
    ret = bootctrl_write_metadata(&metadata);
    if (ret < 0) {
        return ret;
    }

    ret = switch_pl_boot_part(slot);
    if (ret < 0) {
        ALOGE("bootctrl_set_active_boot_slot switch boot part fail\n");
        return ret;
    }

    ret = SetOTAResultForDMVerity();
    if (ret < 0) {
        ALOGE("bootctrl_set_active_boot_slot SetOTAResultForDMVerity fail\n");
        return ret;
    }

    return 0;
}

int bootctrl_set_slot_as_unbootable(boot_control_module_t *module __unused,
    unsigned slot)
{
    ALOGI("boot control bootctrl_set_slot_as_unbootable\n");
    int ret;
    AvbABData metadata;
    AvbABSlotData *slotp;

    if (slot >= 2) {
        ALOGE("%s Wrong Slot value %u\n", __func__ , slot);
        return -EINVAL;
    }
    ret = bootctrl_read_metadata(&metadata);
    if (ret < 0) {
        return ret;
    }
    /* Set zero to priority ,successful_boot and tries_remaining */
    slotp = &metadata.slots[slot];
    slotp->successful_boot = 0;
    slotp->priority = 0;
    slotp->tries_remaining = 0;
    ret = bootctrl_write_metadata(&metadata);
    if (ret < 0) {
        return ret;
    }

    return 0;
}

int bootctrl_is_slot_bootable(boot_control_module_t *module __unused,
    unsigned slot)
{
    ALOGI("boot control bootctrl_is_slot_bootable\n");
    int ret;
    AvbABData metadata;

    /* slot 0 is A , slot 1 is B */
    if (slot >= 2) {
        ALOGE("%s Wrong slot value %u\n", __func__,slot);
        return -EINVAL;
    }
    ret = bootctrl_read_metadata(&metadata);
    if (ret < 0) {
        return ret;
    }

    return (metadata.slots[slot].priority != 0);
}

int bootctrl_get_bootup_status(boot_control_module_t *module __unused,
    unsigned slot)
{
    ALOGI("bootctrl bootctrl_get_bootup_status\n");
    int ret = -1;
    AvbABSlotData *slotp;
    AvbABData metadata;

    if(slot >= 2) {
        ALOGE("%s Wrong slot value %u\n", __func__,slot);
        return -1;
    }

    ret = bootctrl_read_metadata(&metadata);
    if (ret < 0) {
        return ret;
    }

    slotp = &metadata.slots[slot];

    ALOGI("bootctrl bootctrl_get_bootup_status = %d\n", slotp->successful_boot);
    return slotp->successful_boot;
}

const char *bootctrl_get_suffix(boot_control_module_t *module __unused,
    unsigned slot)
{
    ALOGI("boot control bootctrl_get_suffix\n");
    static const char* suffix[2] = {BOOTCTRL_SUFFIX_A, BOOTCTRL_SUFFIX_B};
    if (slot >= 2)
        return NULL;
    return suffix[slot];
}

static struct hw_module_methods_t bootctrl_methods = {
    .open  = NULL,
};

/* Boot Control Module implementation */
boot_control_module_t HAL_MODULE_INFO_SYM = {
    .common = {
        .tag                 = HARDWARE_MODULE_TAG,
        .module_api_version  = BOOT_CONTROL_MODULE_API_VERSION_0_1,
        .hal_api_version     = HARDWARE_HAL_API_VERSION,
        .id                  = BOOT_CONTROL_HARDWARE_MODULE_ID,
        .name                = "boot_control HAL",
        .author              = "Mediatek Corporation",
        .methods             = &bootctrl_methods,
    },
    .init                 = bootctrl_init,
    .getNumberSlots       = bootctrl_get_number_slots,
    .getCurrentSlot       = bootctrl_get_current_slot,
    .markBootSuccessful   = bootctrl_mark_boot_successful,
    .setActiveBootSlot    = bootctrl_set_active_boot_slot,
    .setSlotAsUnbootable  = bootctrl_set_slot_as_unbootable,
    .isSlotBootable       = bootctrl_is_slot_bootable,
    .isSlotMarkedSuccessful = bootctrl_get_bootup_status,
    .getSuffix            = bootctrl_get_suffix,
};
