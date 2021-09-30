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

#ifndef _BOOTCTRL_H_
#define _BOOTCTRL_H_

#include <stdint.h>

/* struct boot_ctrl occupies the slot_suffix field of
 * struct bootloader_message */
#define OFFSETOF_SLOT_SUFFIX 2048

#define BOOTCTRL_SUFFIX_A           "_a"
#define BOOTCTRL_SUFFIX_B           "_b"
#define BOOT_CONTROL_VERSION    1

#define BOOTCTRL_PROPERTY "ro.boot.slot_suffix"
#define SLOT_SUFFIX_STR "androidboot.slot_suffix="
#define COMMAND_LINE_PATH "/proc/cmdline"
#define COMMAND_LINE_SIZE 2048

enum mt_device_type {
     FS_TYPE_MTD = 0,
     FS_TYPE_EMMC,
     FS_TYPE_UFS,
     FS_TYPE_MNTL,
     FS_TYPE_UNKNOWN,
     FS_TYPE_INIT
};

/* AVB20 */
/* Magic for the A/B struct when serialized. */
#define BOOTCTRL_MAGIC 0x19191100

#define AVB_AB_MAGIC "\0AB0"
#define AVB_AB_MAGIC_LEN 4

/* Versioning for the on-disk A/B metadata - keep in sync with avbtool. */
#define AVB_AB_MAJOR_VERSION 1
#define AVB_AB_MINOR_VERSION 0

/* Size of AvbABData struct. */
#define AVB_AB_DATA_SIZE 32

/* Maximum values for slot data */
#define AVB_AB_MAX_PRIORITY 15
#define AVB_AB_MAX_TRIES_REMAINING 7

/* Struct used for recording per-slot metadata.
 *
 * When serialized, data is stored in network byte-order.
 */
typedef struct AvbABSlotData {
  /* Slot priority. Valid values range from 0 to AVB_AB_MAX_PRIORITY,
   * both inclusive with 1 being the lowest and AVB_AB_MAX_PRIORITY
   * being the highest. The special value 0 is used to indicate the
   * slot is unbootable.
   */
  uint8_t priority;

  /* Number of times left attempting to boot this slot ranging from 0
   * to AVB_AB_MAX_TRIES_REMAINING.
   */
  uint8_t tries_remaining;

  /* Non-zero if this slot has booted successfully, 0 otherwise. */
  uint8_t successful_boot;

  /* Reserved for future use. */
  uint8_t reserved[1];

} AvbABSlotData;

/* Struct used for recording A/B metadata.
 *
 * When serialized, data is stored in network byte-order.
 */
typedef struct AvbABData {
  /* Magic number used for identification - see AVB_AB_MAGIC. */
  uint8_t magic[AVB_AB_MAGIC_LEN];

  /* Version of on-disk struct - see AVB_AB_{MAJOR,MINOR}_VERSION. */
  uint8_t version_major;
  uint8_t version_minor;

  /* Padding to ensure |slots| field start eight bytes in. */
  uint8_t reserved1[2];

  /* Per-slot metadata. */
  AvbABSlotData slots[2];

  /* Reserved for future use. */
  uint8_t reserved2[12];

  /* CRC32 of all 28 bytes preceding this field. */
  uint32_t crc32;
} AvbABData;

typedef struct slot_metadata_vendor{
    uint8_t priority : 3;
    uint8_t retry_count : 3;
    uint8_t successful_boot : 1;
    uint8_t normal_boot : 1;
} slot_metadata_t;

typedef struct boot_ctrl {
    /* Magic for identification */
    uint32_t magic;

    /* Version of struct. */
    uint8_t version;

    /* Information about each slot. */
    slot_metadata_t slot_info[2];

    uint8_t recovery_retry_count;
} boot_ctrl_t;


#endif /* _BOOTCTRL_H_ */
