#ifndef _RECOVERY_H_
#define _RECOVERY_H_

#include "headers/mt_typedefs.h"
#include <bootloader_message/bootloader_message.h>

#define MISC_PAGES            3
#define MISC_COMMAND_PAGE     1  /* bootloader command is this page */

struct misc_message {
    char command[32];
    char status[32];
    char recovery[1024];
};

extern BOOL recovery_check_command_trigger(void) __attribute__((weak));
BOOL check_ota_result(void);
BOOL clear_ota_result(void);

struct bootloader_message_ab {
    struct bootloader_message message;
    char slot_suffix[32];

    // Round up the entire struct to 4096-byte.
    char reserved[2016];
};

#endif /* _RECOVERY_H_ */
