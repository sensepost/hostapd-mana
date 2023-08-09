/*
 * hostapd / mana includes
 * Copyright (c) 2018-2018, singe
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include "utils/includes.h"

#include "utils/common.h"
#include "ap/ap_config.h"

// Maintain a global pointer to hostapd config struct for parts of hostapd that
// don't have it passed in as context
struct mana_conf {
	struct hostapd_config *conf;
};
extern struct mana_conf mana;
