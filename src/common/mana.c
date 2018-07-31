/*
 * hostapd / mana includes
 * Copyright (c) 2018-2018, singe
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include "common/mana.h"

// Initialise global hostapd config pointer A kludge to access config options
// in parts of hostapd that don't have the context passed to it without having
// to rewrite a ton of methods
// Check src/ap/hostapd.c for where it's initialised
// 	hostapd_init
// 	hostapd_reload_config
struct mana_conf mana = {
	.conf = 0
};
