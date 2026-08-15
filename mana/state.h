/*
 * hostapd-mana shared state
 */

#ifndef MANA_STATE_H
#define MANA_STATE_H

#include "utils/includes.h"
#include "utils/common.h"
#include "ap/ap_config.h"

struct mana_conf {
	struct hostapd_config *conf;
};

extern struct mana_conf mana;

static inline int mana_enabled(void)
{
	return mana.conf && mana.conf->enable_mana;
}

#endif /* MANA_STATE_H */
