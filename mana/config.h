/*
 * hostapd-mana configuration parsing
 */

#ifndef MANA_CONFIG_H
#define MANA_CONFIG_H

#include "ap/ap_config.h"

enum mana_config_parse_result {
	MANA_CONFIG_UNKNOWN = 0,
	MANA_CONFIG_HANDLED = 1,
	MANA_CONFIG_ERROR = -1
};

void mana_config_defaults(struct hostapd_config *conf);
int mana_config_fill(struct hostapd_config *conf,
		     struct hostapd_bss_config *bss,
		     const char *field, char *value, int line);
int mana_config_read_ssidlist(const char *fname,
			      struct ssid_filter_entry **ssid_filter,
			      int *num);

#endif /* MANA_CONFIG_H */
