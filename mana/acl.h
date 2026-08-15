/*
 * hostapd-mana ACL helpers
 */

#ifndef MANA_ACL_H
#define MANA_ACL_H

#include "ap/ap_config.h"

int mana_acl_parse_mask(char *pos, int vlanflag, const u8 *addr,
			u8 *transform, u8 *mask, int line, const char *fname);
int mana_acl_compare_entry(const struct mac_acl_entry *entry, const u8 *addr);
int mana_ssidlist_found(struct ssid_filter_entry *list, int num_entries,
			const char *ssid);

#endif /* MANA_ACL_H */
