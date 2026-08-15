/*
 * hostapd-mana ACL helpers
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "mana/acl.h"

int mana_acl_parse_mask(char *pos, int vlanflag, const u8 *addr,
			u8 *transform, u8 *mask, int line, const char *fname)
{
	int i;

	if (vlanflag) {
		while (*pos != '\0' && *pos != ' ' && *pos != '\t')
			pos++;
		while (*pos == ' ' || *pos == '\t')
			pos++;
	}

	if (*pos != '\0') {
		if (hwaddr_aton(pos, mask)) {
			wpa_printf(MSG_ERROR, "Invalid MAC mask '%s' at line %d in '%s'",
				   pos, line, fname);
			return -1;
		}
	} else {
		hwaddr_aton("ff:ff:ff:ff:ff:ff", mask);
	}

	for (i = 0; i < ETH_ALEN; i++)
		transform[i] = addr[i] & mask[i];

	return 0;
}

int mana_acl_compare_entry(const struct mac_acl_entry *entry, const u8 *addr)
{
	u8 transformed[ETH_ALEN];
	int i, res;

	for (i = 0; i < ETH_ALEN; i++)
		transformed[i] = addr[i] & entry->mask[i];

	wpa_printf(MSG_DEBUG,
		   "MANA: Comparing " MACSTR "/" MACSTR " against " MACSTR
		   " transformed to " MACSTR,
		   MAC2STR(entry->addr), MAC2STR(entry->mask), MAC2STR(addr),
		   MAC2STR(transformed));

	res = os_memcmp(entry->addr, transformed, ETH_ALEN);
	if (res == 0)
		return 0;

	/* Preserve binary-search ordering from the transformed stored value. */
	return os_memcmp(entry->addr, addr, ETH_ALEN);
}

int mana_ssidlist_found(struct ssid_filter_entry *list, int num_entries,
			const char *ssid)
{
	int i;

	for (i = 0; i < num_entries; i++) {
		if (os_strcmp(list[i].ssid, ssid) == 0)
			return 1;
	}
	return 0;
}
