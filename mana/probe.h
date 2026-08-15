/*
 * hostapd-mana probe-response helpers
 */

#ifndef MANA_PROBE_H
#define MANA_PROBE_H

#include "utils/common.h"
#include "ap/uthash/uthash.h"

struct hostapd_data;
struct hostapd_iface;
struct hostapd_sta_info;
struct ieee80211_mgmt;
struct ieee802_11_elems;

struct mana_ssid {
	char ssid_txt[SSID_MAX_LEN * 4 + 1];
	u8 ssid[SSID_MAX_LEN];
	size_t ssid_len;
	UT_hash_handle hh;
};

struct mana_mac {
	u8 sta_addr[ETH_ALEN];
	struct mana_ssid *ssids;
	UT_hash_handle hh;
};

extern struct mana_mac *mana_machash;
extern struct mana_ssid *mana_ssidhash;

int mana_probe_macacl_allowed(struct hostapd_data *hapd,
			      const struct ieee80211_mgmt *req);
void mana_log_ssid(struct hostapd_data *hapd, const u8 *ssid, size_t ssid_len,
		   const u8 *mac);
int mana_probe_ssid_allowed(struct hostapd_data *hapd, const u8 *ssid,
			    size_t ssid_len);
void mana_probe_record_taxonomy(struct hostapd_data *hapd, const u8 *addr);
void mana_probe_process_request(struct hostapd_data *hapd,
				const struct ieee80211_mgmt *mgmt,
				const u8 *ssid, size_t ssid_len,
				int wildcard_match, int *iterate);
struct mana_ssid * mana_probe_iter_hash(struct hostapd_data *hapd,
					const u8 *addr);

#endif /* MANA_PROBE_H */
