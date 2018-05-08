/*
 * hostapd / IEEE 802.11 Management: Beacon and Probe Request/Response
 * Copyright (c) 2002-2004, Instant802 Networks, Inc.
 * Copyright (c) 2005-2006, Devicescape Software, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef BEACON_H
#define BEACON_H

struct ieee80211_mgmt;

void handle_probe_req(struct hostapd_data *hapd,
		      const struct ieee80211_mgmt *mgmt, size_t len,
		      int ssi_signal);
int ieee802_11_set_beacon(struct hostapd_data *hapd);
int ieee802_11_set_beacons(struct hostapd_iface *iface);
int ieee802_11_update_beacons(struct hostapd_iface *iface);
int ieee802_11_build_ap_params(struct hostapd_data *hapd,
			       struct wpa_driver_ap_params *params);
void ieee802_11_free_ap_params(struct wpa_driver_ap_params *params);
void sta_track_add(struct hostapd_iface *iface, const u8 *addr);
void sta_track_del(struct hostapd_sta_info *info);
void sta_track_expire(struct hostapd_iface *iface, int force);
struct hostapd_sta_info * sta_track_get(struct hostapd_iface *iface, //MANA
                                               const u8 *addr);
struct hostapd_data *
sta_track_seen_on(struct hostapd_iface *iface, const u8 *addr,
		  const char *ifname);
void sta_track_claim_taxonomy_info(struct hostapd_iface *iface, const u8 *addr,
				   struct wpabuf **probe_ie_taxonomy);

#endif /* BEACON_H */

// MANA START
#include "uthash/uthash.h"
struct mana_ssid {
        char ssid_txt[SSID_MAX_LEN+1];
        u8 ssid[SSID_MAX_LEN];
        size_t ssid_len;
		//u8 sta_addr[6];
        UT_hash_handle hh;
};
//struct mana_ssid *mana_data;
struct mana_mac {
	//char mac_txt[18];
	u8 sta_addr[6];
	struct mana_ssid *ssids;
	UT_hash_handle hh;
};
struct mana_mac *mana_machash;
struct mana_ssid *mana_ssidhash;
// MANA END
