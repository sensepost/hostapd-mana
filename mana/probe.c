/*
 * hostapd-mana probe-response helpers
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "ap/hostapd.h"
#include "ap/ap_config.h"
#include "ap/beacon.h"
#include "ap/sta_info.h"
#include "ap/taxonomy.h"
#include "mana/acl.h"
#include "mana/probe.h"
#include "mana/state.h"

struct mana_mac *mana_machash = NULL;
struct mana_ssid *mana_ssidhash = NULL;

int mana_probe_macacl_allowed(struct hostapd_data *hapd,
			      const struct ieee80211_mgmt *req)
{
	if (!req || !hapd->iconf->mana_macacl)
		return 1;

	if (hapd->iconf->bss[0]->macaddr_acl == DENY_UNLESS_ACCEPTED) {
		if (!hostapd_maclist_found(hapd->conf->accept_mac,
					   hapd->conf->num_accept_mac,
					   req->sa, NULL)) {
			wpa_printf(MSG_DEBUG,
				   "MANA: Station MAC is not authorised by accept ACL: "
				   MACSTR, MAC2STR(req->sa));
			return 0;
		}
	} else if (hapd->iconf->bss[0]->macaddr_acl == ACCEPT_UNLESS_DENIED) {
		if (hostapd_maclist_found(hapd->conf->deny_mac,
					  hapd->conf->num_deny_mac,
					  req->sa, NULL)) {
			wpa_printf(MSG_DEBUG,
				   "MANA: Station MAC is not authorised by deny ACL: "
				   MACSTR, MAC2STR(req->sa));
			return 0;
		}
	}

	wpa_printf(MSG_INFO, "MANA: Station MAC is authorised by ACL: " MACSTR,
		   MAC2STR(req->sa));
	return 1;
}

void mana_log_ssid(struct hostapd_data *hapd, const u8 *ssid, size_t ssid_len,
		   const u8 *mac)
{
	FILE *f;
	int rand = 0;

	if (os_strcmp("NOT_SET", hapd->iconf->mana_outfile) == 0)
		return;

	f = fopen(hapd->iconf->mana_outfile, "a");
	if (!f) {
		wpa_printf(MSG_ERROR, "MANA: Error writing to activity file %s",
			   hapd->iconf->mana_outfile);
		return;
	}

	if (mac[0] & 2)
		rand = 1;

#ifdef CONFIG_TAXONOMY
	{
		struct sta_info *sta;
		struct hostapd_sta_info *info;
		char reply[512] = "";
		size_t reply_len = sizeof(reply);

		sta = ap_get_sta(hapd, mac);
		if (sta) {
			retrieve_sta_taxonomy(hapd, sta, reply, reply_len);
			fprintf(f, MACSTR ", %s, %d, %s\n", MAC2STR(mac),
				wpa_ssid_txt(ssid, ssid_len), rand, reply);
		} else if ((info = sta_track_get(hapd->iface, mac)) != NULL) {
			retrieve_hostapd_sta_taxonomy(hapd, info, reply, reply_len);
			fprintf(f, MACSTR ", %s, %d, %s\n", MAC2STR(mac),
				wpa_ssid_txt(ssid, ssid_len), rand, reply);
		} else {
			fprintf(f, MACSTR ", %s, %d\n", MAC2STR(mac),
				wpa_ssid_txt(ssid, ssid_len), rand);
		}
	}
#else
	fprintf(f, MACSTR ", %s, %d\n", MAC2STR(mac),
		wpa_ssid_txt(ssid, ssid_len), rand);
#endif
	fclose(f);
}

int mana_probe_ssid_allowed(struct hostapd_data *hapd, const u8 *ssid,
			    size_t ssid_len)
{
	if (os_strcmp(hapd->iconf->mana_ssid_filter_file, "NOT_SET") == 0 ||
	    ssid_len == 0)
		return 1;

	if (mana_ssidlist_found(hapd->conf->ssid_filter,
				hapd->conf->num_ssid_filter,
				wpa_ssid_txt(ssid, ssid_len)) !=
	    hapd->iconf->mana_ssid_filter_type) {
		wpa_printf(MSG_DEBUG, "MANA - SSID '%s' has been denied.",
			   wpa_ssid_txt(ssid, ssid_len));
		return 0;
	}

	return 1;
}

void mana_probe_record_taxonomy(struct hostapd_data *hapd, const u8 *addr)
{
#ifdef CONFIG_TAXONOMY
	struct sta_info *sta;
	struct hostapd_sta_info *info;
	char reply[512] = "";
	size_t reply_len = sizeof(reply);

	if ((sta = ap_get_sta(hapd, addr)) != NULL) {
		retrieve_sta_taxonomy(hapd, sta, reply, reply_len);
		wpa_printf(MSG_MSGDUMP, "MANA TAXONOMY STA '%s'", reply);
	} else if ((info = sta_track_get(hapd->iface, addr)) != NULL) {
		retrieve_hostapd_sta_taxonomy(hapd, info, reply, reply_len);
		wpa_printf(MSG_MSGDUMP, "MANA TAXONOMY STA '%s'", reply);
	}
#else
	(void) hapd;
	(void) addr;
#endif
}

void mana_probe_process_request(struct hostapd_data *hapd,
				const struct ieee80211_mgmt *mgmt,
				const u8 *ssid, size_t ssid_len,
				int wildcard_match, int *iterate)
{
	struct mana_ssid *newssid = NULL;
	struct mana_mac *newsta = NULL;

	if (!mana_enabled())
		return;

	if (wildcard_match) {
		wpa_printf(MSG_DEBUG, "MANA - Broadcast probe request from " MACSTR,
			   MAC2STR(mgmt->sa));
		if (!hapd->conf->ignore_broadcast_ssid) {
			*iterate = 1;
			mana_log_ssid(hapd, (const u8 *) "<Broadcast>", 11,
				      mgmt->sa);
		}
		return;
	}

	if (hapd->iconf->mana_loud) {
		HASH_FIND_STR(mana_ssidhash, wpa_ssid_txt(ssid, ssid_len),
			      newssid);
	} else {
		HASH_FIND(hh, mana_machash, mgmt->sa, ETH_ALEN, newsta);
		if (!newsta) {
			wpa_printf(MSG_DEBUG,
				   "MANA - Adding STA " MACSTR " to the hash.",
				   MAC2STR(mgmt->sa));
			newsta = os_zalloc(sizeof(*newsta));
			if (!newsta)
				return;
			os_memcpy(newsta->sta_addr, mgmt->sa, ETH_ALEN);
			HASH_ADD(hh, mana_machash, sta_addr, ETH_ALEN, newsta);
		}
		HASH_FIND_STR(newsta->ssids, wpa_ssid_txt(ssid, ssid_len),
			      newssid);
	}

	if (!newssid) {
		const char *ssid_txt = wpa_ssid_txt(ssid, ssid_len);

		newssid = os_zalloc(sizeof(*newssid));
		if (!newssid)
			return;
		os_strlcpy(newssid->ssid_txt, ssid_txt,
			   sizeof(newssid->ssid_txt));
		os_memcpy(newssid->ssid, ssid, ssid_len);
		newssid->ssid_len = ssid_len;
		if (hapd->iconf->mana_loud)
			HASH_ADD_STR(mana_ssidhash, ssid_txt, newssid);
		else
			HASH_ADD_STR(newsta->ssids, ssid_txt, newssid);
	}

	wpa_printf(MSG_INFO, "MANA - Directed probe request for SSID '%s' from "
		   MACSTR, wpa_ssid_txt(ssid, ssid_len), MAC2STR(mgmt->sa));
	mana_log_ssid(hapd, ssid, ssid_len, mgmt->sa);
}

struct mana_ssid * mana_probe_iter_hash(struct hostapd_data *hapd,
					const u8 *addr)
{
	struct mana_mac *sta = NULL;

	if (hapd->iconf->mana_loud)
		return mana_ssidhash;

	HASH_FIND(hh, mana_machash, addr, ETH_ALEN, sta);
	return sta ? sta->ssids : NULL;
}
