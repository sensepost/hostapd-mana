/*
 * hostapd / IEEE 802.11 Management: Beacon and Probe Request/Response
 * Copyright (c) 2002-2004, Instant802 Networks, Inc.
 * Copyright (c) 2005-2006, Devicescape Software, Inc.
 * Copyright (c) 2008-2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#ifndef CONFIG_NATIVE_WINDOWS

#include "utils/common.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "common/hw_features_common.h"
#include "wps/wps_defs.h"
#include "p2p/p2p.h"
#include "hostapd.h"
#include "ieee802_11.h"
#include "wpa_auth.h"
#include "wmm.h"
#include "ap_config.h"
#include "sta_info.h"
#include "p2p_hostapd.h"
#include "ap_drv_ops.h"
#include "beacon.h"
#include "hs20.h"
#include "dfs.h"
#include "taxonomy.h"
// MANA START
#include "common/mana.h" //MANA

struct mana_mac *mana_machash = NULL;
struct mana_ssid *mana_ssidhash = NULL;
// MANA END

#ifdef NEED_AP_MLME

static u8 * hostapd_eid_rm_enabled_capab(struct hostapd_data *hapd, u8 *eid,
					 size_t len)
{
	size_t i;

	for (i = 0; i < RRM_CAPABILITIES_IE_LEN; i++) {
		if (hapd->conf->radio_measurements[i])
			break;
	}

	if (i == RRM_CAPABILITIES_IE_LEN || len < 2 + RRM_CAPABILITIES_IE_LEN)
		return eid;

	*eid++ = WLAN_EID_RRM_ENABLED_CAPABILITIES;
	*eid++ = RRM_CAPABILITIES_IE_LEN;
	os_memcpy(eid, hapd->conf->radio_measurements, RRM_CAPABILITIES_IE_LEN);

	return eid + RRM_CAPABILITIES_IE_LEN;
}


static u8 * hostapd_eid_bss_load(struct hostapd_data *hapd, u8 *eid, size_t len)
{
	if (len < 2 + 5)
		return eid;

#ifdef CONFIG_TESTING_OPTIONS
	if (hapd->conf->bss_load_test_set) {
		*eid++ = WLAN_EID_BSS_LOAD;
		*eid++ = 5;
		os_memcpy(eid, hapd->conf->bss_load_test, 5);
		eid += 5;
		return eid;
	}
#endif /* CONFIG_TESTING_OPTIONS */
	if (hapd->conf->bss_load_update_period) {
		*eid++ = WLAN_EID_BSS_LOAD;
		*eid++ = 5;
		WPA_PUT_LE16(eid, hapd->num_sta);
		eid += 2;
		*eid++ = hapd->iface->channel_utilization;
		WPA_PUT_LE16(eid, 0); /* no available admission capabity */
		eid += 2;
	}
	return eid;
}

//Start MANA
//Log output of observed MACs & SSIDs
static void log_ssid(struct hostapd_data *hapd, const u8 *ssid, size_t ssid_len, const u8 *mac) {
	if (os_strcmp("NOT_SET", hapd->iconf->mana_outfile) == 0) {
		return; // File not set, so don't log
	}
	FILE *f = fopen(hapd->iconf->mana_outfile, "a");
	if (f != NULL) {
		int rand=0;
		if (mac[0] & 2) //Check if locally administered aka random MAC
			rand=1; 

#ifdef CONFIG_TAXONOMY
		struct sta_info *sta;
		struct hostapd_sta_info *info;
		if ((sta = ap_get_sta(hapd, mac)) != NULL) {
			char reply[512] = "";
			size_t reply_len = 512;
			retrieve_sta_taxonomy(hapd, sta, reply, reply_len);
			fprintf(f,MACSTR ", %s, %d, %s\n", MAC2STR(mac), wpa_ssid_txt(ssid, ssid_len), rand, reply);
		} else if ((info = sta_track_get(hapd->iface, mac)) != NULL) {
			char reply[512] = "";
			size_t reply_len = 512;
			retrieve_hostapd_sta_taxonomy(hapd, info, reply, reply_len);
			fprintf(f,MACSTR ", %s, %d, %s\n", MAC2STR(mac), wpa_ssid_txt(ssid, ssid_len), rand, reply);
		} else {
			fprintf(f,MACSTR ", %s, %d\n", MAC2STR(mac), wpa_ssid_txt(ssid, ssid_len), rand);
		}
#endif /* CONFIG_TAXONOMY */
#ifndef CONFIG_TAXONOMY
		fprintf(f,MACSTR ", %s, %d\n", MAC2STR(mac), wpa_ssid_txt(ssid, ssid_len), rand);
#endif /* CONFIG_TAXONOMY */
		fclose(f);
	} else
		wpa_printf(MSG_ERROR, "MANA: Error writing to activity file %s", hapd->iconf->mana_outfile);
}
//End MANA

static u8 ieee802_11_erp_info(struct hostapd_data *hapd)
{
	u8 erp = 0;

	if (hapd->iface->current_mode == NULL ||
	    hapd->iface->current_mode->mode != HOSTAPD_MODE_IEEE80211G)
		return 0;

	if (hapd->iface->olbc)
		erp |= ERP_INFO_USE_PROTECTION;
	if (hapd->iface->num_sta_non_erp > 0) {
		erp |= ERP_INFO_NON_ERP_PRESENT |
			ERP_INFO_USE_PROTECTION;
	}
	if (hapd->iface->num_sta_no_short_preamble > 0 ||
	    hapd->iconf->preamble == LONG_PREAMBLE)
		erp |= ERP_INFO_BARKER_PREAMBLE_MODE;

	return erp;
}


static u8 * hostapd_eid_ds_params(struct hostapd_data *hapd, u8 *eid)
{
	*eid++ = WLAN_EID_DS_PARAMS;
	*eid++ = 1;
	*eid++ = hapd->iconf->channel;
	return eid;
}


static u8 * hostapd_eid_erp_info(struct hostapd_data *hapd, u8 *eid)
{
	if (hapd->iface->current_mode == NULL ||
	    hapd->iface->current_mode->mode != HOSTAPD_MODE_IEEE80211G)
		return eid;

	/* Set NonERP_present and use_protection bits if there
	 * are any associated NonERP stations. */
	/* TODO: use_protection bit can be set to zero even if
	 * there are NonERP stations present. This optimization
	 * might be useful if NonERP stations are "quiet".
	 * See 802.11g/D6 E-1 for recommended practice.
	 * In addition, Non ERP present might be set, if AP detects Non ERP
	 * operation on other APs. */

	/* Add ERP Information element */
	*eid++ = WLAN_EID_ERP_INFO;
	*eid++ = 1;
	*eid++ = ieee802_11_erp_info(hapd);

	return eid;
}


static u8 * hostapd_eid_pwr_constraint(struct hostapd_data *hapd, u8 *eid)
{
	u8 *pos = eid;
	u8 local_pwr_constraint = 0;
	int dfs;

	if (hapd->iface->current_mode == NULL ||
	    hapd->iface->current_mode->mode != HOSTAPD_MODE_IEEE80211A)
		return eid;

	/* Let host drivers add this IE if DFS support is offloaded */
	if (hapd->iface->drv_flags & WPA_DRIVER_FLAGS_DFS_OFFLOAD)
		return eid;

	/*
	 * There is no DFS support and power constraint was not directly
	 * requested by config option.
	 */
	if (!hapd->iconf->ieee80211h &&
	    hapd->iconf->local_pwr_constraint == -1)
		return eid;

	/* Check if DFS is required by regulatory. */
	dfs = hostapd_is_dfs_required(hapd->iface);
	if (dfs < 0) {
		wpa_printf(MSG_WARNING, "Failed to check if DFS is required; ret=%d",
			   dfs);
		dfs = 0;
	}

	if (dfs == 0 && hapd->iconf->local_pwr_constraint == -1)
		return eid;

	/*
	 * ieee80211h (DFS) is enabled so Power Constraint element shall
	 * be added when running on DFS channel whenever local_pwr_constraint
	 * is configured or not. In order to meet regulations when TPC is not
	 * implemented using a transmit power that is below the legal maximum
	 * (including any mitigation factor) should help. In this case,
	 * indicate 3 dB below maximum allowed transmit power.
	 */
	if (hapd->iconf->local_pwr_constraint == -1)
		local_pwr_constraint = 3;

	/*
	 * A STA that is not an AP shall use a transmit power less than or
	 * equal to the local maximum transmit power level for the channel.
	 * The local maximum transmit power can be calculated from the formula:
	 * local max TX pwr = max TX pwr - local pwr constraint
	 * Where max TX pwr is maximum transmit power level specified for
	 * channel in Country element and local pwr constraint is specified
	 * for channel in this Power Constraint element.
	 */

	/* Element ID */
	*pos++ = WLAN_EID_PWR_CONSTRAINT;
	/* Length */
	*pos++ = 1;
	/* Local Power Constraint */
	if (local_pwr_constraint)
		*pos++ = local_pwr_constraint;
	else
		*pos++ = hapd->iconf->local_pwr_constraint;

	return pos;
}


static u8 * hostapd_eid_country_add(u8 *pos, u8 *end, int chan_spacing,
				    struct hostapd_channel_data *start,
				    struct hostapd_channel_data *prev)
{
	if (end - pos < 3)
		return pos;

	/* first channel number */
	*pos++ = start->chan;
	/* number of channels */
	*pos++ = (prev->chan - start->chan) / chan_spacing + 1;
	/* maximum transmit power level */
	*pos++ = start->max_tx_power;

	return pos;
}


static u8 * hostapd_eid_country(struct hostapd_data *hapd, u8 *eid,
				int max_len)
{
	u8 *pos = eid;
	u8 *end = eid + max_len;
	int i;
	struct hostapd_hw_modes *mode;
	struct hostapd_channel_data *start, *prev;
	int chan_spacing = 1;

	if (!hapd->iconf->ieee80211d || max_len < 6 ||
	    hapd->iface->current_mode == NULL)
		return eid;

	*pos++ = WLAN_EID_COUNTRY;
	pos++; /* length will be set later */
	os_memcpy(pos, hapd->iconf->country, 3); /* e.g., 'US ' */
	pos += 3;

	mode = hapd->iface->current_mode;
	if (mode->mode == HOSTAPD_MODE_IEEE80211A)
		chan_spacing = 4;

	start = prev = NULL;
	for (i = 0; i < mode->num_channels; i++) {
		struct hostapd_channel_data *chan = &mode->channels[i];
		if (chan->flag & HOSTAPD_CHAN_DISABLED)
			continue;
		if (start && prev &&
		    prev->chan + chan_spacing == chan->chan &&
		    start->max_tx_power == chan->max_tx_power) {
			prev = chan;
			continue; /* can use same entry */
		}

		if (start && prev) {
			pos = hostapd_eid_country_add(pos, end, chan_spacing,
						      start, prev);
			start = NULL;
		}

		/* Start new group */
		start = prev = chan;
	}

	if (start) {
		pos = hostapd_eid_country_add(pos, end, chan_spacing,
					      start, prev);
	}

	if ((pos - eid) & 1) {
		if (end - pos < 1)
			return eid;
		*pos++ = 0; /* pad for 16-bit alignment */
	}

	eid[1] = (pos - eid) - 2;

	return pos;
}


static u8 * hostapd_eid_wpa(struct hostapd_data *hapd, u8 *eid, size_t len)
{
	const u8 *ie;
	size_t ielen;

	ie = wpa_auth_get_wpa_ie(hapd->wpa_auth, &ielen);
	if (ie == NULL || ielen > len)
		return eid;

	os_memcpy(eid, ie, ielen);
	return eid + ielen;
}


static u8 * hostapd_eid_csa(struct hostapd_data *hapd, u8 *eid)
{
#ifdef CONFIG_TESTING_OPTIONS
	if (hapd->iface->cs_oper_class && hapd->iconf->ecsa_ie_only)
		return eid;
#endif /* CONFIG_TESTING_OPTIONS */

	if (!hapd->cs_freq_params.channel)
		return eid;

	*eid++ = WLAN_EID_CHANNEL_SWITCH;
	*eid++ = 3;
	*eid++ = hapd->cs_block_tx;
	*eid++ = hapd->cs_freq_params.channel;
	*eid++ = hapd->cs_count;

	return eid;
}


static u8 * hostapd_eid_ecsa(struct hostapd_data *hapd, u8 *eid)
{
	if (!hapd->cs_freq_params.channel || !hapd->iface->cs_oper_class)
		return eid;

	*eid++ = WLAN_EID_EXT_CHANSWITCH_ANN;
	*eid++ = 4;
	*eid++ = hapd->cs_block_tx;
	*eid++ = hapd->iface->cs_oper_class;
	*eid++ = hapd->cs_freq_params.channel;
	*eid++ = hapd->cs_count;

	return eid;
}


static u8 * hostapd_eid_supported_op_classes(struct hostapd_data *hapd, u8 *eid)
{
	u8 op_class, channel;

	if (!(hapd->iface->drv_flags & WPA_DRIVER_FLAGS_AP_CSA) ||
	    !hapd->iface->freq)
		return eid;

	if (ieee80211_freq_to_channel_ext(hapd->iface->freq,
					  hapd->iconf->secondary_channel,
					  hapd->iconf->vht_oper_chwidth,
					  &op_class, &channel) ==
	    NUM_HOSTAPD_MODES)
		return eid;

	*eid++ = WLAN_EID_SUPPORTED_OPERATING_CLASSES;
	*eid++ = 2;

	/* Current Operating Class */
	*eid++ = op_class;

	/* TODO: Advertise all the supported operating classes */
	*eid++ = 0;

	return eid;
}


static u8 * hostapd_gen_probe_resp(struct hostapd_data *hapd,
				   const u8 *ssid, size_t ssid_len, //MANA
				   const struct ieee80211_mgmt *req,
				   int is_p2p, size_t *resp_len)
{
	struct ieee80211_mgmt *resp;
	u8 *pos, *epos, *csa_pos;
	size_t buflen;

#define MAX_PROBERESP_LEN 768
	buflen = MAX_PROBERESP_LEN;
#ifdef CONFIG_WPS
	if (hapd->wps_probe_resp_ie)
		buflen += wpabuf_len(hapd->wps_probe_resp_ie);
#endif /* CONFIG_WPS */
#ifdef CONFIG_P2P
	if (hapd->p2p_probe_resp_ie)
		buflen += wpabuf_len(hapd->p2p_probe_resp_ie);
#endif /* CONFIG_P2P */
#ifdef CONFIG_FST
	if (hapd->iface->fst_ies)
		buflen += wpabuf_len(hapd->iface->fst_ies);
#endif /* CONFIG_FST */
	if (hapd->conf->vendor_elements)
		buflen += wpabuf_len(hapd->conf->vendor_elements);
	if (hapd->conf->vendor_vht) {
		buflen += 5 + 2 + sizeof(struct ieee80211_vht_capabilities) +
			2 + sizeof(struct ieee80211_vht_operation);
	}

	buflen += hostapd_mbo_ie_len(hapd);

	resp = os_zalloc(buflen);
	if (resp == NULL)
		return NULL;

	epos = ((u8 *) resp) + MAX_PROBERESP_LEN;

	resp->frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
					   WLAN_FC_STYPE_PROBE_RESP);

	//MANA - check against macacl
	if (req && hapd->iconf->mana_macacl) {
		int match;
		if (hapd->iconf->bss[0]->macaddr_acl == DENY_UNLESS_ACCEPTED) {
			match = hostapd_maclist_found(hapd->conf->accept_mac, hapd->conf->num_accept_mac, req->sa, NULL);
			if (!match) {
				wpa_printf(MSG_DEBUG, "MANA: Station MAC is not authorised by accept ACL: " MACSTR, MAC2STR(req->sa));
				return NULL; //MAC is not in accept list, back out and don't send
			}
		} else if (hapd->iconf->bss[0]->macaddr_acl == ACCEPT_UNLESS_DENIED) {
			if (hostapd_maclist_found(hapd->conf->deny_mac, hapd->conf->num_deny_mac, req->sa, NULL)) {
				wpa_printf(MSG_DEBUG, "MANA: Station MAC is not authorised by deny ACL: " MACSTR, MAC2STR(req->sa));
				return NULL; //MAC is in deny list, back out and don't send
			}
		}
		wpa_printf(MSG_INFO, "MANA: Station MAC is authorised by ACL: " MACSTR, MAC2STR(req->sa));
	}
    //MANA END
	if (req)
		os_memcpy(resp->da, req->sa, ETH_ALEN);
	os_memcpy(resp->sa, hapd->own_addr, ETH_ALEN);

	os_memcpy(resp->bssid, hapd->own_addr, ETH_ALEN);
	resp->u.probe_resp.beacon_int =
		host_to_le16(hapd->iconf->beacon_int);

	/* hardware or low-level driver will setup seq_ctrl and timestamp */
	resp->u.probe_resp.capab_info =
		host_to_le16(hostapd_own_capab_info(hapd));

	pos = resp->u.probe_resp.variable;
	*pos++ = WLAN_EID_SSID;
	//*pos++ = hapd->conf->ssid.ssid_len;
	//os_memcpy(pos, hapd->conf->ssid.ssid, hapd->conf->ssid.ssid_len);
	//pos += hapd->conf->ssid.ssid_len;
 	// MANA START
 	if (hapd->iconf->enable_mana && ssid_len > 0) {
 		*pos++ = ssid_len;
 		os_memcpy(pos, ssid, ssid_len);
 		pos += ssid_len;
 	} else {
 		*pos++ = hapd->conf->ssid.ssid_len;
 		os_memcpy(pos, hapd->conf->ssid.ssid, hapd->conf->ssid.ssid_len);
 		pos += hapd->conf->ssid.ssid_len;
 	}
 	// MANA END

	/* Supported rates */
	pos = hostapd_eid_supp_rates(hapd, pos);

	/* DS Params */
	pos = hostapd_eid_ds_params(hapd, pos); //MANA

	pos = hostapd_eid_country(hapd, pos, epos - pos);

	/* Power Constraint element */
	pos = hostapd_eid_pwr_constraint(hapd, pos);

	/* CSA IE */
	csa_pos = hostapd_eid_csa(hapd, pos);
	if (csa_pos != pos)
		hapd->cs_c_off_proberesp = csa_pos - (u8 *) resp - 1;
	pos = csa_pos;

	/* ERP Information element */
	pos = hostapd_eid_erp_info(hapd, pos);

	/* Extended supported rates */
	pos = hostapd_eid_ext_supp_rates(hapd, pos);

	/* RSN, MDIE, WPA */
	pos = hostapd_eid_wpa(hapd, pos, epos - pos);

	pos = hostapd_eid_bss_load(hapd, pos, epos - pos);

	pos = hostapd_eid_rm_enabled_capab(hapd, pos, epos - pos);

	/* eCSA IE */
	csa_pos = hostapd_eid_ecsa(hapd, pos);
	if (csa_pos != pos)
		hapd->cs_c_off_ecsa_proberesp = csa_pos - (u8 *) resp - 1;
	pos = csa_pos;

	pos = hostapd_eid_supported_op_classes(hapd, pos);

#ifdef CONFIG_IEEE80211N
	/* Secondary Channel Offset element */
	/* TODO: The standard doesn't specify a position for this element. */
	pos = hostapd_eid_secondary_channel(hapd, pos);

	pos = hostapd_eid_ht_capabilities(hapd, pos);
	pos = hostapd_eid_ht_operation(hapd, pos);
#endif /* CONFIG_IEEE80211N */

	pos = hostapd_eid_ext_capab(hapd, pos);

	pos = hostapd_eid_time_adv(hapd, pos);
	pos = hostapd_eid_time_zone(hapd, pos);

	pos = hostapd_eid_interworking(hapd, pos);
	pos = hostapd_eid_adv_proto(hapd, pos);
	pos = hostapd_eid_roaming_consortium(hapd, pos);

#ifdef CONFIG_FST
	if (hapd->iface->fst_ies) {
		os_memcpy(pos, wpabuf_head(hapd->iface->fst_ies),
			  wpabuf_len(hapd->iface->fst_ies));
		pos += wpabuf_len(hapd->iface->fst_ies);
	}
#endif /* CONFIG_FST */

#ifdef CONFIG_IEEE80211AC
	if (hapd->iconf->ieee80211ac && !hapd->conf->disable_11ac) {
		pos = hostapd_eid_vht_capabilities(hapd, pos, 0);
		pos = hostapd_eid_vht_operation(hapd, pos);
		pos = hostapd_eid_txpower_envelope(hapd, pos);
		pos = hostapd_eid_wb_chsw_wrapper(hapd, pos);
	}
	if (hapd->conf->vendor_vht)
		pos = hostapd_eid_vendor_vht(hapd, pos);
#endif /* CONFIG_IEEE80211AC */

	/* Wi-Fi Alliance WMM */
	pos = hostapd_eid_wmm(hapd, pos);

#ifdef CONFIG_WPS
	if (hapd->conf->wps_state && hapd->wps_probe_resp_ie) {
		os_memcpy(pos, wpabuf_head(hapd->wps_probe_resp_ie),
			  wpabuf_len(hapd->wps_probe_resp_ie));
		pos += wpabuf_len(hapd->wps_probe_resp_ie);
	}
#endif /* CONFIG_WPS */

#ifdef CONFIG_P2P
	if ((hapd->conf->p2p & P2P_ENABLED) && is_p2p &&
	    hapd->p2p_probe_resp_ie) {
		os_memcpy(pos, wpabuf_head(hapd->p2p_probe_resp_ie),
			  wpabuf_len(hapd->p2p_probe_resp_ie));
		pos += wpabuf_len(hapd->p2p_probe_resp_ie);
	}
#endif /* CONFIG_P2P */
#ifdef CONFIG_P2P_MANAGER
	if ((hapd->conf->p2p & (P2P_MANAGE | P2P_ENABLED | P2P_GROUP_OWNER)) ==
	    P2P_MANAGE)
		pos = hostapd_eid_p2p_manage(hapd, pos);
#endif /* CONFIG_P2P_MANAGER */

#ifdef CONFIG_HS20
	pos = hostapd_eid_hs20_indication(hapd, pos);
	pos = hostapd_eid_osen(hapd, pos);
#endif /* CONFIG_HS20 */

	pos = hostapd_eid_mbo(hapd, pos, (u8 *) resp + buflen - pos);

	if (hapd->conf->vendor_elements) {
		os_memcpy(pos, wpabuf_head(hapd->conf->vendor_elements),
			  wpabuf_len(hapd->conf->vendor_elements));
		pos += wpabuf_len(hapd->conf->vendor_elements);
	}

	*resp_len = pos - (u8 *) resp;
	return (u8 *) resp;
}

enum ssid_match_result {
	NO_SSID_MATCH,
	EXACT_SSID_MATCH,
	WILDCARD_SSID_MATCH
};

static enum ssid_match_result ssid_match(struct hostapd_data *hapd,
					 const u8 *ssid, size_t ssid_len,
					 const u8 *ssid_list,
					 size_t ssid_list_len)
{
	const u8 *pos, *end;
	int wildcard = 0;

	if (ssid_len == 0)
		wildcard = 1;
	if (ssid_len == hapd->conf->ssid.ssid_len &&
	    os_memcmp(ssid, hapd->conf->ssid.ssid, ssid_len) == 0)
		return EXACT_SSID_MATCH;

	if (ssid_list == NULL)
		return wildcard ? WILDCARD_SSID_MATCH : NO_SSID_MATCH;

	pos = ssid_list;
	end = ssid_list + ssid_list_len;
	while (end - pos >= 1) {
		if (2 + pos[1] > end - pos)
			break;
		if (pos[1] == 0)
			wildcard = 1;
		if (pos[1] == hapd->conf->ssid.ssid_len &&
		    os_memcmp(pos + 2, hapd->conf->ssid.ssid, pos[1]) == 0)
			return EXACT_SSID_MATCH;
		pos += 2 + pos[1];
	}

	return wildcard ? WILDCARD_SSID_MATCH : NO_SSID_MATCH;
}


void sta_track_expire(struct hostapd_iface *iface, int force)
{
	struct os_reltime now;
	struct hostapd_sta_info *info;

	if (!iface->num_sta_seen)
		return;

	os_get_reltime(&now);
	while ((info = dl_list_first(&iface->sta_seen, struct hostapd_sta_info,
				     list))) {
		if (!force &&
		    !os_reltime_expired(&now, &info->last_seen,
					iface->conf->track_sta_max_age))
			break;
		force = 0;

		wpa_printf(MSG_MSGDUMP, "%s: Expire STA tracking entry for "
			   MACSTR, iface->bss[0]->conf->iface,
			   MAC2STR(info->addr));
		dl_list_del(&info->list);
		iface->num_sta_seen--;
		sta_track_del(info);
	}
}


//static struct hostapd_sta_info * sta_track_get(struct hostapd_iface *iface, //MANA
struct hostapd_sta_info * sta_track_get(struct hostapd_iface *iface,
					       const u8 *addr)
{
	struct hostapd_sta_info *info;

	dl_list_for_each(info, &iface->sta_seen, struct hostapd_sta_info, list)
		if (os_memcmp(addr, info->addr, ETH_ALEN) == 0)
			return info;

	return NULL;
}


void sta_track_add(struct hostapd_iface *iface, const u8 *addr)
{
	struct hostapd_sta_info *info;

	info = sta_track_get(iface, addr);
	if (info) {
		/* Move the most recent entry to the end of the list */
		dl_list_del(&info->list);
		dl_list_add_tail(&iface->sta_seen, &info->list);
		os_get_reltime(&info->last_seen);
		return;
	}

	/* Add a new entry */
	info = os_zalloc(sizeof(*info));
	if (info == NULL)
		return;
	os_memcpy(info->addr, addr, ETH_ALEN);
	os_get_reltime(&info->last_seen);

	if (iface->num_sta_seen >= iface->conf->track_sta_max_num) {
		/* Expire oldest entry to make room for a new one */
		sta_track_expire(iface, 1);
	}

	wpa_printf(MSG_MSGDUMP, "%s: Add STA tracking entry for "
		   MACSTR, iface->bss[0]->conf->iface, MAC2STR(addr));
	dl_list_add_tail(&iface->sta_seen, &info->list);
	iface->num_sta_seen++;
}


struct hostapd_data *
sta_track_seen_on(struct hostapd_iface *iface, const u8 *addr,
		  const char *ifname)
{
	struct hapd_interfaces *interfaces = iface->interfaces;
	size_t i, j;

	for (i = 0; i < interfaces->count; i++) {
		struct hostapd_data *hapd = NULL;

		iface = interfaces->iface[i];
		for (j = 0; j < iface->num_bss; j++) {
			hapd = iface->bss[j];
			if (os_strcmp(ifname, hapd->conf->iface) == 0)
				break;
			hapd = NULL;
		}

		if (hapd && sta_track_get(iface, addr))
			return hapd;
	}

	return NULL;
}


#ifdef CONFIG_TAXONOMY
void sta_track_claim_taxonomy_info(struct hostapd_iface *iface, const u8 *addr,
				   struct wpabuf **probe_ie_taxonomy)
{
	struct hostapd_sta_info *info;

	info = sta_track_get(iface, addr);
	if (!info)
		return;

	wpabuf_free(*probe_ie_taxonomy);
	*probe_ie_taxonomy = info->probe_ie_taxonomy;
	info->probe_ie_taxonomy = NULL;
}
#endif /* CONFIG_TAXONOMY */


void handle_probe_req(struct hostapd_data *hapd,
		      const struct ieee80211_mgmt *mgmt, size_t len,
		      int ssi_signal)
{
	u8 *resp;
	struct ieee802_11_elems elems;
	const u8 *ie;
	size_t ie_len;
	size_t i, resp_len;
	int noack;
	enum ssid_match_result res;
	int ret;
	u16 csa_offs[2];
	size_t csa_offs_len;
	int iterate = 0; //MANA

	if (len < IEEE80211_HDRLEN)
		return;
	ie = ((const u8 *) mgmt) + IEEE80211_HDRLEN;
	if (hapd->iconf->track_sta_max_num)
		sta_track_add(hapd->iface, mgmt->sa);
	ie_len = len - IEEE80211_HDRLEN;

	for (i = 0; hapd->probereq_cb && i < hapd->num_probereq_cb; i++)
		if (hapd->probereq_cb[i].cb(hapd->probereq_cb[i].ctx,
					    mgmt->sa, mgmt->da, mgmt->bssid,
					    ie, ie_len, ssi_signal) > 0)
			return;

	if (!hapd->iconf->send_probe_response)
		return;

	if (ieee802_11_parse_elems(ie, ie_len, &elems, 0) == ParseFailed) {
		wpa_printf(MSG_DEBUG, "Could not parse ProbeReq from " MACSTR,
			   MAC2STR(mgmt->sa));
		return;
	}

	if ((!elems.ssid || !elems.supp_rates)) {
		wpa_printf(MSG_DEBUG, "STA " MACSTR " sent probe request "
			   "without SSID or supported rates element",
			   MAC2STR(mgmt->sa));
		return;
	}

	/*
	 * No need to reply if the Probe Request frame was sent on an adjacent
	 * channel. IEEE Std 802.11-2012 describes this as a requirement for an
	 * AP with dot11RadioMeasurementActivated set to true, but strictly
	 * speaking does not allow such ignoring of Probe Request frames if
	 * dot11RadioMeasurementActivated is false. Anyway, this can help reduce
	 * number of unnecessary Probe Response frames for cases where the STA
	 * is less likely to see them (Probe Request frame sent on a
	 * neighboring, but partially overlapping, channel).
	 */
	if (elems.ds_params &&
	    hapd->iface->current_mode &&
	    (hapd->iface->current_mode->mode == HOSTAPD_MODE_IEEE80211G ||
	     hapd->iface->current_mode->mode == HOSTAPD_MODE_IEEE80211B) &&
	    hapd->iconf->channel != elems.ds_params[0]) {
		wpa_printf(MSG_DEBUG,
			   "Ignore Probe Request due to DS Params mismatch: chan=%u != ds.chan=%u",
			   hapd->iconf->channel, elems.ds_params[0]);
		return;
	}

#ifdef CONFIG_P2P
	if (hapd->p2p && hapd->p2p_group && elems.wps_ie) {
		struct wpabuf *wps;
		wps = ieee802_11_vendor_ie_concat(ie, ie_len, WPS_DEV_OUI_WFA);
		if (wps && !p2p_group_match_dev_type(hapd->p2p_group, wps)) {
			wpa_printf(MSG_MSGDUMP, "P2P: Ignore Probe Request "
				   "due to mismatch with Requested Device "
				   "Type");
			wpabuf_free(wps);
			return;
		}
		wpabuf_free(wps);
	}

	if (hapd->p2p && hapd->p2p_group && elems.p2p) {
		struct wpabuf *p2p;
		p2p = ieee802_11_vendor_ie_concat(ie, ie_len, P2P_IE_VENDOR_TYPE);
		if (p2p && !p2p_group_match_dev_id(hapd->p2p_group, p2p)) {
			wpa_printf(MSG_MSGDUMP, "P2P: Ignore Probe Request "
				   "due to mismatch with Device ID");
			wpabuf_free(p2p);
			return;
		}
		wpabuf_free(p2p);
	}
#endif /* CONFIG_P2P */
	if (os_strcmp(hapd->iconf->mana_ssid_filter_file,"NOT_SET") && elems.ssid_len != 0) { //MANA
		if (!hostapd_ssidlist_found(hapd->conf->ssid_filter, hapd->conf->num_ssid_filter, wpa_ssid_txt(elems.ssid, elems.ssid_len))) {
			wpa_printf(MSG_DEBUG, "MANA - SSID '%s' not found in list.", wpa_ssid_txt(elems.ssid, elems.ssid_len));
			return;
		}
	}

	if (hapd->conf->ignore_broadcast_ssid && elems.ssid_len == 0 &&
	    elems.ssid_list_len == 0 && !hapd->iconf->enable_mana) { //MANA
		wpa_printf(MSG_MSGDUMP, "Probe Request from " MACSTR " for "
			   "broadcast SSID ignored", MAC2STR(mgmt->sa));
		return;
	}

#ifdef CONFIG_P2P
	if ((hapd->conf->p2p & P2P_GROUP_OWNER) &&
	    elems.ssid_len == P2P_WILDCARD_SSID_LEN &&
	    os_memcmp(elems.ssid, P2P_WILDCARD_SSID,
		      P2P_WILDCARD_SSID_LEN) == 0) {
		/* Process P2P Wildcard SSID like Wildcard SSID */
		elems.ssid_len = 0;
	}
#endif /* CONFIG_P2P */

#ifdef CONFIG_TAXONOMY
	
		struct sta_info *sta;
		struct hostapd_sta_info *info;

		if ((sta = ap_get_sta(hapd, mgmt->sa)) != NULL) {
			taxonomy_sta_info_probe_req(hapd, sta, ie, ie_len);
			//START MANA - JUST CHECK TAXONOMY IN OUTPUT
			char reply[512] = "";
			size_t reply_len = 512;
			retrieve_sta_taxonomy(hapd, sta, reply, reply_len);
			wpa_printf(MSG_MSGDUMP, "MANA TAXONOMY STA '%s'", reply);
			//END MANA
		} else if ((info = sta_track_get(hapd->iface,
						 mgmt->sa)) != NULL) {
			taxonomy_hostapd_sta_info_probe_req(hapd, info,
							    ie, ie_len);
			//START MANA - JUST CHECK TAXONOMY IN OUTPUT
			char reply[512] = "";
			size_t reply_len = 512;
			retrieve_hostapd_sta_taxonomy(hapd, info, reply, reply_len);
			wpa_printf(MSG_MSGDUMP, "MANA TAXONOMY STA '%s'", reply);
			//END MANA
		}
	
#endif /* CONFIG_TAXONOMY */

	res = ssid_match(hapd, elems.ssid, elems.ssid_len,
			 elems.ssid_list, elems.ssid_list_len);
	//MANA START
 	// todo handle ssid_list see ssid_match for code
 	// todo change emit code below (global flag?)
	if (!hapd->iconf->enable_mana && res == NO_SSID_MATCH) {
		if (!(mgmt->da[0] & 0x01)) {
			wpa_printf(MSG_MSGDUMP, "Probe Request from " MACSTR
				   " for foreign SSID '%s' (DA " MACSTR ")%s",
				   MAC2STR(mgmt->sa),
				   wpa_ssid_txt(elems.ssid, elems.ssid_len),
				   MAC2STR(mgmt->da),
				   elems.ssid_list ? " (SSID list)" : "");
		}
		return;
	} else if (hapd->iconf->enable_mana) {
		if (res == WILDCARD_SSID_MATCH) {
			//Broadcast probe no need to record SSID or STA
			wpa_printf(MSG_DEBUG,"MANA - Broadcast probe request from " MACSTR "",MAC2STR(mgmt->sa));
			iterate = 1; //iterate through hash emitting multiple probe responses
			log_ssid(hapd, (const u8 *)"<Broadcast>", 11, mgmt->sa);
		} else {
			//Directed probe
			struct mana_ssid *newssid = NULL;
			struct mana_mac *newsta = NULL;
			if (hapd->iconf->mana_loud) {
				//Loud mode check ssidhash
				HASH_FIND_STR(mana_ssidhash, wpa_ssid_txt(elems.ssid, elems.ssid_len), newssid);
			} else {
				//Not loud mode, check if the STA probing is in our hash
				HASH_FIND(hh,mana_machash, mgmt->sa, 6, newsta);
				if (newsta == NULL) { //STA MAC not seen before adding to hash
					wpa_printf(MSG_DEBUG, "MANA - Adding STA " MACSTR " to the hash.", MAC2STR(mgmt->sa));
					newsta = (struct mana_mac*)os_malloc(sizeof(struct mana_mac));
					os_memcpy(newsta->sta_addr, mgmt->sa, ETH_ALEN);
					newsta->ssids = NULL;
					HASH_ADD(hh,mana_machash, sta_addr, 6, newsta);
				}
				HASH_FIND_STR(newsta->ssids, wpa_ssid_txt(elems.ssid, elems.ssid_len), newssid);
			}

			if (newssid == NULL) {
				//Probed for SSID not found (and not Broadcast) add SSID to hash
				wpa_printf(MSG_DEBUG, "MANA - Adding SSID %s(%d) from STA " MACSTR " to the hash.", wpa_ssid_txt(elems.ssid, elems.ssid_len), elems.ssid_len, MAC2STR(mgmt->sa));
				struct mana_ssid *newssid = os_malloc(sizeof(struct mana_ssid));
				os_memcpy(newssid->ssid_txt, wpa_ssid_txt(elems.ssid, elems.ssid_len), elems.ssid_len+1);
				os_memcpy(newssid->ssid, elems.ssid, elems.ssid_len);
				newssid->ssid_len = elems.ssid_len;
				if (hapd->iconf->mana_loud)
					HASH_ADD_STR(mana_ssidhash, ssid_txt, newssid);
				else
					HASH_ADD_STR(newsta->ssids, ssid_txt, newssid);
			}
 			wpa_printf(MSG_INFO,"MANA - Directed probe request for SSID '%s' from " MACSTR "",wpa_ssid_txt(elems.ssid, elems.ssid_len),MAC2STR(mgmt->sa));
			log_ssid(hapd, elems.ssid, elems.ssid_len, mgmt->sa);
 		}
	}
	//MANA END

#ifdef CONFIG_INTERWORKING
	if (hapd->conf->interworking &&
	    elems.interworking && elems.interworking_len >= 1) {
		u8 ant = elems.interworking[0] & 0x0f;
		if (ant != INTERWORKING_ANT_WILDCARD &&
		    ant != hapd->conf->access_network_type) {
			wpa_printf(MSG_MSGDUMP, "Probe Request from " MACSTR
				   " for mismatching ANT %u ignored",
				   MAC2STR(mgmt->sa), ant);
			return;
		}
	}

	if (hapd->conf->interworking && elems.interworking &&
	    (elems.interworking_len == 7 || elems.interworking_len == 9)) {
		const u8 *hessid;
		if (elems.interworking_len == 7)
			hessid = elems.interworking + 1;
		else
			hessid = elems.interworking + 1 + 2;
		if (!is_broadcast_ether_addr(hessid) &&
		    os_memcmp(hessid, hapd->conf->hessid, ETH_ALEN) != 0) {
			wpa_printf(MSG_MSGDUMP, "Probe Request from " MACSTR
				   " for mismatching HESSID " MACSTR
				   " ignored",
				   MAC2STR(mgmt->sa), MAC2STR(hessid));
			return;
		}
	}
#endif /* CONFIG_INTERWORKING */

#ifdef CONFIG_P2P
	if ((hapd->conf->p2p & P2P_GROUP_OWNER) &&
	    supp_rates_11b_only(&elems)) {
		/* Indicates support for 11b rates only */
		wpa_printf(MSG_EXCESSIVE, "P2P: Ignore Probe Request from "
			   MACSTR " with only 802.11b rates",
			   MAC2STR(mgmt->sa));
		return;
	}
#endif /* CONFIG_P2P */

	/* TODO: verify that supp_rates contains at least one matching rate
	 * with AP configuration */

	if (hapd->conf->no_probe_resp_if_seen_on &&
	    is_multicast_ether_addr(mgmt->da) &&
	    is_multicast_ether_addr(mgmt->bssid) &&
	    sta_track_seen_on(hapd->iface, mgmt->sa,
			      hapd->conf->no_probe_resp_if_seen_on)) {
		wpa_printf(MSG_MSGDUMP, "%s: Ignore Probe Request from " MACSTR
			   " since STA has been seen on %s",
			   hapd->conf->iface, MAC2STR(mgmt->sa),
			   hapd->conf->no_probe_resp_if_seen_on);
		return;
	}

	if (hapd->conf->no_probe_resp_if_max_sta &&
	    is_multicast_ether_addr(mgmt->da) &&
	    is_multicast_ether_addr(mgmt->bssid) &&
	    hapd->num_sta >= hapd->conf->max_num_sta &&
	    !ap_get_sta(hapd, mgmt->sa)) {
		wpa_printf(MSG_MSGDUMP, "%s: Ignore Probe Request from " MACSTR
			   " since no room for additional STA",
			   hapd->conf->iface, MAC2STR(mgmt->sa));
		return;
	}

#ifdef CONFIG_TESTING_OPTIONS
	if (hapd->iconf->ignore_probe_probability > 0.0 &&
	    drand48() < hapd->iconf->ignore_probe_probability) {
		wpa_printf(MSG_INFO,
			   "TESTING: ignoring probe request from " MACSTR,
			   MAC2STR(mgmt->sa));
		return;
	}
#endif /* CONFIG_TESTING_OPTIONS */


	//MANA Start - this is just the same original code repeated twice, except MANA has a hash iterator around it
	if (!iterate) { //MANA Either we're not in mana or it's not a broadcast probe
		if (!hapd->iconf->enable_mana) //MANA if *not* mana, respond with the proper ssid
			resp = hostapd_gen_probe_resp(hapd, hapd->conf->ssid.ssid, hapd->conf->ssid.ssid_len, mgmt, elems.p2p != NULL, &resp_len);
		else {
			wpa_printf(MSG_DEBUG, "MANA - Attempting to generate response : %.*s (%d) for STA " MACSTR, elems.ssid_len, elems.ssid, elems.ssid_len, MAC2STR(mgmt->sa));
			resp = hostapd_gen_probe_resp(hapd, elems.ssid, elems.ssid_len, mgmt, elems.p2p != NULL, &resp_len);
		}
		if (resp == NULL)
			return;

		/*
	 	* If this is a broadcast probe request, apply no ack policy to avoid
	 	* excessive retries.
	 	*/
		noack = !!(res == WILDCARD_SSID_MATCH &&
		   	is_broadcast_ether_addr(mgmt->da));

		csa_offs_len = 0;
		if (hapd->csa_in_progress) {
			if (hapd->cs_c_off_proberesp)
				csa_offs[csa_offs_len++] =
					hapd->cs_c_off_proberesp;

			if (hapd->cs_c_off_ecsa_proberesp)
				csa_offs[csa_offs_len++] =
					hapd->cs_c_off_ecsa_proberesp;
		}

		ret = hostapd_drv_send_mlme_csa(hapd, resp, resp_len, noack,
						csa_offs_len ? csa_offs : NULL,
						csa_offs_len);

		if (ret < 0)
			wpa_printf(MSG_INFO, "handle_probe_req: send failed");

		os_free(resp);

		wpa_printf(MSG_EXCESSIVE, "STA " MACSTR " sent probe request for %s "
			   "SSID", MAC2STR(mgmt->sa),
			   elems.ssid_len == 0 ? "broadcast" : "our");
	} else { 
		//MANA iterate
		struct mana_ssid *khash;
		struct mana_ssid *k;
		struct mana_mac *newsta = NULL;

		// Select appropriate hash to iterate
		if (hapd->iconf->mana_loud)
			khash = mana_ssidhash;
		else {
			// Find specific MAC's SSID hash
			HASH_FIND(hh, mana_machash, mgmt->sa, 6, newsta);
			if (newsta == NULL)
				return;
			khash = newsta->ssids;
		}
		for ( k = khash; k != NULL; k = (struct mana_ssid*)(k->hh.next)) {
			wpa_printf(MSG_DEBUG, "MANA: Generating Broadcast response : %s (%zu) for STA " MACSTR, k->ssid_txt, k->ssid_len, MAC2STR(mgmt->sa));
			resp = hostapd_gen_probe_resp(hapd, k->ssid, k->ssid_len, mgmt, elems.p2p != NULL, &resp_len);
			if (resp == NULL)
				return;

			/*
	 		* If this is a broadcast probe request, apply no ack policy to avoid
	 		* excessive retries.
	 		*/
			noack = !!(res == WILDCARD_SSID_MATCH &&
		   		is_broadcast_ether_addr(mgmt->da));

			csa_offs_len = 0;
			if (hapd->csa_in_progress) {
				if (hapd->cs_c_off_proberesp)
					csa_offs[csa_offs_len++] =
						hapd->cs_c_off_proberesp;

				if (hapd->cs_c_off_ecsa_proberesp)
					csa_offs[csa_offs_len++] =
						hapd->cs_c_off_ecsa_proberesp;
			}

			ret = hostapd_drv_send_mlme_csa(hapd, resp, resp_len, noack,
							csa_offs_len ? csa_offs : NULL,
							csa_offs_len);

			if (ret < 0)
				wpa_printf(MSG_ERROR, "handle_probe_req: send failed");

			os_free(resp);

			wpa_printf(MSG_EXCESSIVE, "MANA: STA " MACSTR " sent probe request for %s "
			   	"SSID", MAC2STR(mgmt->sa), k->ssid);
		} //for
	} //MANA iterate END

}

static u8 * hostapd_probe_resp_offloads(struct hostapd_data *hapd,
					size_t *resp_len)
{
	/* check probe response offloading caps and print warnings */
	if (!(hapd->iface->drv_flags & WPA_DRIVER_FLAGS_PROBE_RESP_OFFLOAD))
		return NULL;

#ifdef CONFIG_WPS
	if (hapd->conf->wps_state && hapd->wps_probe_resp_ie &&
	    (!(hapd->iface->probe_resp_offloads &
	       (WPA_DRIVER_PROBE_RESP_OFFLOAD_WPS |
		WPA_DRIVER_PROBE_RESP_OFFLOAD_WPS2))))
		wpa_printf(MSG_WARNING, "Device is trying to offload WPS "
			   "Probe Response while not supporting this");
#endif /* CONFIG_WPS */

#ifdef CONFIG_P2P
	if ((hapd->conf->p2p & P2P_ENABLED) && hapd->p2p_probe_resp_ie &&
	    !(hapd->iface->probe_resp_offloads &
	      WPA_DRIVER_PROBE_RESP_OFFLOAD_P2P))
		wpa_printf(MSG_WARNING, "Device is trying to offload P2P "
			   "Probe Response while not supporting this");
#endif  /* CONFIG_P2P */

	if (hapd->conf->interworking &&
	    !(hapd->iface->probe_resp_offloads &
	      WPA_DRIVER_PROBE_RESP_OFFLOAD_INTERWORKING))
		wpa_printf(MSG_WARNING, "Device is trying to offload "
			   "Interworking Probe Response while not supporting "
			   "this");

	/* Generate a Probe Response template for the non-P2P case */
	//return hostapd_gen_probe_resp(hapd, NULL, 0, resp_len);
	return hostapd_gen_probe_resp(hapd, NULL, 0, NULL, 0, resp_len); //MANA
}

#endif /* NEED_AP_MLME */


void sta_track_del(struct hostapd_sta_info *info)
{
#ifdef CONFIG_TAXONOMY
	wpabuf_free(info->probe_ie_taxonomy);
	info->probe_ie_taxonomy = NULL;
#endif /* CONFIG_TAXONOMY */
	os_free(info);
}


int ieee802_11_build_ap_params(struct hostapd_data *hapd,
			       struct wpa_driver_ap_params *params)
{
	struct ieee80211_mgmt *head = NULL;
	u8 *tail = NULL;
	size_t head_len = 0, tail_len = 0;
	u8 *resp = NULL;
	size_t resp_len = 0;
#ifdef NEED_AP_MLME
	u16 capab_info;
	u8 *pos, *tailpos, *csa_pos;

#define BEACON_HEAD_BUF_SIZE 256
#define BEACON_TAIL_BUF_SIZE 512
	head = os_zalloc(BEACON_HEAD_BUF_SIZE);
	tail_len = BEACON_TAIL_BUF_SIZE;
#ifdef CONFIG_WPS
	if (hapd->conf->wps_state && hapd->wps_beacon_ie)
		tail_len += wpabuf_len(hapd->wps_beacon_ie);
#endif /* CONFIG_WPS */
#ifdef CONFIG_P2P
	if (hapd->p2p_beacon_ie)
		tail_len += wpabuf_len(hapd->p2p_beacon_ie);
#endif /* CONFIG_P2P */
#ifdef CONFIG_FST
	if (hapd->iface->fst_ies)
		tail_len += wpabuf_len(hapd->iface->fst_ies);
#endif /* CONFIG_FST */
	if (hapd->conf->vendor_elements)
		tail_len += wpabuf_len(hapd->conf->vendor_elements);

#ifdef CONFIG_IEEE80211AC
	if (hapd->conf->vendor_vht) {
		tail_len += 5 + 2 + sizeof(struct ieee80211_vht_capabilities) +
			2 + sizeof(struct ieee80211_vht_operation);
	}
#endif /* CONFIG_IEEE80211AC */

	tail_len += hostapd_mbo_ie_len(hapd);

	tailpos = tail = os_malloc(tail_len);
	if (head == NULL || tail == NULL) {
		wpa_printf(MSG_ERROR, "Failed to set beacon data");
		os_free(head);
		os_free(tail);
		return -1;
	}

	head->frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
					   WLAN_FC_STYPE_BEACON);
	head->duration = host_to_le16(0);
	os_memset(head->da, 0xff, ETH_ALEN);

	os_memcpy(head->sa, hapd->own_addr, ETH_ALEN);
	os_memcpy(head->bssid, hapd->own_addr, ETH_ALEN);
	head->u.beacon.beacon_int =
		host_to_le16(hapd->iconf->beacon_int);

	/* hardware or low-level driver will setup seq_ctrl and timestamp */
	capab_info = hostapd_own_capab_info(hapd);
	head->u.beacon.capab_info = host_to_le16(capab_info);
	pos = &head->u.beacon.variable[0];

	/* SSID */
	*pos++ = WLAN_EID_SSID;
	if (hapd->conf->ignore_broadcast_ssid == 2) {
		/* clear the data, but keep the correct length of the SSID */
		*pos++ = hapd->conf->ssid.ssid_len;
		os_memset(pos, 0, hapd->conf->ssid.ssid_len);
		pos += hapd->conf->ssid.ssid_len;
	} else if (hapd->conf->ignore_broadcast_ssid) {
		*pos++ = 0; /* empty SSID */
	} else {
		*pos++ = hapd->conf->ssid.ssid_len;
		os_memcpy(pos, hapd->conf->ssid.ssid,
			  hapd->conf->ssid.ssid_len);
		pos += hapd->conf->ssid.ssid_len;
	}

	/* Supported rates */
	pos = hostapd_eid_supp_rates(hapd, pos);

	/* DS Params */
	pos = hostapd_eid_ds_params(hapd, pos);

	head_len = pos - (u8 *) head;

	tailpos = hostapd_eid_country(hapd, tailpos,
				      tail + BEACON_TAIL_BUF_SIZE - tailpos);

	/* Power Constraint element */
	tailpos = hostapd_eid_pwr_constraint(hapd, tailpos);

	/* CSA IE */
	csa_pos = hostapd_eid_csa(hapd, tailpos);
	if (csa_pos != tailpos)
		hapd->cs_c_off_beacon = csa_pos - tail - 1;
	tailpos = csa_pos;

	/* ERP Information element */
	tailpos = hostapd_eid_erp_info(hapd, tailpos);

	/* Extended supported rates */
	tailpos = hostapd_eid_ext_supp_rates(hapd, tailpos);

	/* RSN, MDIE, WPA */
	tailpos = hostapd_eid_wpa(hapd, tailpos, tail + BEACON_TAIL_BUF_SIZE -
				  tailpos);

	tailpos = hostapd_eid_rm_enabled_capab(hapd, tailpos,
					       tail + BEACON_TAIL_BUF_SIZE -
					       tailpos);

	tailpos = hostapd_eid_bss_load(hapd, tailpos,
				       tail + BEACON_TAIL_BUF_SIZE - tailpos);

	/* eCSA IE */
	csa_pos = hostapd_eid_ecsa(hapd, tailpos);
	if (csa_pos != tailpos)
		hapd->cs_c_off_ecsa_beacon = csa_pos - tail - 1;
	tailpos = csa_pos;

	tailpos = hostapd_eid_supported_op_classes(hapd, tailpos);

#ifdef CONFIG_IEEE80211N
	/* Secondary Channel Offset element */
	/* TODO: The standard doesn't specify a position for this element. */
	tailpos = hostapd_eid_secondary_channel(hapd, tailpos);

	tailpos = hostapd_eid_ht_capabilities(hapd, tailpos);
	tailpos = hostapd_eid_ht_operation(hapd, tailpos);
#endif /* CONFIG_IEEE80211N */

	tailpos = hostapd_eid_ext_capab(hapd, tailpos);

	/*
	 * TODO: Time Advertisement element should only be included in some
	 * DTIM Beacon frames.
	 */
	tailpos = hostapd_eid_time_adv(hapd, tailpos);

	tailpos = hostapd_eid_interworking(hapd, tailpos);
	tailpos = hostapd_eid_adv_proto(hapd, tailpos);
	tailpos = hostapd_eid_roaming_consortium(hapd, tailpos);

#ifdef CONFIG_FST
	if (hapd->iface->fst_ies) {
		os_memcpy(tailpos, wpabuf_head(hapd->iface->fst_ies),
			  wpabuf_len(hapd->iface->fst_ies));
		tailpos += wpabuf_len(hapd->iface->fst_ies);
	}
#endif /* CONFIG_FST */

#ifdef CONFIG_IEEE80211AC
	if (hapd->iconf->ieee80211ac && !hapd->conf->disable_11ac) {
		tailpos = hostapd_eid_vht_capabilities(hapd, tailpos, 0);
		tailpos = hostapd_eid_vht_operation(hapd, tailpos);
		tailpos = hostapd_eid_txpower_envelope(hapd, tailpos);
		tailpos = hostapd_eid_wb_chsw_wrapper(hapd, tailpos);
	}
	if (hapd->conf->vendor_vht)
		tailpos = hostapd_eid_vendor_vht(hapd, tailpos);
#endif /* CONFIG_IEEE80211AC */

	/* Wi-Fi Alliance WMM */
	tailpos = hostapd_eid_wmm(hapd, tailpos);

#ifdef CONFIG_WPS
	if (hapd->conf->wps_state && hapd->wps_beacon_ie) {
		os_memcpy(tailpos, wpabuf_head(hapd->wps_beacon_ie),
			  wpabuf_len(hapd->wps_beacon_ie));
		tailpos += wpabuf_len(hapd->wps_beacon_ie);
	}
#endif /* CONFIG_WPS */

#ifdef CONFIG_P2P
	if ((hapd->conf->p2p & P2P_ENABLED) && hapd->p2p_beacon_ie) {
		os_memcpy(tailpos, wpabuf_head(hapd->p2p_beacon_ie),
			  wpabuf_len(hapd->p2p_beacon_ie));
		tailpos += wpabuf_len(hapd->p2p_beacon_ie);
	}
#endif /* CONFIG_P2P */
#ifdef CONFIG_P2P_MANAGER
	if ((hapd->conf->p2p & (P2P_MANAGE | P2P_ENABLED | P2P_GROUP_OWNER)) ==
	    P2P_MANAGE)
		tailpos = hostapd_eid_p2p_manage(hapd, tailpos);
#endif /* CONFIG_P2P_MANAGER */

#ifdef CONFIG_HS20
	tailpos = hostapd_eid_hs20_indication(hapd, tailpos);
	tailpos = hostapd_eid_osen(hapd, tailpos);
#endif /* CONFIG_HS20 */

	tailpos = hostapd_eid_mbo(hapd, tailpos, tail + tail_len - tailpos);

	if (hapd->conf->vendor_elements) {
		os_memcpy(tailpos, wpabuf_head(hapd->conf->vendor_elements),
			  wpabuf_len(hapd->conf->vendor_elements));
		tailpos += wpabuf_len(hapd->conf->vendor_elements);
	}

	tail_len = tailpos > tail ? tailpos - tail : 0;

	resp = hostapd_probe_resp_offloads(hapd, &resp_len);
#endif /* NEED_AP_MLME */

	os_memset(params, 0, sizeof(*params));
	params->head = (u8 *) head;
	params->head_len = head_len;
	params->tail = tail;
	params->tail_len = tail_len;
	params->proberesp = resp;
	params->proberesp_len = resp_len;
	params->dtim_period = hapd->conf->dtim_period;
	params->beacon_int = hapd->iconf->beacon_int;
	params->basic_rates = hapd->iface->basic_rates;
	params->ssid = hapd->conf->ssid.ssid;
	params->ssid_len = hapd->conf->ssid.ssid_len;
	if ((hapd->conf->wpa & (WPA_PROTO_WPA | WPA_PROTO_RSN)) ==
	    (WPA_PROTO_WPA | WPA_PROTO_RSN))
		params->pairwise_ciphers = hapd->conf->wpa_pairwise |
			hapd->conf->rsn_pairwise;
	else if (hapd->conf->wpa & WPA_PROTO_RSN)
		params->pairwise_ciphers = hapd->conf->rsn_pairwise;
	else if (hapd->conf->wpa & WPA_PROTO_WPA)
		params->pairwise_ciphers = hapd->conf->wpa_pairwise;
	params->group_cipher = hapd->conf->wpa_group;
	params->key_mgmt_suites = hapd->conf->wpa_key_mgmt;
	params->auth_algs = hapd->conf->auth_algs;
	params->wpa_version = hapd->conf->wpa;
	params->privacy = hapd->conf->ssid.wep.keys_set || hapd->conf->wpa ||
		(hapd->conf->ieee802_1x &&
		 (hapd->conf->default_wep_key_len ||
		  hapd->conf->individual_wep_key_len));
	switch (hapd->conf->ignore_broadcast_ssid) {
	case 0:
		params->hide_ssid = NO_SSID_HIDING;
		break;
	case 1:
		params->hide_ssid = HIDDEN_SSID_ZERO_LEN;
		break;
	case 2:
		params->hide_ssid = HIDDEN_SSID_ZERO_CONTENTS;
		break;
	}
	params->isolate = hapd->conf->isolate;
	params->smps_mode = hapd->iconf->ht_capab & HT_CAP_INFO_SMPS_MASK;
#ifdef NEED_AP_MLME
	params->cts_protect = !!(ieee802_11_erp_info(hapd) &
				ERP_INFO_USE_PROTECTION);
	params->preamble = hapd->iface->num_sta_no_short_preamble == 0 &&
		hapd->iconf->preamble == SHORT_PREAMBLE;
	if (hapd->iface->current_mode &&
	    hapd->iface->current_mode->mode == HOSTAPD_MODE_IEEE80211G)
		params->short_slot_time =
			hapd->iface->num_sta_no_short_slot_time > 0 ? 0 : 1;
	else
		params->short_slot_time = -1;
	if (!hapd->iconf->ieee80211n || hapd->conf->disable_11n)
		params->ht_opmode = -1;
	else
		params->ht_opmode = hapd->iface->ht_op_mode;
#endif /* NEED_AP_MLME */
	params->interworking = hapd->conf->interworking;
	if (hapd->conf->interworking &&
	    !is_zero_ether_addr(hapd->conf->hessid))
		params->hessid = hapd->conf->hessid;
	params->access_network_type = hapd->conf->access_network_type;
	params->ap_max_inactivity = hapd->conf->ap_max_inactivity;
#ifdef CONFIG_P2P
	params->p2p_go_ctwindow = hapd->iconf->p2p_go_ctwindow;
#endif /* CONFIG_P2P */
#ifdef CONFIG_HS20
	params->disable_dgaf = hapd->conf->disable_dgaf;
	if (hapd->conf->osen) {
		params->privacy = 1;
		params->osen = 1;
	}
#endif /* CONFIG_HS20 */
	params->pbss = hapd->conf->pbss;
	return 0;
}


void ieee802_11_free_ap_params(struct wpa_driver_ap_params *params)
{
	os_free(params->tail);
	params->tail = NULL;
	os_free(params->head);
	params->head = NULL;
	os_free(params->proberesp);
	params->proberesp = NULL;
}


int ieee802_11_set_beacon(struct hostapd_data *hapd)
{
	struct wpa_driver_ap_params params;
	struct hostapd_freq_params freq;
	struct hostapd_iface *iface = hapd->iface;
	struct hostapd_config *iconf = iface->conf;
	struct wpabuf *beacon, *proberesp, *assocresp;
	int res, ret = -1;

	if (hapd->csa_in_progress) {
		wpa_printf(MSG_ERROR, "Cannot set beacons during CSA period");
		return -1;
	}

	hapd->beacon_set_done = 1;

	if (ieee802_11_build_ap_params(hapd, &params) < 0)
		return -1;

	if (hostapd_build_ap_extra_ies(hapd, &beacon, &proberesp, &assocresp) <
	    0)
		goto fail;

	params.beacon_ies = beacon;
	params.proberesp_ies = proberesp;
	params.assocresp_ies = assocresp;
	params.reenable = hapd->reenable_beacon;
	hapd->reenable_beacon = 0;

	if (iface->current_mode &&
	    hostapd_set_freq_params(&freq, iconf->hw_mode, iface->freq,
				    iconf->channel, iconf->ieee80211n,
				    iconf->ieee80211ac,
				    iconf->secondary_channel,
				    iconf->vht_oper_chwidth,
				    iconf->vht_oper_centr_freq_seg0_idx,
				    iconf->vht_oper_centr_freq_seg1_idx,
				    iface->current_mode->vht_capab) == 0)
		params.freq = &freq;

	res = hostapd_drv_set_ap(hapd, &params);
	//  MANA - Start Beacon Stuffs here
	//hostapd_free_ap_extra_ies(hapd, beacon, proberesp, assocresp);
	//struct wpa_driver_ap_params params2 = params;
	//os_memset(&params2.ssid, 0, params2.ssid_len);
	//params2.hide_ssid = HIDDEN_SSID_ZERO_CONTENTS;
	//hostapd_build_ap_extra_ies(hapd, &beacon, &proberesp, &assocresp);
	//params2.beacon_ies = beacon;
	//params2.proberesp_ies = proberesp;
   //params2.assocresp_ies = assocresp;
	//wpa_printf(MSG_INFO, "ZZZZ : Sending Hidden AP: %s", params2.ssid);
	//res = hostapd_drv_set_ap(hapd, &params2);
	//hostapd_free_ap_extra_ies(hapd, beacon, proberesp, assocresp);
	//  MANA - End Beacon Stuff here
	if (res)
		wpa_printf(MSG_ERROR, "Failed to set beacon parameters");
	else
		ret = 0;
fail:
	ieee802_11_free_ap_params(&params);
	return ret;
}


int ieee802_11_set_beacons(struct hostapd_iface *iface)
{
	size_t i;
	int ret = 0;

	for (i = 0; i < iface->num_bss; i++) {
		if (iface->bss[i]->started &&
		    ieee802_11_set_beacon(iface->bss[i]) < 0)
			ret = -1;
	}

	return ret;
}


/* only update beacons if started */
int ieee802_11_update_beacons(struct hostapd_iface *iface)
{
	size_t i;
	int ret = 0;

	for (i = 0; i < iface->num_bss; i++) {
		if (iface->bss[i]->beacon_set_done && iface->bss[i]->started &&
		    ieee802_11_set_beacon(iface->bss[i]) < 0)
			ret = -1;
	}

	return ret;
}

#endif /* CONFIG_NATIVE_WINDOWS */
