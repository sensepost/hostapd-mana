/*
 * hostapd-mana control interface helpers
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "common/ieee802_11_defs.h"
#include "ap/hostapd.h"
#include "ap/ap_config.h"
#include "ap/beacon.h"
#include "mana/ctrl_iface.h"

static int mana_reply(char *reply, int reply_size, int *reply_len,
		      const char *text)
{
	int ret = os_snprintf(reply, reply_size, "%s", text);

	if (os_snprintf_error(reply_size, ret))
		return -1;
	*reply_len = ret;
	return 0;
}

static int mana_change_ssid(struct hostapd_data *hapd, const char *ssid)
{
	size_t len = os_strlen(ssid);

	wpa_printf(MSG_DEBUG, "MANA CTRL_IFACE CHANGE SSID %s", ssid);
	if (len > SSID_MAX_LEN || len == 0)
		return -1;

	hapd->conf->ssid.ssid_len = len;
	os_memset(hapd->conf->ssid.ssid, 0, sizeof(hapd->conf->ssid.ssid));
	os_memcpy(hapd->conf->ssid.ssid, ssid, len);
	ieee802_11_set_beacon(hapd);
	wpa_printf(MSG_DEBUG, "MANA CTRL_IFACE DEFAULT SSID CHANGED");
	return 0;
}

int mana_ctrl_iface_process(struct hostapd_data *hapd, const char *cmd,
			    char *reply, int reply_size, int *reply_len)
{
	if (os_strcmp(cmd, "MANA_GET_SSID") == 0) {
		int ret = os_snprintf(reply, reply_size, "%s\n",
				      wpa_ssid_txt(hapd->conf->ssid.ssid,
						   hapd->conf->ssid.ssid_len));
		if (os_snprintf_error(reply_size, ret))
			return -1;
		*reply_len = ret;
		return 1;
	}
	if (os_strncmp(cmd, "MANA_CHANGE_SSID ", 17) == 0) {
		if (mana_change_ssid(hapd, cmd + 17) < 0)
			return -1;
		return mana_reply(reply, reply_size, reply_len, "CHANGED\n") < 0 ?
			-1 : 1;
	}
	if (os_strcmp(cmd, "MANA_DISABLE") == 0) {
		wpa_printf(MSG_DEBUG, "MANA CTRL_IFACE DISABLED");
		hapd->iconf->enable_mana = 0;
		return 1;
	}
	if (os_strcmp(cmd, "MANA_ENABLE") == 0) {
		wpa_printf(MSG_DEBUG, "MANA CTRL_IFACE ENABLED");
		hapd->iconf->enable_mana = 1;
		return 1;
	}
	if (os_strcmp(cmd, "MANA_STATE") == 0) {
		return mana_reply(reply, reply_size, reply_len,
				  hapd->iconf->enable_mana ?
				  "MANA ENABLED\n" : "MANA DISABLED\n") < 0 ?
			-1 : 1;
	}
	if (os_strcmp(cmd, "LOUD_ENABLE") == 0) {
		hapd->iconf->mana_loud = 1;
		return 1;
	}
	if (os_strcmp(cmd, "LOUD_DISABLE") == 0) {
		hapd->iconf->mana_loud = 0;
		return 1;
	}
	if (os_strcmp(cmd, "MANA_MODE") == 0) {
		return mana_reply(reply, reply_size, reply_len,
				  hapd->iconf->mana_loud ?
				  "MANA LOUD MODE ENABLED\n" :
				  "MANA LOUD MODE DISABLED\n") < 0 ? -1 : 1;
	}
	if (os_strcmp(cmd, "MANAACL_ENABLE") == 0) {
		hapd->iconf->mana_macacl = 1;
		return 1;
	}
	if (os_strcmp(cmd, "MANAACL_DISABLE") == 0) {
		hapd->iconf->mana_macacl = 0;
		return 1;
	}
	if (os_strcmp(cmd, "MANA_ACLMODE") == 0) {
		return mana_reply(reply, reply_size, reply_len,
				  hapd->iconf->mana_macacl ?
				  "MANA ACL MODE ENABLED\n" :
				  "MANA ACL MODE DISABLED\n") < 0 ? -1 : 1;
	}
	if (os_strcmp(cmd, "WPE_ENABLE") == 0) {
		hapd->iconf->mana_wpe = 1;
		return 1;
	}
	if (os_strcmp(cmd, "WPE_DISABLE") == 0) {
		hapd->iconf->mana_wpe = 0;
		return 1;
	}
	if (os_strcmp(cmd, "WPE_MODE") == 0) {
		return mana_reply(reply, reply_size, reply_len,
				  hapd->iconf->mana_wpe ?
				  "MANA WPE MODE ENABLED\n" :
				  "MANA WPE MODE DISABLED\n") < 0 ? -1 : 1;
	}
	if (os_strcmp(cmd, "EAPSUCCESS_ENABLE") == 0) {
		hapd->iconf->mana_eapsuccess = 1;
		return 1;
	}
	if (os_strcmp(cmd, "EAPSUCCESS_DISABLE") == 0) {
		hapd->iconf->mana_eapsuccess = 0;
		return 1;
	}
	if (os_strcmp(cmd, "EAPSUCCESS_MODE") == 0) {
		return mana_reply(reply, reply_size, reply_len,
				  hapd->iconf->mana_eapsuccess ?
				  "MANA EAPSUCCESS MODE ENABLED\n" :
				  "MANA EAPSUCCESS MODE DISABLED\n") < 0 ?
			-1 : 1;
	}
	if (os_strcmp(cmd, "MANA_EAPTLS_ENABLE") == 0) {
		hapd->iconf->mana_eaptls = 1;
		return 1;
	}
	if (os_strcmp(cmd, "MANA_EAPTLS_DISABLE") == 0) {
		hapd->iconf->mana_eaptls = 0;
		return 1;
	}
	if (os_strcmp(cmd, "MANA_EAPTLS_MODE") == 0) {
		return mana_reply(reply, reply_size, reply_len,
				  hapd->iconf->mana_eaptls ?
				  "MANA EAPTLS MODE ENABLED\n" :
				  "MANA EAPTLS MODE DISABLED\n") < 0 ?
			-1 : 1;
	}
	if (os_strcmp(cmd, "SYCOPHANT_DISABLE") == 0) {
		hapd->iconf->enable_sycophant = 0;
		return 1;
	}
	if (os_strcmp(cmd, "SYCOPHANT_ENABLE") == 0) {
		hapd->iconf->enable_sycophant = 1;
		return 1;
	}
	if (os_strcmp(cmd, "SYCOPHANT_STATE") == 0) {
		return mana_reply(reply, reply_size, reply_len,
				  hapd->iconf->enable_sycophant ?
				  "SYCOPHANT ENABLED\n" :
				  "SYCOPHANT DISABLED\n") < 0 ? -1 : 1;
	}

	return 0;
}
