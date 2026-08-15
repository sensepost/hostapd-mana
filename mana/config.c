/*
 * hostapd-mana configuration parsing
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "mana/config.h"

static int mana_config_open_append(const char *path, const char *what, int line)
{
	FILE *f = fopen(path, "a");

	if (!f) {
		wpa_printf(MSG_ERROR, "MANA: Line %d: Failed to open %s '%s'",
			   line, what, path);
		return -1;
	}
	fclose(f);
	return 0;
}

void mana_config_defaults(struct hostapd_config *conf)
{
	conf->enable_mana = 0;
	conf->mana_loud = 0;
	conf->mana_macacl = 0;
	conf->mana_outfile = "NOT_SET";
	conf->mana_ssid_filter_file = "NOT_SET";
	conf->mana_ssid_filter_type = 1;
	conf->mana_wpe = 0;
	conf->mana_credout = "NOT_SET";
	conf->mana_wpaout = "NOT_SET";
	conf->mana_eapsuccess = 0;
	conf->mana_eaptls = 0;
	conf->enable_sycophant = 0;
	conf->sycophant_dir = "NOT_SET";
}

int mana_config_read_ssidlist(const char *fname,
			      struct ssid_filter_entry **ssid_filter, int *num)
{
	FILE *f;
	char buf[128], *pos;
	struct ssid_filter_entry *new_ssid_filter;

	if (!fname)
		return 0;

	f = fopen(fname, "r");
	if (!f) {
		wpa_printf(MSG_ERROR, "SSID list file '%s' not found.", fname);
		return -1;
	}

	while (fgets(buf, sizeof(buf), f)) {
		if (buf[0] == '#')
			continue;

		pos = buf;
		while (*pos != '\0') {
			if (*pos == '\n') {
				*pos = '\0';
				break;
			}
			pos++;
		}

		if (buf[0] == '\0')
			continue;

		pos = buf;
		if (os_strlen(pos) > SSID_MAX_LEN) {
			wpa_printf(MSG_ERROR,
				   "SSID %s is too long (more than %d characters.)",
				   pos, SSID_MAX_LEN);
			fclose(f);
			return -1;
		}

		new_ssid_filter = os_realloc_array(*ssid_filter, *num + 1,
						   sizeof(**ssid_filter));
		if (!new_ssid_filter) {
			wpa_printf(MSG_ERROR, "SSID list reallocation failed");
			fclose(f);
			return -1;
		}

		*ssid_filter = new_ssid_filter;
		os_memset(&(*ssid_filter)[*num], 0, sizeof(**ssid_filter));
		os_memcpy((*ssid_filter)[*num].ssid, pos, os_strlen(pos));
		(*num)++;
		wpa_printf(MSG_INFO, "SSID: '%s' added.", pos);
	}

	fclose(f);
	return 0;
}

int mana_config_fill(struct hostapd_config *conf,
		     struct hostapd_bss_config *bss,
		     const char *field, char *value, int line)
{
	if (os_strcmp(field, "enable_mana") == 0) {
		conf->enable_mana = atoi(value) != 0;
		if (conf->enable_mana)
			wpa_printf(MSG_DEBUG, "MANA: Enabled");
		return MANA_CONFIG_HANDLED;
	}
	if (os_strcmp(field, "mana_loud") == 0) {
		conf->mana_loud = atoi(value) != 0;
		if (conf->mana_loud)
			wpa_printf(MSG_DEBUG, "MANA: Loud mode enabled");
		return MANA_CONFIG_HANDLED;
	}
	if (os_strcmp(field, "mana_macacl") == 0) {
		conf->mana_macacl = atoi(value) != 0;
		if (conf->mana_macacl)
			wpa_printf(MSG_DEBUG,
				   "MANA: MAC ACLs extended to management frames");
		return MANA_CONFIG_HANDLED;
	}
	if (os_strcmp(field, "mana_outfile") == 0) {
		if (mana_config_open_append(value, "activity file", line) < 0)
			return MANA_CONFIG_ERROR;
		conf->mana_outfile = os_strdup(value);
		if (!conf->mana_outfile)
			return MANA_CONFIG_ERROR;
		wpa_printf(MSG_INFO,
			   "MANA: Observed activity will be written to. File %s set.",
			   conf->mana_outfile);
		return MANA_CONFIG_HANDLED;
	}
	if (os_strcmp(field, "mana_ssid_filter_file") == 0) {
		if (mana_config_read_ssidlist(value, &bss->ssid_filter,
					      &bss->num_ssid_filter)) {
			wpa_printf(MSG_ERROR,
				   "Line %d: Failed to read SSID filter list '%s'",
				   line, value);
			return MANA_CONFIG_ERROR;
		}
		conf->mana_ssid_filter_file = os_strdup(value);
		if (!conf->mana_ssid_filter_file)
			return MANA_CONFIG_ERROR;
		wpa_printf(MSG_INFO, "MANA: SSID Filter enabled. File %s set.",
			   conf->mana_ssid_filter_file);
		return MANA_CONFIG_HANDLED;
	}
	if (os_strcmp(field, "mana_ssid_filter_type") == 0) {
		conf->mana_ssid_filter_type = atoi(value) ? 1 : 0;
		return MANA_CONFIG_HANDLED;
	}
	if (os_strcmp(field, "mana_wpe") == 0) {
		conf->mana_wpe = atoi(value) != 0;
		if (conf->mana_wpe)
			wpa_printf(MSG_DEBUG, "MANA: WPE EAP mode enabled");
		return MANA_CONFIG_HANDLED;
	}
	if (os_strcmp(field, "mana_credout") == 0) {
		if (mana_config_open_append(value, "credential out file", line) < 0)
			return MANA_CONFIG_ERROR;
		conf->mana_credout = os_strdup(value);
		if (!conf->mana_credout)
			return MANA_CONFIG_ERROR;
		wpa_printf(MSG_INFO,
			   "MANA: Captured credentials will be written to file '%s'.",
			   conf->mana_credout);
		return MANA_CONFIG_HANDLED;
	}
	if (os_strcmp(field, "mana_wpaout") == 0) {
		if (mana_config_open_append(value, "WPA/2 handshake out file", line) < 0)
			return MANA_CONFIG_ERROR;
		conf->mana_wpaout = os_strdup(value);
		if (!conf->mana_wpaout)
			return MANA_CONFIG_ERROR;
		wpa_printf(MSG_INFO,
			   "MANA: Captured WPA/2 handshakes will be written to file '%s'.",
			   conf->mana_wpaout);
		return MANA_CONFIG_HANDLED;
	}
	if (os_strcmp(field, "mana_eapsuccess") == 0) {
		conf->mana_eapsuccess = atoi(value) != 0;
		if (conf->mana_eapsuccess)
			wpa_printf(MSG_DEBUG, "MANA: EAP success mode enabled");
		return MANA_CONFIG_HANDLED;
	}
	if (os_strcmp(field, "mana_eaptls") == 0) {
		conf->mana_eaptls = atoi(value) != 0;
		if (conf->mana_eaptls)
			wpa_printf(MSG_DEBUG,
				   "MANA: EAP TLS modes will accept any client certificate.");
		return MANA_CONFIG_HANDLED;
	}
	if (os_strcmp(field, "enable_sycophant") == 0) {
		conf->enable_sycophant = atoi(value) != 0;
		if (conf->enable_sycophant)
			wpa_printf(MSG_DEBUG, "SYCOPHANT: Enabled");
		return MANA_CONFIG_HANDLED;
	}
	if (os_strcmp(field, "sycophant_dir") == 0) {
		size_t dirlen;
		int id;

		if (access(value, W_OK) != 0) {
			wpa_printf(MSG_ERROR,
				   "SYCOPHANT: Line %d: Failed to access sycophant directory '%s'",
				   line, value);
			return MANA_CONFIG_ERROR;
		}

		conf->sycophant_dir = os_strdup(value);
		if (!conf->sycophant_dir)
			return MANA_CONFIG_ERROR;
		wpa_printf(MSG_INFO, "MANA: Sycohpant state directory set to %s.",
			   conf->sycophant_dir);

		dirlen = os_strlen(conf->sycophant_dir);
		conf->sycophant_state_file = os_malloc(dirlen + 16);
		conf->sycophant_challenge_file = os_malloc(dirlen + 10);
		conf->sycophant_response_file = os_malloc(dirlen + 9);
		if (!conf->sycophant_state_file ||
		    !conf->sycophant_challenge_file ||
		    !conf->sycophant_response_file)
			return MANA_CONFIG_ERROR;
		os_snprintf(conf->sycophant_state_file, dirlen + 16,
			    "%sSYCOPHANT_STATE", value);
		os_snprintf(conf->sycophant_challenge_file, dirlen + 10,
			    "%sCHALLENGE", value);
		os_snprintf(conf->sycophant_response_file, dirlen + 9,
			    "%sRESPONSE", value);

		for (id = 1; id <= 2; id++) {
			conf->sycophant_id_file[id - 1] = os_malloc(dirlen + 15);
			if (!conf->sycophant_id_file[id - 1])
				return MANA_CONFIG_ERROR;
			os_snprintf(conf->sycophant_id_file[id - 1],
				    dirlen + 15, "%sSYCOPHANT_P%dID",
				    value, id);
		}
		return MANA_CONFIG_HANDLED;
	}

	return MANA_CONFIG_UNKNOWN;
}
