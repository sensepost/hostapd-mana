/*
 * hostapd-mana control interface helpers
 */

#ifndef MANA_CTRL_IFACE_H
#define MANA_CTRL_IFACE_H

struct hostapd_data;

int mana_ctrl_iface_process(struct hostapd_data *hapd, const char *cmd,
			    char *reply, int reply_size, int *reply_len);

#endif /* MANA_CTRL_IFACE_H */
