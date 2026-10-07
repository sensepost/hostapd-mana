/*
 * hostapd-mana sycophant socket helpers
 */

#include "utils/includes.h"

#ifndef CONFIG_NATIVE_WINDOWS
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/time.h>
#include <unistd.h>
#endif /* CONFIG_NATIVE_WINDOWS */

#include "utils/common.h"
#include "mana/state.h"
#include "mana/sycophant.h"

#define SYCOPHANT_HEADER_LEN 6
#define SYCOPHANT_MAX_PAYLOAD 4096
#define SYCOPHANT_MSCHAPV2_RESPONSE_LEN 49

enum sycophant_message {
	SYCOPHANT_GET_IDENTITY_1 = 1,
	SYCOPHANT_GET_IDENTITY_2 = 2,
	SYCOPHANT_PUT_CHALLENGE = 3,
	SYCOPHANT_GET_IDENTITY_1_REPLY = 0x81,
	SYCOPHANT_GET_IDENTITY_2_REPLY = 0x82,
	SYCOPHANT_RESPONSE = 0x84
};

#ifndef CONFIG_NATIVE_WINDOWS
static int sycophant_listen_fd = -1;
static int sycophant_client_fd = -1;
static char sycophant_socket_path[sizeof(((struct sockaddr_un *) 0)->sun_path)];
static int sycophant_atexit_registered;
#endif /* CONFIG_NATIVE_WINDOWS */


static int mana_sycophant_active(void)
{
	return mana.conf && mana.conf->enable_sycophant &&
		mana.conf->sycophant_socket &&
		mana.conf->sycophant_socket[0] != '\0';
}


#ifndef CONFIG_NATIVE_WINDOWS
static void sycophant_close_client(void)
{
	if (sycophant_client_fd >= 0)
		close(sycophant_client_fd);
	sycophant_client_fd = -1;
}


static int sycophant_write_all(const u8 *data, size_t len)
{
	while (len) {
		ssize_t res;

#ifdef MSG_NOSIGNAL
		res = send(sycophant_client_fd, data, len, MSG_NOSIGNAL);
#else
		res = send(sycophant_client_fd, data, len, 0);
#endif
		if (res < 0 && errno == EINTR)
			continue;
		if (res <= 0)
			return -1;
		data += res;
		len -= res;
	}
	return 0;
}


static int sycophant_read_all(u8 *data, size_t len)
{
	while (len) {
		ssize_t res = recv(sycophant_client_fd, data, len, 0);

		if (res < 0 && errno == EINTR)
			continue;
		if (res <= 0)
			return -1;
		data += res;
		len -= res;
	}
	return 0;
}


static int sycophant_send_frame(u8 type, const u8 *payload, size_t len)
{
	u8 header[SYCOPHANT_HEADER_LEN];

	if (sycophant_client_fd < 0 || len > SYCOPHANT_MAX_PAYLOAD ||
	    len > 0xffff)
		return -1;
	header[0] = 'S';
	header[1] = 'Y';
	header[2] = 1;
	header[3] = type;
	WPA_PUT_BE16(header + 4, len);
	if (sycophant_write_all(header, sizeof(header)) < 0 ||
	    (len && sycophant_write_all(payload, len) < 0)) {
		sycophant_close_client();
		return -1;
	}
	return 0;
}


static int sycophant_read_frame(u8 *type, u8 *payload, size_t payload_size,
				size_t *payload_len)
{
	u8 header[SYCOPHANT_HEADER_LEN];
	size_t len;

	if (sycophant_read_all(header, sizeof(header)) < 0 ||
	    header[0] != 'S' || header[1] != 'Y' || header[2] != 1) {
		sycophant_close_client();
		return -1;
	}
	len = WPA_GET_BE16(header + 4);
	if (len > payload_size || len > SYCOPHANT_MAX_PAYLOAD ||
	    (len && sycophant_read_all(payload, len) < 0)) {
		sycophant_close_client();
		return -1;
	}
	*type = header[3];
	*payload_len = len;
	return 0;
}


static int sycophant_accept_client(void)
{
	struct timeval timeout;
	fd_set rfds;
	int res;
	u8 first_byte;

	if (sycophant_client_fd >= 0)
		return 0;
	if (sycophant_listen_fd < 0)
		return -1;

	for (;;) {
		FD_ZERO(&rfds);
		FD_SET(sycophant_listen_fd, &rfds);
		timeout.tv_sec = 10;
		timeout.tv_usec = 0;
		res = select(sycophant_listen_fd + 1, &rfds, NULL, NULL,
			     &timeout);
		if (res <= 0) {
			wpa_printf(MSG_WARNING,
				   "SYCOPHANT: No client connected to socket %s",
				   sycophant_socket_path);
			return -1;
		}

		sycophant_client_fd = accept(sycophant_listen_fd, NULL, NULL);
		if (sycophant_client_fd < 0)
			return -1;
		FD_ZERO(&rfds);
		FD_SET(sycophant_client_fd, &rfds);
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		res = select(sycophant_client_fd + 1, &rfds, NULL, NULL,
			     &timeout);
		if (res > 0) {
			ssize_t peek = recv(sycophant_client_fd, &first_byte, 1,
					    MSG_PEEK);
			if (peek == 0) {
				sycophant_close_client();
				continue;
			}
			if (peek < 0) {
				sycophant_close_client();
				return -1;
			}
		} else {
			sycophant_close_client();
			return -1;
		}
		break;
	}
	timeout.tv_sec = 60;
	timeout.tv_usec = 0;
	setsockopt(sycophant_client_fd, SOL_SOCKET, SO_RCVTIMEO,
		   &timeout, sizeof(timeout));
	setsockopt(sycophant_client_fd, SOL_SOCKET, SO_SNDTIMEO,
		   &timeout, sizeof(timeout));
#ifdef SO_NOSIGPIPE
	{
		int one = 1;
		setsockopt(sycophant_client_fd, SOL_SOCKET, SO_NOSIGPIPE,
			   &one, sizeof(one));
	}
#endif /* SO_NOSIGPIPE */
	return 0;
}
#endif /* CONFIG_NATIVE_WINDOWS */


int mana_sycophant_init(void)
{
#ifdef CONFIG_NATIVE_WINDOWS
	return mana_sycophant_active() ? -1 : 0;
#else /* CONFIG_NATIVE_WINDOWS */
	struct sockaddr_un addr;
	struct stat st;
	int fd;
	const char *path;

	if (!mana_sycophant_active())
		return 0;
	path = mana.conf->sycophant_socket;
	if (sycophant_listen_fd >= 0) {
		if (os_strcmp(path, sycophant_socket_path) == 0)
			return 0;
		wpa_printf(MSG_ERROR,
			   "SYCOPHANT: Socket path cannot change while Mana is running");
		return -1;
	}
	if (os_strlen(path) >= sizeof(addr.sun_path)) {
		wpa_printf(MSG_ERROR, "SYCOPHANT: Socket path is too long");
		return -1;
	}

	if (lstat(path, &st) == 0) {
		struct sockaddr_un old_addr;
		int probe;

		if (!S_ISSOCK(st.st_mode)) {
			wpa_printf(MSG_ERROR,
				   "SYCOPHANT: Refusing to replace non-socket path %s",
				   path);
			return -1;
		}
		probe = socket(AF_UNIX, SOCK_STREAM, 0);
		if (probe < 0)
			return -1;
		os_memset(&old_addr, 0, sizeof(old_addr));
		old_addr.sun_family = AF_UNIX;
		os_strlcpy(old_addr.sun_path, path, sizeof(old_addr.sun_path));
		if (connect(probe, (struct sockaddr *) &old_addr,
			    sizeof(old_addr)) == 0) {
			close(probe);
			wpa_printf(MSG_ERROR,
				   "SYCOPHANT: Another server is using socket %s",
				   path);
			return -1;
		}
		if (errno != ECONNREFUSED && errno != ENOENT) {
			close(probe);
			return -1;
		}
		close(probe);
		if (unlink(path) < 0)
			return -1;
	}

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;
	os_memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	os_strlcpy(addr.sun_path, path, sizeof(addr.sun_path));
	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		int err = errno;
		close(fd);
		wpa_printf(MSG_ERROR,
			   "SYCOPHANT: Could not bind socket %s: %s",
			   path, strerror(err));
		return -1;
	}
	if (chmod(path, 0600) < 0 || listen(fd, 1) < 0) {
		int err = errno;
		close(fd);
		unlink(path);
		wpa_printf(MSG_ERROR,
			   "SYCOPHANT: Could not create socket %s: %s",
			   path, strerror(err));
		return -1;
	}

	sycophant_listen_fd = fd;
	os_strlcpy(sycophant_socket_path, path,
		   sizeof(sycophant_socket_path));
	if (!sycophant_atexit_registered) {
		atexit(mana_sycophant_deinit);
		sycophant_atexit_registered = 1;
	}
	wpa_printf(MSG_INFO, "SYCOPHANT: Listening on %s",
		   sycophant_socket_path);
	return 0;
#endif /* CONFIG_NATIVE_WINDOWS */
}


void mana_sycophant_deinit(void)
{
#ifndef CONFIG_NATIVE_WINDOWS
	sycophant_close_client();
	if (sycophant_listen_fd >= 0)
		close(sycophant_listen_fd);
	sycophant_listen_fd = -1;
	if (sycophant_socket_path[0])
		unlink(sycophant_socket_path);
#endif /* CONFIG_NATIVE_WINDOWS */
}


void mana_sycophant_identity(int phase, const u8 *identity,
			     size_t identity_len)
{
#ifndef CONFIG_NATIVE_WINDOWS
	u8 type, reply_type, payload[SYCOPHANT_MAX_PAYLOAD];
	size_t len;

	if (!mana_sycophant_active() || identity_len > SYCOPHANT_MAX_PAYLOAD ||
	    sycophant_accept_client() < 0)
		return;
	if (sycophant_read_frame(&type, payload, sizeof(payload), &len) < 0 ||
	    len != 0) {
		wpa_printf(MSG_ERROR, "SYCOPHANT: Invalid identity request");
		sycophant_close_client();
		return;
	}
	if (phase == 1 && type == SYCOPHANT_GET_IDENTITY_1)
		reply_type = SYCOPHANT_GET_IDENTITY_1_REPLY;
	else if (phase == 2 && type == SYCOPHANT_GET_IDENTITY_2)
		reply_type = SYCOPHANT_GET_IDENTITY_2_REPLY;
	else {
		wpa_printf(MSG_ERROR, "SYCOPHANT: Unexpected identity request");
		sycophant_close_client();
		return;
	}
	if (sycophant_send_frame(reply_type, identity, identity_len) < 0)
		wpa_printf(MSG_ERROR, "SYCOPHANT: Failed to return identity");
#endif /* CONFIG_NATIVE_WINDOWS */
}


int mana_sycophant_mschapv2_challenge(u8 *challenge, size_t len)
{
#ifndef CONFIG_NATIVE_WINDOWS
	u8 type, payload[SYCOPHANT_MAX_PAYLOAD];
	size_t payload_len;

	if (!mana_sycophant_active())
		return 0;
	if (len != 16 || sycophant_accept_client() < 0 ||
	    sycophant_read_frame(&type, payload, sizeof(payload),
				 &payload_len) < 0 ||
	    type != SYCOPHANT_PUT_CHALLENGE || payload_len != len) {
		wpa_printf(MSG_ERROR, "SYCOPHANT: Invalid challenge message");
		sycophant_close_client();
		return -1;
	}
	os_memcpy(challenge, payload, len);
	wpa_hexdump(MSG_DEBUG, "SYCOPHANT: Relayed MSCHAPv2 challenge",
		    challenge, len);
	return 0;
#else /* CONFIG_NATIVE_WINDOWS */
	return -1;
#endif /* CONFIG_NATIVE_WINDOWS */
}


void mana_sycophant_mschapv2_response(const u8 *response, size_t len)
{
#ifndef CONFIG_NATIVE_WINDOWS
	if (!mana_sycophant_active() ||
	    len != SYCOPHANT_MSCHAPV2_RESPONSE_LEN ||
	    sycophant_accept_client() < 0)
		return;
	if (sycophant_send_frame(SYCOPHANT_RESPONSE, response, len) < 0)
		wpa_printf(MSG_ERROR,
			   "SYCOPHANT: Failed to send relayed response");
#endif /* CONFIG_NATIVE_WINDOWS */
}
