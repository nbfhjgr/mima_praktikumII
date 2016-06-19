/*************************************************************
 **         Europäisches Institut für Systemsicherheit        *
 **   Proktikum "Kryptoanalyse"                               *
 **                                                           *
 ** Versuch 4: Kocher-Timing-Attack                           *
 **                                                           *
 **************************************************************
 **
 ** daem_acc.c: Routinen für den Zugriff auf den Dämonen
 **/
#include <stdio.h>
#include <pwd.h>

#include "network.h"

#include "longint.h"

#include "timing.h"

#include "daemon.h"

static Connection c = 0;
static struct message in, out;

char *MakeNetName2(const char *name) {
	//const char *username = getlogin();
	struct passwd *pass = getpwuid(getuid());
	const char *username = pass->pw_name;
	char *res;
	int len;

	len = (name ? strlen(name) : 0) + strlen(username) + 2;

	if (!(res = malloc(len))) {
		fprintf(stderr, "FATAL ERROR in MakeNetName: out of memory\n");
		exit(20);
	}

	strcpy(res, username);
	if (name && *name) {
		strcat(res, "_");
		strcat(res, name);
	}

	return res;
}

void connect_daemon(longnum_ptr n) {
	char *name = MakeNetName2("Timing");
	if (c) {
		fprintf(stderr, "Warning: connect_daemon: already connected\n");
		disc_daemon();
	}
	c = ConnectTo(name, TIMING_NAME);
	if (!c) {
		fprintf(stderr, "Connect failed: %s\n", NET_ErrorText());
		exit(1);
	}
	if (Receive(c, &in, sizeof(in)) != sizeof(in)) {
		fprintf(stderr, "Error in Receive in connect_daemon\n");
		exit(1);
	}
	if (in.type != SC_Modulus) {
		fprintf(stderr, "Unexpected message type (expected SC_Modulus)\n");
		exit(1);
	}
	if (n)
		memcpy(n, &in.body.sc_modulus.n, sizeof(*n));
}

unsigned long exp_daemon(longnum_ptr z, const_longnum_ptr x) {
	if (!c) {
		fprintf(stderr, "exp_daemon called without connection\n");
		exit(1);
	}
	out.type = CS_Exp;
	LCpy(&out.body.cs_exp.x, x);
	Transmit(c, &out, sizeof(out));
	if (Receive(c, &in, sizeof(in)) != sizeof(in)) {
		fprintf(stderr, "Error in Receive in exp_daemon\n");
		exit(1);
	}
	if (in.type != SC_ExpResp) {
		fprintf(stderr, "Unexpected message type (expected SC_ExpResp)\n");
		exit(1);
	}
	if (z)
		LCpy(z, &in.body.sc_exp_r.z);
	return in.body.sc_exp_r.timing;
}

int key_daemon(longnum_ptr y_ok, const_longnum_ptr y_trial) {
	if (!c) {
		fprintf(stderr, "key_daemon called without connection\n");
		exit(1);
	}
	out.type = CS_Key;
	LCpy(&out.body.cs_key.y, y_trial);
	Transmit(c, &out, sizeof(out));
	if (Receive(c, &in, sizeof(in)) != sizeof(in)) {
		fprintf(stderr, "Error in Receive in key_daemon\n");
		exit(1);
	}
	if (in.type != SC_KeyResp) {
		fprintf(stderr, "Unexpected message type (expected SC_KeyResp)\n");
		exit(1);
	}
	if (y_ok)
		LCpy(y_ok, &in.body.sc_key_r.y);
	return in.body.sc_key_r.ok;
}

void disc_daemon(void) {
	DisConnect(c);
	c = 0;
}
