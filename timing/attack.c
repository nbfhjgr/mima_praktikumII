/*************************************************************
 **         Europäisches Institut für Systemsicherheit        *
 **   Proktikum "Kryptoanalyse"                               *
 **                                                           *
 ** Versuch 4: Kocher-Timing-Attack                           *
 **                                                           *
 **************************************************************
 **
 ** attack.c: Timing-Attacke Rahmenprogramm
 **/
#include <stdio.h>
#include <time.h>

#include "longint.h"
#include "texp.h"

#include "daemon.h"

#define nbits 128 /* die Rechenlaenge */

#define EXPBITS 128 /* Anzahl der Bits im Exponent */

#define NUM_PROBE 1000

longnum n; /* Modulus */
longnum y_trial; /* Hier soll der geheime Exponent y berechnet werden */
longnum y_ok; /* Tatsaechlicher geheimer Exponent (vom Daemon) */
int ok; /* war der Exponent richtig? */

const unsigned long expected_timing = (1 << 18);
/* Erwartungswert fuer den Zeitaufwand einer Multiplikation */

void timingAttack(longnum_ptr y, longnum_ptr n);

int main(void) {
	connect_daemon(&n); /* Mit dem Daemonen verbinden und den Modulus
	 * abholen */

	/* XXX Aufgabe: mit exp_daemon () Samples generieren und y_trial berechnen */
	LInitNumber(&y_trial, nbits, 0);
	timingAttack(&y_trial, &n);

	printf("Berechneter Exponent: %s\n", LLong2Hex(&y_trial, 0, 1, 1));
	ok = key_daemon(&y_ok, &y_trial);
	printf("Das war %s\n", ok ? "richtig" : "falsch");
	if (!ok) {
		printf("Richtig war: %s\n", LLong2Hex(&y_ok, 0, 1, 1));
	}
	disc_daemon(); /* Verbindung zum Daemon beenden */
	exit(0);
}

unsigned long getModSquareTime(const_longnum_ptr x, const_longnum_ptr n) {
	longnum temp;
	LInitNumber(&temp, nbits, 0);
	LCpy(&temp, x);
	unsigned long t = 0;
	for (int i = 0; i < EXPBITS; i++) {
		t += LITTimeModSquare(&temp, n);
		LModSquare(&temp, &temp, n);
	}
	return t;
}

void initProbes(longnum_ptr x, longnum_ptr z, const longnum_ptr n,
		unsigned long timing[]) {
	longnum temp;
	LInitNumber(&temp, nbits, 0);
	LSeed(time(NULL));

	for (int i = 0; i < NUM_PROBE; i++) {
		LInitNumber(x + i, nbits, 0);
		LInitNumber(z + i, nbits, 0);
		LInt2Long(1, z + i);
		LRand(n, x + i);
		timing[i] = exp_daemon(&temp, x + i) - getModSquareTime(x + i, n);
		//timing[i] = exp_daemon(&temp, x + i)
		//		- EXPBITS * LITTimeModSquare(x + i, n);
	}
}

void timingAttack(longnum_ptr y, longnum_ptr n) {

	longnum eins, temp;
	LInitNumber(&eins, nbits, 0);
	LInt2Long(1, &eins);
	LInitNumber(&temp, nbits, 0);
	unsigned long timing_base_eins = exp_daemon(&temp, &eins);
	unsigned long time_exp_base_eins = LITTimeModSquare(&eins, n);
	unsigned long time_mul_eins = LITTimeModMult(&eins, &eins, n);
	int hammingsGewicht = (timing_base_eins - EXPBITS * time_exp_base_eins)
			/ time_mul_eins;

	longnum probe_x[NUM_PROBE], probe_z[NUM_PROBE];
	unsigned long timing[NUM_PROBE];
	initProbes(probe_x, probe_z, n, timing);

	unsigned long time_multi_z_x[NUM_PROBE];
	unsigned long t1, t0;
	int cur_bit = 0;
	for (int i = 0; i < EXPBITS; i++) {
		t1 = 0;
		t0 = 0;
		for (int j = 0; j < NUM_PROBE; j++) {
			time_multi_z_x[j] = LITTimeModMult(&probe_z[j], &probe_x[j], n);
			t1 += abs(
					timing[j]
							- (time_multi_z_x[j]
									+ (hammingsGewicht - 1) * expected_timing));
			t0 += abs(timing[j] - (hammingsGewicht * expected_timing));
		}

		if (t1 < t0) {
			cur_bit = 1;
			hammingsGewicht--;
			for (int j = 0; j < NUM_PROBE; j++) {
				timing[j] -= time_multi_z_x[j];
				LModMult(&probe_z[j], &probe_x[j], &probe_z[j], n);
			}
		} else
			cur_bit = 0;
		LSetBit(y, i, cur_bit);
		for (int j = 0; j < NUM_PROBE; j++) {
			LModSquare(&probe_x[j], &probe_x[j], n);
		}
	}
}
