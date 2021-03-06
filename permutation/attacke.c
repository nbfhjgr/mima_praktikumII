/*************************************************************
 **         Europäisches Institut für Systemsicherheit        *
 **         Praktikum "Kryptoanalyse"                         *
 **                                                           *
 **   Versuch 2: Permutations-Chiffre                         *
 **                                                           *
 **************************************************************
 **
 ** attacke.c: Implementierung einer Permutations-Chiffre
 **            Rahmenprogramm zur Lösung
 **/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "libperm.h"

#define PERIODE 20
#define CHIFFRAT "chiffrat"
#define PERMUTATION "permutation"
#define LOESUNG "klartext"

int loesung[PERIODE];

int laenge;
char *chiffrat;

char *scratch1, *scratch2;

int main(void) {
	FILE *f;

	f = fopen(CHIFFRAT, "r");
	if (!f) {
		perror("fopen");
		fprintf(stderr, "Konnte Datei %s nicht oeffnen\n", CHIFFRAT);
		exit(2);
	}
	fseek(f, 0, SEEK_END);
	laenge = ftell(f);
	rewind(f);
	chiffrat = malloc(laenge);
	scratch1 = malloc(laenge);
	scratch2 = malloc(laenge);
	if (!chiffrat || !scratch1 || !scratch2) {
		fprintf(stderr, "Konnte Puffer nicht allozieren\n");
		exit(2);
	}
	if (fread(chiffrat, 1, laenge, f) != laenge) {
		fprintf(stderr, "Fehler beim einlesen der Datei %s\n", CHIFFRAT);
		exit(2);
	}
	fclose(f);

	{
		extern void attacke(void);
		attacke();
	}
	if (writeperm(PERMUTATION, PERIODE, loesung) < 0) {
		fprintf(stderr, "Fehler beim Schreiben der Loesung auf Datei %s\n",
		PERMUTATION);
		exit(2);
	}
	printf("Nun kannst Du versuchen, die Datei mit dem Befehl:\n");
	printf("  decrypt %s %s %s\n", PERMUTATION, CHIFFRAT, LOESUNG);
	printf("zu entschluesseln, um zu sehen, ob die Loesung stimmt.\n");
	exit(0);
}

int is_u_space_and_v_grossOrklammer(char u, char v) {
	if (isspace(u))
		if ((v >= 'A' && v <= 'Z') || v == '(') {
			return 1;
		}
	return 0;
}

int is_u_punktOrkomma_and_v_space(char u, char v) {
	if (isspace(v))
		if (u == '.' || u == ',')
			return 1;
	return 0;
}

int check_buv(char u, char v) {
	if (is_u_space_and_v_grossOrklammer(u, v))
		return 1;
	if (is_u_punktOrkomma_and_v_space(u, v))
		return 1;
	return 0;
}

// find the max of the column
int f_max(int a[][PERIODE], int spalte) {
	int max = 0;
	for (int i = 0; i < PERIODE; i++)
		if (max < a[i][spalte]) {
			max = a[i][spalte];
		}
	return max;
}

void attacke(void) {
	/* *** Hier soll die Attacke implementiert werden *** */
	/* Globale Variablen:
	 *   laenge         Laenge des Chiffrats
	 *   chiffrat       Puffer, in dem das Chiffrat vorliegt
	 *   scratch1  und
	 *   scratch2       2 Puffer der Laenge 'laenge', die beliebig verwendet
	 *                  werden koennen (char *)
	 *   loesung        int loesung[PERIODE], dort sollte nach dem Ende
	 *                  dieser Funktion die gesuchte Permutation stehen!
	 *   PERIODE        In diesem #define steht die Periodenlaenge, die
	 *                  in diesem Versuch benutzt wurde.
	 */

	/* Aufgabe */

	int n = laenge / PERIODE;
	int a[PERIODE][PERIODE];
	int min_maxSpalte = n;
	int spalte = 0;
	int cur_pos = 0;
	int max, next = 0;
	memset(&a, 0, sizeof(int) * PERIODE * PERIODE);

	// initialize Matrix a with 2 count functions
	for (int i = 0; i < PERIODE; i++)
		for (int j = 0; j < PERIODE; j++)
			if (i != j) {
				for (int p = 0; p < n; p++)
					a[i][j] += check_buv(chiffrat[PERIODE * p + i],
							chiffrat[PERIODE * p + j]);
			}

	// find the first char in cleartext
	for (int i = 0; i < PERIODE; i++) {
		int temp = f_max(a, i);
		if (min_maxSpalte > temp) {
			spalte = i;
			min_maxSpalte = temp;
		}
	}

	loesung[0] = spalte;
	cur_pos++;

	// find the rest of permutation
	for (int i = 1; i < PERIODE; i++) {
		max = 0;
		for (int j = 0; j < PERIODE; j++)
			if (loesung[i - 1] != j)
				if (max < a[loesung[i - 1]][j]) {
					max = a[loesung[i - 1]][j];
					next = j;
				}
		loesung[cur_pos++] = next;
	}

}
