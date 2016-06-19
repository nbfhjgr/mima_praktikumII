/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Proktikum "Kryptoanalyse"                               *
**                                                           *
** Versuch 4: Kocher-Timing-Attack                           *
**                                                           *
**************************************************************
**
** texp.h: Exponentiation mit simuliertem Timing
**/

#define nbits 128 /* die Rechenlaenge */ 

/* LITModExp (z_in, x, y, n):
 * x_in = (x^y) mod n, return timing
 */
unsigned long LITModExp(longnum_ptr z_in, const_longnum_ptr x, const_longnum_ptr y, const_longnum_ptr n);

/* LITTimeModExp (x,y,n)
 * Berechnet Timing fuer (x^y) mod n
 */
unsigned long LITTimeModExp (const_longnum_ptr x, const_longnum_ptr y,
			     const_longnum_ptr n);

/* LITTimeModMult (x,y,n)
 * Berechnet Timing fuer (x*y) mod n
 * Das Timing ist *nicht* kommutativ!
 */
unsigned long LITTimeModMult (const_longnum_ptr x, const_longnum_ptr y,
			      const_longnum_ptr n);

/* LITTimeModSquare (x, n)
 * Berechnet Timing fuer (x^2) mod n
 * (x^2) mod n ist halb so teuer wie (x*x) mod n!
 */
unsigned long LITTimeModSquare (const_longnum_ptr x, const_longnum_ptr n);
