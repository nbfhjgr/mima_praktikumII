#
#         Europäisches Institut für Systemsicherheit
#   Proktikum "Kryptographie und Datensicherheitstechnik"
#
# Versuch 1: Klassische Chiffrierverfahren
#

include ../include/Makefile.Settings

SRC	= vigenere.c vigenere-attacke.c
OBJ	= $(SRC:%.c=%.o)
CFLAGS  = $(CFLAGS_DEBUG)

BINS	= vigenere vigenere-attacke

all:	$(BINS)

vigenere:	vigenere.o
	$(CC) -o $@ $@.o $(LFLAGS)

vigenere-attacke:	vigenere-attacke.o
	$(CC) -o $@ $@.o $(LFLAGS)

#------------------------------------------------------------------------------

clean:
	-rm -f *.o *~ *% $(BINS) gnuplot.in.cmd gnuplot.in.data
