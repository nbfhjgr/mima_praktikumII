
include ../include/Makefile.Settings


all: ssc attack

clean:
	rm -f *.o ssc attack core

ssc: ssc_main.o libssc.a
	gcc -o ssc ssc_main.o libssc.a

attack: attack.o libssc.a
	gcc -o attack attack.o libssc.a

