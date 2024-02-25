CC      = gcc
CFLAGS  = -Wall -Wunused -Wstrict-prototypes -g -O2
#CFLAGS =
INCLUDE = -I.. -I.
LIBS	= -lpopt

forwarder:	forwarder.c
		$(CC) $(CFLAGS) $(INCLUDE)  -o $@ $^ $(LIBS)

clean:
		rm -f forwarder *.o *~ *.orig
