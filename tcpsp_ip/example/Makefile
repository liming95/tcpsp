CC      = gcc
CFLAGS  = -Wall -Wunused -Wstrict-prototypes -g -O2
#CFLAGS =
INCLUDE = -I.. -I.
LIBS	= -lpopt

forwarder:	forwarder.c
		$(shell if [ ! -d ./output ]; then mkdir ./output; fi)
		$(CC) $(CFLAGS) $(INCLUDE)  -o output/$@ $^ $(LIBS)

clean:
		rm -f forwarder *.o *~ *.orig
