CFLAGS = -g -O2 -Wall
LDFLAGS = -lpcap -lm

all: detector

detector: detector.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f detector *.o
