CFLAGS = -g -O2 -Wall
LDFLAGS = -lpcap -lm

all: detector

clean:
	rm -f detector
