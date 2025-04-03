CC = gcc
CFLAGS = -Wall -Wextra -g

SRC = firewall.c iface.c ruleparser.c logger.c icmprelay.c
OBJ = $(SRC:.c=.o)
DEPS = iface.h ruleparser.h fwdefs.h

TARGET = firewall

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ -lpcap

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o $(TARGET)
