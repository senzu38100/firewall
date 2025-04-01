CC = gcc
CFLAGS = -Wall -Wextra -g

SRC = entrypoint.c iface.c ruleparser.c
OBJ = $(SRC:.c=.o)
DEPS = iface.h ruleparser.h fwdefs.h

TARGET = firewall

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o $(TARGET)

