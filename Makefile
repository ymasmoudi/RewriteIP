TARGET ?= $(notdir $(realpath .))

CFLAGS +=-Wall -O2

ifeq ($(STATIC),y)
LDFLAGS += 
else
LDFLAGS +=-lpcap
endif

TARGET = rewrite-ip

SRC ?= $(wildcard *.c)
OBJS := $(SRC:%.c=%.o)

all: $(TARGET)

init: $(DEPS)
	$(foreach DIR, $(DEPS), $(MAKE) -C $(DIR); )
	
$(TARGET): init $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) $(USER_LDFLAGS) $(LDFLAGS) -o $@

clean:
	rm -f *.o $(TARGET) $(OBJS)
