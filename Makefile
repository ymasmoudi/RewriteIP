TARGET ?= $(notdir $(realpath .))

CFLAGS +=-Wall -O1

ifeq ($(STATIC),y)
LDFLAGS += 
else
LDFLAGS +=-lpcap
endif

ifeq ($(DEBUG),y)
CFLAGS +=-g -D_DEBUG
endif 

TARGET = rewrite-ip
#$(warning Building $(TARGET))

SRC ?= $(wildcard *.c)
OBJS := $(SRC:%.c=%.o)

all: $(TARGET)

init: $(DEPS)
	$(foreach DIR, $(DEPS), $(MAKE) -C $(DIR); )
	
$(TARGET): init $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) $(USER_LDFLAGS) $(LDFLAGS) -o $@

clean:
	rm -f *.o $(TARGET) $(OBJS)
