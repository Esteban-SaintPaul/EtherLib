include lib.conf

CC=arm-none-eabi-gcc
AR=arm-none-eabi-ar

LIB=eth
###################################################

# Check for valid float argument
ifneq ($(FLOAT_TYPE), hard)
ifneq ($(FLOAT_TYPE), soft)
#override FLOAT_TYPE = hard
override FLOAT_TYPE = soft
endif
endif

###################################################

vpath %.c src

CFLAGS  = -g -O0 -Wall
CFLAGS += -mlittle-endian -mthumb -mthumb-interwork -mcpu=cortex-m4

ifeq ($(FLOAT_TYPE), hard)
CFLAGS += -fsingle-precision-constant -Wdouble-promotion
CFLAGS += -mfpu=fpv4-sp-d16 -mfloat-abi=hard
#CFLAGS += -mfpu=fpv4-sp-d16 -mfloat-abi=softfp
else
CFLAGS += -msoft-float
endif

CFLAGS += -ffreestanding -nostdlib
CFLAGS += -Iinc -I../lib/inc -I../lib/inc/core

#SRCS  = stm32f4_discovery.c

OBJS = $(SRCS:.c=.o)

.PHONY: lib$(LIB).a

all: lib$(LIB).a

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $^

lib$(LIB).a: $(OBJS)
	$(AR) -r $@ $(OBJS)

clean:
	rm -f *.o lib$(LIB).a
