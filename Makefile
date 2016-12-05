INCLUDEDIR:=include
LIBS:=

DEFINES:=-D_REENTRANT
CFLAGS:=-g -O2 -Wall
LDFLAGS=:
CC:=gcc
AS:=as
PROG:=ti
INCLUDES:= -I${INCLUDEDIR}
DEPDIR:=deps

SOURCES:=$(wildcard *.c)
OBJECTS:=${SOURCES:.c=.o}
ASM_SOURCE:=syscall.S
ASM_OBJECT:=${ASM_SOURCE:.S=.o}

PREFIX=/usr/local/ulogd
DESTDIR=

.PHONY: clean install check depend

all: check depend ${PROG}

$(PROG): ${OBJECTS} ${ASM_OBJECT}
	${CC} ${CFLAGS} ${LIBS} $^ -o $@ 


${ASM_OBJECT}:	${ASM_SOURCE}
	${CC} ${CFLAGS} ${INCLUDES} ${DEFINES} $^ -c 

${OBJECTS}: ${SOURCES} 
	${CC} ${CFLAGS} ${INCLUDES} ${DEFINES} $^ -c 



depend:
	${CC} ${INCLUDES} -M -MM -MD ${SOURCES}
	@mv *.d ${DEPDIR}

clean:
	rm -f ${DEPDIR}/*.d
	rm -f *.o ${PROG}

check:
	@if [ "`uname`" != "Linux" ]; then \
                echo "Sorry, linux required, not `uname`"; \
                exit 1; \
        fi
#tpt:	tpt.c a.S
#	gcc tpt.c -c
#	as -as --gstabs a.S -o a.o
#	gcc a.o tpt.o -o tpt

install:
	@mkdir -p ${DESTDIR}/${PREFIX}/sbin
	install -m 750 ulogd ${DESTDIR}/${PREFIX}/sbin

-include ${DEPDIR}/*.d


