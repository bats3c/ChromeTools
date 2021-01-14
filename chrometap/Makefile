CC_64=x86_64-w64-mingw32-gcc
CC_86=i686-w64-mingw32-gcc

OUTFILE=bin/chrometap

all: build

build:
	$(CC_64) -c src/main.c -o $(OUTFILE).x64.o -masm=intel
	$(CC_86) -c src/main_winapi.c -o $(OUTFILE).x86.o
