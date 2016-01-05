# Makefile
# 12/13/2013 jichi
# This file is for Windows only.
# Compile SAFESEH table from the ASM file.
# See: http://stackoverflow.com/questions/19722308/exception-handler-not-called-in-c
# See: http://stackoverflow.com/questions/12019689/custom-seh-handler-with-safeseh
# See: http://msdn.microsoft.com/en-us/library/16aexws6.aspx

BUILDDIR = ../../../build
OBJ = $(BUILDDIR)/safeseh.obj

ML = ml
CFLAGS =

.PHONY: all compile clean

all: compile

compile: $(OBJ)

$(OBJ): safeseh.asm
	$(ML) $(CFLAGS) -Fo $@ -c -safeseh $^

clean:

# EOF
