# sime makefile

SOURCES=smurf.d scanner.d helpers.d
OBJECTS=$(SOURCES:.d=.o)
EXECUTABLE=smurf

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS) $(SOURCES)
	dmd $(OBJECTS)

%.o: %.d
	dmd -w -release -inline -c -O $<

devel:
	dmd -w -wi smurf.d


.PHONY:  clean

clean:
	rm -f *.o smurf
