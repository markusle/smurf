# sime makefile

build:
	dmd -w -release -inline -c -O time_string.d
	dmd -w -release -inline -O smurf.d time_string.o


devel:
	dmd -w -wi smurf.d


.PHONY:  clean

clean:
	rm -f *.o smurf
