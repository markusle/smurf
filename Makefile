# sime makefile

build:
	dmd -w -inline -c -O time_string.d
	dmd -w -inline -O smurf.d time_string.o


devel:
	dmd -w -wi smurf.d


shared:
	dmd -O -shared -fPIC smurf.d
