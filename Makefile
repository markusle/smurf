# sime makefile

build:
	dmd -w -inline -O smurf.d


devel:
	dmd -w -wi smurf.d

