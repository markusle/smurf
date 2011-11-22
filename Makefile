all:
	ghc -O2 --make smurf.hs


.PHONY: clean

clean:
	rm -f smurf.hi smurf.o smurf

