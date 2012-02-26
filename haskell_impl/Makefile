GHC_FLAGS_DEVEL = -Wall -fwarn-tabs -fwarn-incomplete-record-updates -fwarn-monomorphism-restriction -fwarn-implicit-prelude -fno-warn-orphans
GHC_FLAGS_RELEASE = -O3 
GHC = /home/markus/local/bin/ghc
#GHC = /usr/bin/ghc

all:
	$(GHC) $(GHC_FLAGS_DEVEL) -i./src --make src/smurf.hs


build:
	$(GHC) $(GHC_FLAGS_RELEASE) -i./src --make src/smurf.hs


.PHONY: clean

clean:
	rm -f src/*.hi src/*.o src/smurf

