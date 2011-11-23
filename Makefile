GHC_FLAGS_DEVEL = -O -Wall -fwarn-tabs -fwarn-incomplete-record-updates -fwarn-monomorphism-restriction -fwarn-implicit-prelude -fno-warn-orphans
GHC_FLAGS_RELEASE = -O2

all:
	ghc $(GHC_FLAGS_DEVEL) -i./src --make src/smurf.hs


build:
	ghc $(GHC_FLAGS_RELEASE) -i./src --make src/smurf.hs


.PHONY: clean

clean:
	rm -f src/*.hi src/*.o src/smurf

