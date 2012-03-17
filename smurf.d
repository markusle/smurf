/********************************************************************
 *
 * smurf is a filesystem vulnerability checker
 *
 * (C) Markus Dittrich 2012, released under GPLv3
 *
 ********************************************************************/

import permissions;
import std.file: DirEntry;


immutable root = "/"; 

void main() {

  DirEntry[][string] vulLists = check_for_vulnerable_files(root);
  print_vulnerable_files(vulLists);
}


