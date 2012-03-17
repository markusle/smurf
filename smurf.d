/********************************************************************
 *
 * smurf is a filesystem vulnerability checker
 *
 * (C) Markus Dittrich 2012, released under GPLv3
 *
 ********************************************************************/


import std.getopt;
import std.stdio;
import std.file: DirEntry;
import std.c.stdlib: exit;

import helpers: usage;
import permissions;


immutable __version__ = "0.0.1";

/++
    main entry point
 +/
void main(string[] args) {

  /* set up some defaults */
  string rootPath = "/";
  string excludePaths; 
  bool scanPermissions = false;
  bool help = false;
  bool versionInfo = false;

  getopt(
      args,
      std.getopt.config.passThrough,
      "permission_scan|p", &scanPermissions,
      "scan_root|r", &rootPath,
      "exclude_paths|e", &excludePaths,
      "help|h", &help,
      "version|v", &versionInfo
  );

  /* no valid options - show usage */
  if (!scanPermissions && !help && !versionInfo) {
    usage();
    exit(1);
  }
 
  /* pick requested selection */
  if (scanPermissions) {
    DirEntry[][string] vulLists = check_for_vulnerable_files(rootPath,
        excludePaths);
    print_vulnerable_files(vulLists);
  } else if (help) {
    usage();
  } else if (versionInfo) {
    writeln("This is sconcho version ", __version__);
  }

  exit(0);
}


