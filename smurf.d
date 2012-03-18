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
import scanner;


immutable __version__ = "0.0.1";

/++
    main entry point
 +/
void main(string[] args) {

  /* set up some defaults */
  string rootPath = "/";
  string executableCheckPaths = "/usr/share/doc:/usr/include:/var";
  string excludePaths; 
  bool scanPermissions = false;
  bool scanExecutables = false;
  bool help = false;
  bool versionInfo = false;

  getopt(
      args,
      std.getopt.config.passThrough,
      "permission_scan|p", &scanPermissions,
      "executable_scan|e", &scanExecutables,
      "scan_root|r", &rootPath,
      "executable_paths|x", &executableCheckPaths,
      "exclude_paths|l", &excludePaths,
      "help|h", &help,
      "version|v", &versionInfo
  );

  /* no valid options - show usage */
  if (!scanPermissions && !scanExecutables && !help && !versionInfo) {
    usage();
    exit(1);
  }
 
  /* pick requested selection */
  if (scanPermissions) {
    DirEntry[][string] vulLists = check_files(rootPath, excludePaths, 
        &handle_permissions);
    print_vulnerable_files(vulLists);

  } else if (scanExecutables) {
    DirEntry[][string] execList = check_files(executableCheckPaths, 
        excludePaths, &handle_executables);
    print_executable_files(execList);

  } else if (help) {
    usage();

  } else if (versionInfo) {
    writeln("This is smurf version ", __version__);
  }

  exit(0);
}


