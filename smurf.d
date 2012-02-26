/********************************************************************
 *
 * smurf is a filesystem vulnerability checker
 *
 * (C) Markus Dittrich 2012, released under GPLv3
 *
 ********************************************************************/


import std.array;
import std.stdio;
import std.file;
import std.exception;
import std.c.linux.linux;

immutable root = "/"; 

void main() {

  DirEntry[][string] vulLists = check_for_vulnerable_files(root);
  print_vulnerable_files(vulLists);
}




/* 
 * pretty printer for outputting vulnerable file info
 */
void print_vulnerable_files(in DirEntry[][string] info) {

  
  writeln("\n************** file with suid *********************");
  foreach (item; info["suid"]) {
    writeln(item.name);
  }

  writeln("\n************** files with sgid ********************");
  foreach (item; info["sgid"]) {
    writeln(item.name);
  }

  writeln("\n************** group writable files ***************");
  foreach (item; info["groupWritable"]) {
    writeln(item.name);
  }

  writeln("\n************** world writable files ***************");
  foreach (item; info["worldWritable"]) {
    writeln(item.name);
  }
}



/*
 * this function checks for vulnerable files (files that 
 * are suid, sgid, groupWritable, worldWritable)
 */
DirEntry[][string] check_for_vulnerable_files(in string root) {

  string[] dirs = [root];
  DirEntry[] suid;
  DirEntry[] sgid;
  DirEntry[] groupWritable;
  DirEntry[] worldWritable;

  DirIterator dirIter;
  while (dirs.length) {

    // retrieve next dir
    string dirName = dirs.back();
    dirs.popBack();

    // check if we can access it
    try {
      dirIter = dirEntries(dirName, SpanMode.shallow, true);
    } catch (Exception ex) {
      continue;
    }

    // read content
    foreach(DirEntry e; dirIter) {

      try {
        uint attr = e.linkAttributes;
        if (attrIsSymlink(attr)) {
          continue;
        } else if (attrIsFile(attr)) {

          if (attr & S_ISUID) {
            suid ~= e;
          } 
          
          if (attr & S_ISGID) {
            sgid ~= e;
          } 
          
          if (attr & S_IWGRP) {
            groupWritable ~= e;
          } 
          
          if (attr & S_IWOTH) {
            worldWritable ~= e;
          }
        } else if (attrIsDir(attr)) {
          string name = e.name;
          if (name == "/proc" || name == "/sys") {
            continue;
          }
          dirs ~= name;
        }
      } catch (Exception ex) {
        continue;
      }
    }
  }

  // collect results in a map
  DirEntry[][string] entryMap = [ "suid" : suid,
                                  "sgid" : sgid,
                                  "groupWritable" : groupWritable,
                                  "worldWritable" : worldWritable];
  return entryMap; 
}

