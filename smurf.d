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
import std.format : formattedWrite;
import std.datetime;
import std.conv : to;
import std.string : toStringz;
import std.exception;
import posix = std.c.linux.linux;

import time_string : time_to_string;

/* stuff for parsing /etc/group */
public import core.sys.posix.sys.types;

struct group {
  char* gr_name;
  char* gr_passwd;
  gid_t gr_gid;
  char** gr_mem;
};

extern (C) group* getgrgid(gid_t);


immutable root = "/"; 

void main() {

  DirEntry[][string] vulLists = check_for_vulnerable_files(root);
  print_vulnerable_files(vulLists);
}


/++ 
    pretty printer for outputting vulnerable file info
 +/
void print_vulnerable_files(in DirEntry[][string] info) {

  
  writeln("\n************** file with suid *********************");
  foreach (item; info["suid"]) {
    pretty_print_file_info(item);
  }

  writeln("\n************** files with sgid ********************");
  foreach (item; info["sgid"]) {
    pretty_print_file_info(item);
  }

  writeln("\n************** group writable files ***************");
  foreach (item; info["groupWritable"]) {
    pretty_print_file_info(item);
  }

  writeln("\n************** world writable files ***************");
  foreach (item; info["worldWritable"]) {
    pretty_print_file_info(item);
  }
}


/++
    print file info in ls -la format
 +/
void pretty_print_file_info(DirEntry fileInfo) {

  uint attr = fileInfo.attributes;

  /* extract file attributes */
  char type = (attr & posix.S_IFDIR) ? 'd' : '-';    // we kept only files and dirs
  char own_r = (attr & posix.S_IRUSR) ? 'r' : '-';
  char own_w = (attr & posix.S_IWUSR) ? 'w' : '-';
  char own_x = (attr & posix.S_ISUID) ? 's' : 
               ((attr & posix.S_IXUSR) ? 'x' : '-');
  char grp_r = (attr & posix.S_IRGRP) ? 'r' : '-';
  char grp_w = (attr & posix.S_IWGRP) ? 'w' : '-';
  char grp_x = (attr & posix.S_ISGID) ? 's' : 
               ((attr & posix.S_IXGRP) ? 'x' : '-');
  char oth_r = (attr & posix.S_IROTH) ? 'r' : '-';
  char oth_w = (attr & posix.S_IWOTH) ? 'w' : '-';
  char oth_x = (attr & posix.S_ISVTX) ? 't' : 
               ((attr & posix.S_IXOTH) ? 'x' : '-'); 

  /* get owner and group */
  struct_stat64 stat = fileInfo.statBuf;
  uint uid = stat.st_uid;
  uint gid = stat.st_gid;

  auto uidEntry = posix.getpwuid(uid);
  string userName;
  if (uidEntry) {
    userName = to!(string)(uidEntry.pw_name);
  }

  auto gidEntry = getgrgid(gid);
  string groupName;
  if (gidEntry) {
    groupName = to!(string)(gidEntry.gr_name);
  }

  /* generate time string */
  string timeString = time_to_string("%m/%d/%y %H:%M:%S", 
                                     fileInfo.timeLastAccessed);

  writefln("%s%s%s%s%s%s%s%s%s%s %s %s  %s  %s", type, own_r, own_w, own_x, 
           grp_r, grp_w, grp_x, oth_r, oth_w, oth_x, userName, groupName, 
           timeString, fileInfo.name);
}



/++
    read /etc/passwd and returns a map with username[uid]
 +/
string[uint] get_password_map(in string filename) {

  string[uint] pwMap;

  auto entry = posix.getpwent();
  while (entry) {
    uint uid = to!(uint)(entry.pw_uid);
    string name = to!(string)(entry.pw_name);
    pwMap[uid] = name;
    entry = posix.getpwent();
  }

  return pwMap;
}


/++
    this function checks for vulnerable files (files that 
    are suid, sgid, groupWritable, worldWritable)
 +/
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
    } catch (FileException ex) {
      continue;
    }

    // read content
    foreach(DirEntry e; dirIter) {

      try {
        uint attr = e.linkAttributes;
        if (attrIsSymlink(attr)) {
          continue;
        } else if (attrIsFile(attr)) {

          if (attr & posix.S_ISUID) {
            suid ~= e;
          } 
          
          if (attr & posix.S_ISGID) {
            sgid ~= e;
          } 
          
          if (attr & posix.S_IWGRP) {
            groupWritable ~= e;
          } 
          
          if (attr & posix.S_IWOTH) {
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

