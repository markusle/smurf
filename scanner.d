/********************************************************************
 *
 * smurf is a filesystem vulnerability checker
 *
 * (C) Markus Dittrich 2012, released under GPLv3
 *
 ********************************************************************/

module permissions;

import std.array: split, join, back, popBack;
import std.algorithm: find;
import std.stdio;
import std.file;
import std.format : formattedWrite;
import std.datetime;
import std.conv : to;
import std.string : toStringz;
import std.exception;
import posix = std.c.linux.linux;

import helpers: time_to_string;


/* stuff for parsing /etc/group */
public import core.sys.posix.sys.types;

struct group {
  char* gr_name;
  char* gr_passwd;
  gid_t gr_gid;
  char** gr_mem;
};

extern (C) group* getgrgid(gid_t);


/++
    this handler collects all files that are either
    suid, sgid, groupWritable, or worldWritable)
 +/
void handle_permissions(ref DirEntry[][string] tracker, DirEntry e, 
                        uint attr) {

  if (attr & posix.S_ISUID) {
    tracker["suid"] ~= e;
  } 
    
  if (attr & posix.S_ISGID) {
    tracker["sgid"] ~= e;
  } 
          
  if (attr & posix.S_IWGRP) {
    tracker["groupWritable"] ~= e;
  } 
          
  if (attr & posix.S_IWOTH) {
    tracker["worldWritable"] ~= e;
  }
}



/++
    this handler collects all files that are executable
 +/
void handle_executables(ref DirEntry[][string] tracker, DirEntry e, 
                       uint attr) {

  if (attr & posix.S_IXUSR || attr & posix.S_IXGRP 
      || attr & posix.S_IXOTH ) { 
    tracker["exec"] ~= e;
  } 
}



/++
    this function walks the filesystem starting at root and
    applies handler to each file. handler fills an associative
    array with arrays of DirEntries corresponding to certain
    properties.
 +/
DirEntry[][string] check_files(in string rootDirs,
    in string excludedDirString, 
    void function(ref DirEntry[][string], DirEntry, uint) handler) {

  /* split root path */
  string[] primaryDirs = split(rootDirs,":");

  string[] excludedDirs = split(excludedDirString,":");
  string[] dirs;
  foreach (dir; primaryDirs) {
    if (!has_path(excludedDirs, dir)) {
      dirs ~= dir;
    }
  }

  DirEntry[][string] entryMap;
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
          handler(entryMap, e, attr);

        } else if (attrIsDir(attr)) {
          string name = e.name;
          if (name == "/proc" || name == "/sys" 
              || has_path(excludedDirs, name)) {
            continue;
          }
          dirs ~= name;
        }
      } catch (Exception ex) {
        continue;
      }
    }
  }

  return entryMap; 
}



/++ 
    pretty printer for outputting vulnerable file info
 +/
void print_vulnerable_files(in DirEntry[][string] info) {

  writeln("\n************** files with suid *********************");
  if ("suid" in info) {
    foreach (item; info["suid"]) {
      pretty_print_file_info(item);
    }
  }

  writeln("\n************** files with sgid ********************");
  if ("sgid" in info) {
    foreach (item; info["sgid"]) {
      pretty_print_file_info(item);
    }
  }

  writeln("\n************** group writable files ***************");
  if ("groupWritable" in info) {
    foreach (item; info["groupWritable"]) {
      pretty_print_file_info(item);
    }
  }

  writeln("\n************** world writable files ***************");
  if ("worldWritable" in info) {
    foreach (item; info["worldWritable"]) {
      pretty_print_file_info(item);
    }
  }
}


/++ 
    pretty printer for outputting executable file info
 +/
void print_executable_files(in DirEntry[][string] info) {

  writeln("\n************** executable files *********************");
  if ("exec" in info) {
    foreach (item; info["exec"]) {
      pretty_print_file_info(item);
    }
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
    checks if string needs is contained in paths.
 +/
pure bool has_path(string paths[], string needle) {
  
  foreach(path; paths) {
    if (path == needle) {
      return true;
    }
  }

  return false;
}


