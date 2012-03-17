/********************************************************************
 *
 * smurf is a filesystem vulnerability checker
 *
 * (C) Markus Dittrich 2012, released under GPLv3
 *
 ********************************************************************/

module helpers;

import std.array : appender, split, join;
import std.stdio;
import std.format : formattedWrite;
import std.datetime;
import std.conv : to;



/++
    Very simplistic strftime ripoff based on SysTime. Currently, the
    following format specifiers are supported:

    %d The day of the month as a decimal number (range 01 to 31).
    %H The hour as a decimal number using a 24-hour clock (range 00 to 23).
    %I The hour as a decimal number using a 12-hour clock (range 01 to 12).
    %m The month as a decimal number (range 01 to 12).
    %M The minute as a decimal number (range 00 to 59).
    %S The second as a decimal number (range 00 to 60).  (The range is up to
       60 to allow for occasional leap seconds.)
    %y The year as a decimal number without a century (range 00 to 99).
    %Y The year as a decimal number including the century.
+/
string time_to_string(in string format, in SysTime time) {

  /* writer helper */
  void write_token(T)(in T value, in string token, ref string[] outString) {
    outString ~= to!(string)(value);
    outString ~= token[1..$];
  }
    
  /* parse format string */
  string[] outString;
  string[] tokens = format.split("%");

  /* take care of potentially empty string in first element 
     courtesy of split */
  if (tokens[0].length == 0) {
    tokens = tokens[1..$];
  }

  foreach (token; tokens) {
    switch(token[0]) {
      case 'd':
        uint day = to!(uint)(time.day);
        write_token(day, token, outString);
        break;
      case 'H':
        auto writer = appender!string();
        uint hour = to!(uint)(time.hour);
        formattedWrite(writer, "%02d", hour);
        write_token(writer.data, token, outString);
        break;
      case 'I':
        auto writer = appender!string();
        uint hour = to!(uint)(time.hour) % 12;
        if (hour == 0) {
          hour = 12;
        }
        formattedWrite(writer, "%02d", hour);
        write_token(writer.data, token, outString);
        break;
      case 'm':
        auto writer = appender!string();
        uint month = to!(uint)(time.month);
        formattedWrite(writer, "%02d", month);
        write_token(writer.data, token, outString);
        break;
     case 'M':
        auto writer = appender!string();
        uint minute = to!(uint)(time.minute);
        formattedWrite(writer, "%02d", minute);
        write_token(writer.data, token, outString);
        break;
     case 'S':
        auto writer = appender!string();
        uint second = to!(uint)(time.second);
        formattedWrite(writer, "%02d", second);
        write_token(writer.data, token, outString);
        break;
      case 'Y':
        uint year = to!(uint)(time.year);
        write_token(year, token, outString);
        break;
      case 'y':
        uint year = to!(uint)(time.year) % 100;
        write_token(year, token, outString);
        break;
      default:
        outString ~= token;
        break;
    } 
  }

  return (join(outString));
}


/++
    prints out usage information
 +/

void usage() {

  writeln("usage: ./smurf [options]");
  writeln();
  writeln("-p, --permission_scan");
  writeln("\tscans the filesystem for suid and guid binaries as well");
  writeln("\tas group and world writable files. The root of the scan");
  writeln("\tcan be set with the -r flag.");
  writeln();
  writeln("-r, --scan_root");
  writeln("\tsets the root of any filesystem scan, e.g. requested via -p.");
  writeln("\tThe default is to start at '/'.");
  writeln();
  writeln("-e, --exclude_paths");
  writeln("\tPaths in this list are excluded in any filesystem scans");
  writeln("\tand should be given as a colon separated list, i.e.");
  writeln("\t\"path1:path2:path3\"");
  writeln();
  writeln("-h, --help");
  writeln("\tShows this list of available options.");
  writeln();
  writeln("-v, --version");
  writeln("\tShow version information");
  writeln();
}





