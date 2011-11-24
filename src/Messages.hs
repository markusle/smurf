{-----------------------------------------------------------------
 
  (c) 2011 Markus Dittrich,
 
  This program is free software; you can redistribute it 
  and/or modify it under the terms of the GNU General Public 
  License Version 3 as published by the Free Software Foundation. 
 
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License Version 3 for more details.
 
  You should have received a copy of the GNU General Public 
  License along with this program; if not, write to the Free 
  Software Foundation, Inc., 59 Temple Place - Suite 330, 
  Boston, MA 02111-1307, USA.

--------------------------------------------------------------------}

-- | message routines used in smurf
module Messages ( show_version 
                , usage
                ) where


-- imports
import Prelude


-- | show version info
show_version :: IO ()
show_version = putStrLn "This is smurf v0.0 (c) 2011 Markus Dittrich"



-- | provide brief usage info
usage :: IO ()
usage = putStrLn "Usage: smurf [options] <input file>\n\n\
        \Currently supported options are:\n\n\
        \\t -f --find-bad-permissions \n\
        \\t       scan filesystem for files with bad permissions\n\n\
        \\t -r --root_path <root_path> \n\
        \\t       specify the root path for the scan.\n\n\
        \\t -v --version-info \n\
        \\t       print version info.\n\n\
        \\t -h --help \n\
        \\t       print this help message."
