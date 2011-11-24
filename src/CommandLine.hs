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

module CommandLine ( process_commandline 
                   , CmdlOpt(..)
                   , CmdlRequest(..)
                   ) where


-- imports
--import Data.Word
import Prelude
import System
import System.Console.GetOpt

import Messages (show_version
                , usage
                )


-- | data structure for keeping track of user provided
-- command line options
data CmdlOpt = CmdlOpt {
  cmdlRequest :: CmdlRequest,
  cmdlString  :: String
}


-- | data structure describing all commandline options we know of
data CmdlRequest = RootPath | ScanMode
                   deriving(Eq)


-- | main driver for command line processing
process_commandline :: [String] -> IO [CmdlOpt]
process_commandline args = 

  let 
    (actions, nonOpts, _) = getOpt RequireOrder options args
  in
    foldl (>>=) ( return [] ) actions 



-- | available command line flags
options :: [OptDescr ([CmdlOpt] -> IO [CmdlOpt])]
options = [
  Option ['v'] ["version-info"] (NoArg version_info) 
         "show version information",
  Option ['h'] ["help"] (NoArg help_msg) "show help message",
  Option ['f'] ["find-bad-permissions"] (NoArg find_bad_permissions) 
         "find all vulnerable files under root path",
  Option ['r'] ["root-path"] (ReqArg root_path "ROOT_PATH") 
         "root path for scanning"
 ]



-- | extractor function for version info
version_info :: [CmdlOpt] -> IO [CmdlOpt]
version_info _ =
  do
    show_version
    exitWith ExitSuccess



-- | extractor function for help message
help_msg :: [CmdlOpt] -> IO [CmdlOpt]
help_msg _ =
  do
    usage
    exitWith ExitSuccess



-- | extract the root path
root_path :: String -> [CmdlOpt] -> IO [CmdlOpt]
root_path arg opt = 
  return ( (CmdlOpt {cmdlRequest = RootPath, cmdlString = arg }):opt)



-- | extractor function for a scan for files with bad permissions
find_bad_permissions :: [CmdlOpt] -> IO [CmdlOpt]
find_bad_permissions opt =
  return ( (CmdlOpt {cmdlRequest = ScanMode, cmdlString = "BadPerms"}):opt)
