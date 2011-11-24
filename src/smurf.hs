{-----------------------------------------------------------------
 
  (c) 2011 Markus Dittrich 
 
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

module Main where

import Data.List (find)
import Prelude
import System.Environment (getArgs)
import Debug.Trace

import Permissions (FileEntry(..)
                   , get_files_with_suspect_permissions 
                   , get_id_name_map
                   , generate_entry 
                   ) 

import CommandLine (CmdlOpt(..)
                   , CmdlRequest(..)
                   , process_commandline
                   )

import Messages (usage)


-- | couple of definitions
passwordPath :: String
passwordPath = "/etc/passwd" 

groupPath :: String
groupPath    = "/etc/group" 


main :: IO ()
main = 
  getArgs >>= process_commandline 
  >>= \cmdlOpts -> 
  let rootPath = get_root_path cmdlOpts 
      scanType = get_scan_type cmdlOpts in
  case scanType of
    BadPerms -> scan_for_bad_permissions rootPath
    _        -> usage
  

-- | main driver for scanning the filesystem for files with
-- bad permissions
scan_for_bad_permissions :: String -> IO ()
scan_for_bad_permissions rootPath =
  get_id_name_map passwordPath
  >>= \uidMap -> get_id_name_map groupPath 
  >>= \gidMap -> get_files_with_suspect_permissions rootPath
  >>= \entries -> 
  putStrLn "\nFiles with set UID:"
  >> putStrLn "----------------------------------------"
  >> mapM_ (generate_entry uidMap gidMap) (filter isSuid entries)
  >> putStrLn "\n\nFiles with set GID:"
  >> putStrLn "----------------------------------------"
  >> mapM_ (generate_entry uidMap gidMap) (filter isSgid entries)
  >> putStrLn "\n\nFiles that are group writable"
  >> putStrLn "----------------------------------------"
  >> mapM_ (generate_entry uidMap gidMap) (filter isGroupWrite entries)
  >> putStrLn "\n\nFiles that are world writable"
  >> putStrLn "----------------------------------------"
  >> mapM_ (generate_entry uidMap gidMap) (filter isWorldWrite entries)           

-- | extract the root path from commandline options if present
get_root_path :: [CmdlOpt] -> String
get_root_path opts = 
  case find (\(CmdlOpt x _) -> x == RootPath) opts of
    Nothing -> "/"
    Just a  -> let (CmdlOpt _ newPath) = a in
                 newPath



-- | data type to keep track of what kind of scan we'd like
-- to do
data ScanType = None | BadPerms
                       
                       

-- | extract the type of scan mode from the commandline 
get_scan_type :: [CmdlOpt] -> ScanType
get_scan_type opts = 
  case find (\(CmdlOpt x _) -> x == ScanMode ) opts of
    Nothing -> None
    Just a  -> let (CmdlOpt _ scanType) = a in
                case scanType of
                  "BadPerms" -> BadPerms
                  _          -> None
