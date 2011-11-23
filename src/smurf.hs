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

import Permissions (FileEntry(..)
                   , get_files_with_suspect_permissions 
                   , get_id_name_map
                   , generate_entry 
                   ) 


-- | couple of definitions
root :: String
root         = "/"            

passwordPath :: String
passwordPath = "/etc/passwd" 

groupPath :: String
groupPath    = "/etc/group" 


main :: IO ()
main = 
  get_id_name_map passwordPath
  >>= \uidMap -> get_id_name_map groupPath 
  >>= \gidMap -> get_files_with_suspect_permissions root
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

