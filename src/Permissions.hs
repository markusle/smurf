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

module Permissions ( FileEntry(..)
                   , get_files_with_suspect_permissions 
                   , get_id_name_map
                   , generate_entry
                   ) where

import Data.Char(ord)
import Control.Exception (try, SomeException)
import Data.Bits
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.Char8 as BC
import Data.List (isPrefixOf)
import Data.Map (Map, fromList, (!))
import System.Posix.Files
import System.Posix.Types
import System.Directory (getDirectoryContents)
import System.FilePath ((</>))
import Text.Printf (printf)
import Data.Word (Word8)
import Debug.Trace
import Prelude



-- | data structure to keep track of files
data FileEntry = FileEntry { path :: String
                           , uid  :: Int 
                           , gid  :: Int
                           , mode :: FileMode
                           , isSuid :: Bool
                           , isSgid :: Bool
                           , isWorldWrite :: Bool
                           , isGroupWrite :: Bool
                           }
                 deriving (Show)



-- | data classifier for file entries
data EntryType = File | Directory | None



-- | recursively walk down the file tree starting at root
get_files_with_suspect_permissions :: FilePath -> IO [FileEntry]
get_files_with_suspect_permissions rootPath =
  walk_path [rootPath] []
  

-- | main path walking routine
walk_path :: [FilePath] -> [FileEntry] -> IO [FileEntry]
walk_path [] acc = return acc
walk_path (thePath:xs) acc = 

  -- we have to be careful since we might encouter files we can't
  -- read for whatever reason (permissions, etc.)
  (try :: IO FileStatus -> IO (Either SomeException FileStatus))
  (getSymbolicLinkStatus thePath)
  >>= \status ->
  case status of
    Left _ -> walk_path xs acc
    Right s -> case get_entry_type s of
       File      -> update_file_status 
                    >>= \newAcc-> walk_path xs (newAcc ++ acc)
       Directory -> update_paths 
                    >>= \newPaths -> walk_path (newPaths ++ xs) acc
       None      -> walk_path xs acc


  where
    update_file_status = getFileStatus thePath 
      >>= \status -> 
      case check_file_entry thePath status of
        Just x -> return [x] 
        Nothing -> return []


    update_paths = 
      (try :: IO [FilePath] -> IO (Either SomeException [FilePath])) 
      (getDirectoryContents thePath)
        >>= \result -> 
        case result of
          Left _ -> return [] 
          Right content ->
            let filteredContent = filter (`notElem` [".", ".."]) content 
                newPaths        = map (\x -> thePath </> x) filteredContent
            in
            return newPaths


    get_entry_type s 
      | (isRegularFile s) 
        && (not_sys_entry thePath) 
        && (not_proc_entry thePath)  = File
      | isDirectory s                = Directory
      | otherwise                    = None



-- | checks if path is part of /sys
not_sys_entry :: FilePath -> Bool
not_sys_entry = not . isPrefixOf "/sys/"
           


-- | checks if path is part of /proc
not_proc_entry :: FilePath -> Bool
not_proc_entry = not . isPrefixOf "/proc/"
            


-- | pick out entries with properties we are looking
-- for (suid, sgid, ....)
check_file_entry :: FilePath -> FileStatus -> Maybe FileEntry
check_file_entry name status = 
  let 
    theMode    = fileMode status 
    worldWrite = (theMode .&. otherWriteMode) /= 0
    groupWrite = (theMode .&. groupWriteMode) /= 0
    suid       = (theMode .&. setUserIDMode) /= 0
    sgid       = (theMode .&. setGroupIDMode) /= 0
    theUid     = fromIntegral $ fileOwner status
    theGid     = fromIntegral $ fileGroup status
  in
   if (suid || sgid || worldWrite || groupWrite)
      then Just (FileEntry name theUid theGid theMode suid sgid worldWrite groupWrite)
      else Nothing
      


-- | generate a pretty printed line of output for each entry 
generate_entry :: Map Int String -> Map Int String -> FileEntry -> IO ()
generate_entry uidMap gidMap entry = 
  let
    item    = mode entry
    modes   = map (\x -> (item .&. x) /= 0) modeFuncs
    perms   = map (\(x,y) -> if x then y else '-') $ zip modes convert
    suid    = (item .&. setUserIDMode) /= 0
    guid    = (item .&. setGroupIDMode) /= 0
    convert = pick_converter suid guid
    uname   = (!) uidMap (uid entry)
    gname   = (!) gidMap (gid entry)
  in
   printf "%s   %-6s %-6s %s\n" perms uname gname (path entry)
   

  where
    modeFuncs = [ownerReadMode, ownerWriteMode, ownerExecuteMode,
                 groupReadMode, groupWriteMode, groupExecuteMode,
                 otherReadMode, otherWriteMode, otherExecuteMode]
    convert_reg       = ['r', 'w', 'x', 'r', 'w', 'x', 'r', 'w', 'x']
    convert_suid      = ['r', 'w', 's', 'r', 'w', 'x', 'r', 'w', 'x']
    convert_sgid      = ['r', 'w', 'x', 'r', 'w', 's', 'r', 'w', 'x']
    convert_suid_sgid = ['r', 'w', 's', 'r', 'w', 's', 'r', 'w', 'x']
             
    -- based on the discovered modes and suid/sgid status return the
    -- proper converterinto a standard unix rwx type string
    pick_converter suid sgid = 
      if not suid && not sgid 
      then convert_reg
      else if suid && sgid
           then convert_suid_sgid
           else if sgid
                then convert_sgid
                else convert_suid
                           


-- | this function returns a map from ids to usernames 
-- by reading /etc/passwd or /etc/group
get_id_name_map :: String -> IO (Map Int String)
get_id_name_map idFile = 
  B.readFile idFile
  >>= \content -> 
  let entries = B.split eol (B.init content) 
      pairs   = map grab_id_name entries 
      idMap  = fromList pairs in
  return idMap

  where
    grab_id_name entry = 
      let items = B.split colon entry 
          theId = read . BC.unpack $ items !! 2 :: Int
          name  = BC.unpack $ head items
      in
      (theId, name)
      
      
      
-- | convert char into Word8
char_to_Word8 :: Char -> Word8
char_to_Word8 = fromIntegral . ord


      
-- | end of line character      
eol :: Word8
eol = char_to_Word8 '\n'
      


-- | colon character
colon :: Word8
colon = char_to_Word8 ':'
