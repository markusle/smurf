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

import Char(ord)
import Control.Monad (forM, liftM)
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
import Word (Word8)
--import Debug.Trace



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



-- | top level wrapper for permission checking functionality
get_files_with_suspect_permissions :: FilePath -> IO [FileEntry]
get_files_with_suspect_permissions rootPath = walk_path rootPath [] 


  
-- | recursively walk down the file tree starting at root
walk_path :: FilePath -> [FileEntry] -> IO [FileEntry]
walk_path rootPath acc =
  (try :: IO [FilePath] -> IO (Either SomeException [FilePath])) 
  (getDirectoryContents rootPath)
  >>= \result -> 
  case result of
    Left _        -> return acc
    Right content ->
      let filteredContent = filter (`notElem` [".", ".."]) content in
      liftM concat $ forM filteredContent $
      \name -> let newPath = rootPath </> name in 
      (try :: IO FileStatus -> IO (Either SomeException FileStatus))
      (getSymbolicLinkStatus newPath)
      >>= \status ->
      case status of
        Left _  -> return acc
        Right s -> if (isSymbolicLink s  
                       || isCharacterDevice s 
                       || isBlockDevice s
                       || isSocket s
                       || isNamedPipe s
                       || is_sys_entry newPath
                       || is_proc_entry newPath
                      )
         then return acc
         else 
           if isDirectory s
              then walk_path newPath acc
              else 
                (get_file_mode newPath)
                >>= \theFileMode -> 
                let entry = (uncurry get_file_entry $ theFileMode) in
                if (isSuid entry || isSgid entry || isWorldWrite entry 
                    || isGroupWrite entry)
                   then return [entry]
                   else return []
                          


-- | checks if path is part of /sys
is_sys_entry :: FilePath -> Bool
is_sys_entry = isPrefixOf "/sys/"



-- | checks if path is part of /proc
is_proc_entry :: FilePath -> Bool
is_proc_entry = isPrefixOf "/proc/"



get_file_mode :: FilePath -> IO (FilePath, FileStatus)
get_file_mode name = 
  getFileStatus name
  >>= \status -> return (name, status)



get_file_entry :: FilePath -> FileStatus -> FileEntry
get_file_entry name status = 
  let 
    theMode    = fileMode status 
    worldWrite = (theMode .&. otherWriteMode) /= 0
    groupWrite = (theMode .&. groupWriteMode) /= 0
    suid       = (theMode .&. setUserIDMode) /= 0
    sgid       = (theMode .&. setGroupIDMode) /= 0
    theUid     = fromIntegral $ fileOwner status
    theGid     = fromIntegral $ fileGroup status
  in
   FileEntry name theUid theGid theMode suid sgid worldWrite groupWrite
   

   
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
