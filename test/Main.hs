module Main (main) where

import Crypt.SHA1
import Text.Printf

main :: IO ()
main = mapM_ (printf "%x") $ padding [ 0b01100001, 0b01100010, 0b01100011, 0b01100100, 0b01100101 ] 
