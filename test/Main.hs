module Main (main) where

import CSV

main :: IO ()
main =  readFile "ejemplo.csv" >>= mapM_ print . parseCSV
