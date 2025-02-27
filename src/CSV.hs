module CSV where

import Data.Char

parseCSV :: String -> [[String]]
parseCSV = map separateValues . lines

separateValues :: String -> [String]
separateValues = separateValues' []
    where
        separateValues' xs [] = xs
        separateValues' xs ws = case span (/= ',') ws of
          ([], w) -> separateValues' (xs <> [""]) (tail w)
          (x, ",") -> xs <> ["", trim x]
          (x, []) ->  xs <> [trim x]
          (x, w) -> separateValues'  (xs <> [trim x]) (tail w)

trim :: String -> String
trim = trim' . trim' -- I copypasted it from Stack Overflow XDDDDD
trim' = reverse . dropWhile isSpace


