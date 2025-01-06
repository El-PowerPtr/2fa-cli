module CSV where

import Data.Char

parseCSV :: String -> [[String]]
parseCSV = map (reverse . separateValues) . lines
  where
    separateValues = separateValues' []
    separateValues' xs [] = xs
    separateValues' xs ws = case span (/= ',') ws of
      ([], w) -> separateValues' ("" : xs) (tail w)
      (x, ",") -> trim x : xs
      (x, []) -> trim x : xs
      (x, w) -> separateValues' (trim x : xs) (tail w)
    trim = trim' . trim' -- I copypasted it from Stack Overflow XDDDDD
    trim' = reverse . dropWhile isSpace
