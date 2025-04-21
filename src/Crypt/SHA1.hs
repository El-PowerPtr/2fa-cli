{-# OPTIONS_GHC -Wno-incomplete-patterns #-}

module Crypt.SHA1 where

import Data.Bits
import Data.ByteString qualified as BS
import Data.Word

hexPair :: Word8 -> [Word8]
hexPair x = [x .>>. 4, x .&. 0b00001111]

initialWords :: [Word32]
initialWords = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

constant :: Int -> Word32
constant 0 = 0x5A827999
constant 1 = 0x6ED9EBA1
constant 2 = 0x8F1BBCDC
constant 3 = 0xCA62C1D6
constant _ = error "only 80 sha1Rounds"

sha1Round :: Int -> Word32 -> Word32 -> Word32 -> Word32
sha1Round 0 b c d = (b .&. c) .|. ((complement b) .&. d)
sha1Round 1 b c d = b .^. c .^. d
sha1Round 2 b c d = (b .&. c) .|. (b .&. d) .|. (c .&. d)
sha1Round 3 b c d = b .^. c .^. d
sha1Round _ _ _ _ = error "only 80 rounds"

padding :: [Word8] -> Int -> Either ([Word8], [Word8]) [Word8]
padding msg len = case length msg of
  64 -> Right msg
  size ->
    let len8 = len * 8
        highBound = len8 .&. 0x7FFFFFFF00000000
        lowBound = len8 .&. 0x00000000FFFFFFFF
        endPart = (toWord8List . toEnum) =<< [highBound, lowBound]
     in if size >= 56
          then
            Left
              ( msg ++ [0b10000000] ++ replicate (63 - size) (toEnum 0),
                replicate 56 (toEnum 0) ++ endPart
              )
          else Left (msg ++ [0b10000000] ++ replicate (55 - size) (toEnum 0) ++ endPart, [])

(|+|) :: Word32 -> Word32 -> Word32
(|+|) a b = toEnum $ (fromEnum a + fromEnum b) `mod` 0x100000000

chunks :: BS.ByteString -> [[Word8]]
chunks msg = chunks' msg $ BS.length msg
  where
    chunks' m l =
      let (lft, rgt) = BS.splitAt 64 m
       in case padding (BS.unpack lft) l of
            Right x -> x : chunks' rgt l
            Left (x, []) -> [x]
            Left (x, y) -> [x, y]

cut :: Int -> [a] -> [[a]]
cut _ [] = []
cut size lst =
  let (l, r) = splitAt size lst
   in l : cut size r

sha1 :: [Word32] -> [Word32] -> [Word32]
sha1 words5 msg =
  let w = wrds msg (drop 13 msg) (drop 8 msg) (drop 2 msg) msg 16
   in processMsg words5 w 0
  where
    wrds :: [Word32] -> [Word32] -> [Word32] -> [Word32] -> [Word32] -> Int -> [Word32]
    wrds result _ _ _ _ 80 = result
    wrds _ [] _ _ _ _ = error $ "empty list: a " ++ show msg
    wrds _ _ [] _ _ _ = error $ "empty list: b " ++ show msg
    wrds _ _ _ [] _ _ = error $ "empty list: c " ++ show msg
    wrds _ _ _ _ [] _ = error $ "empty list: d " ++ show msg
    wrds result (a : as) (b : bs) (c : cs) (d : ds) t =
      let w = [(a .^. b .^. c .^. d) `rotateL` 1]
       in wrds
            (result ++ w)
            (as ++ w)
            (bs ++ w)
            (cs ++ w)
            (ds ++ w)
            (t + 1)
    processMsg :: [Word32] -> [Word32] -> Int -> [Word32]
    processMsg result _ 80 = zipWith (|+|) result words5
    processMsg [a, b, c, d, e] (w : ws) time =
      let t = time `div` 20
          temp =
            (a `rotateL` 5)
              |+| sha1Round t b c d
              |+| e
              |+| w
              |+| constant t
          rb = b `rotateL` 30
       in processMsg [temp, a, rb, c, d] ws (time + 1)

msgDiggest :: [[Word8]] -> [[Word32]]
msgDiggest = map (map fromWord8List . cut 4)

sha1Encoding :: BS.ByteString -> BS.ByteString
sha1Encoding = BS.pack . concatMap toWord8List . foldl sha1 initialWords . msgDiggest . chunks

wordToDigit :: Word8 -> Word8
wordToDigit x
  | x <= 9 = x + 48
  | otherwise = x + 87

fromString :: String -> BS.ByteString
fromString = BS.pack . map ((toEnum :: Int -> Word8) . fromEnum)

toString :: BS.ByteString -> String
toString = map ((toEnum :: Int -> Char) . fromEnum . wordToDigit) . concatMap hexPair . BS.unpack

toWord8List :: Word32 -> [Word8]
toWord8List number = map (\x -> toEnum $ ((0b11111111 .<<. x) .&. fromEnum number) .>>. x) [24, 16 .. 0]

fromWord8List :: [Word8] -> Word32
fromWord8List numbers =
  toEnum $
    sum $
      zipWith
        (\number place -> fromEnum number .<<. place)
        numbers
        [24, 16 .. 0]
