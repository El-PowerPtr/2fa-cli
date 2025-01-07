module Crypt.SHA1 where

import Data.Bits
import Data.Word
import qualified Data.ByteString as BS

hexPair :: Word8 -> [Word8]
hexPair x = [(x .>>. 4) .&. 0b11110000, x .&. 0b00001111]

padding :: [Word8] -> [Word8]
padding msg = let l = length msg 
                        in if l < 64
                            then msg ++ [0b10000000] ++ replicate (61 - l) (toEnum 0) ++ toWord8List (toEnum $ l * 8)
                            else msg

toWord8List :: Word32 -> [Word8]
toWord8List number =  map (\x -> toEnum $ ((0b11111111 .>>. x) .&. fromEnum number) .>>. x) [24,16..0]

fromWord8List :: [Word8] -> Word32
fromWord8List numbers = toEnum $ sum $ zipWith (\number place -> fromEnum number .<<. place) numbers [28,24..0]

sum32 :: Word32 -> Word32 -> Word32
sum32 a b = toEnum $ (fromEnum a + fromEnum b) `mod` 0x100000000 
        
h0 :: Word32
h0 = 0x67452301
h1 :: Word32
h1 = 0xEFCDAB89
h2 :: Word32
h2 = 0x98BADCFE
h3 :: Word32
h3 = 0x10325476
h4 :: Word32
h4 = 0xC3D2E1F0
mask :: Word32
mask = 0x0000000F

constant :: Int -> Word32
constant 0 = 0x5A827999         
constant 1 = 0x6ED9EBA1         
constant 2 = 0x8F1BBCDC         
constant 3 = 0xCA62C1D6         
constant _ = error "only 80 rounds"

round :: Int -> Word32 -> Word32 -> Word32 -> Word32 
round 0 b' c' d' = (b' .&. c') .|. (complement b' .&. d')         
round 1 b' c' d' = b' .^. c' .^. d'                        
round 2 b' c' d' = (b' .&. c') .|. (b' .&. d') .|. (c' .&. d')  
round 3 b' c' d' = b' .^. c' .^. d'
round _ _ _ _ = error "only 80 rounds"

sha1Encoding :: BS.ByteString -> [[Word8]]
sha1Encoding = chunks 
    where 
        chunks m
            | BS.null m = []
            | otherwise = let (l, r) = BS.splitAt 64 m
                            in padding (BS.unpack l) : chunks r

