module Crypt.SHA1 where

import Data.Bits
import Data.Word
import Control.Monad

hexPair :: Word8 -> [Word8]
hexPair x = [(x .>>. 4) .&. 0b11110000, x .&. 0b00001111]

padding :: [Word8] -> [Word8]
padding message = let l = length message 
                        in if l < 64
                            then message ++ [0b10000000] ++ replicate (61 - l) (toEnum 0) ++ toWord8List (toEnum l)
                            else message

toWord8List :: Word32 -> [Word8]
toWord8List number = join $ map (\x -> hexPair $ toEnum $ ((0b11111111 .>>. x) .&. fromEnum number) .>>. x) [24,16..0]

fromWord8List :: [Word8] -> Word32
fromWord8List numbers = toEnum $ sum $ zipWith (\number place -> fromEnum number .<<. place) numbers [28,24..0]

sum32 :: (Integral a, Integral b) => a -> b -> Int
sum32 a b = fromIntegral $ (fromIntegral a + fromIntegral b) `mod` 0x100000000 
        
h0 = 0x67452301
h1 = 0xEFCDAB89
h2 = 0x98BADCFE
h3 = 0x10325476
h4 = 0xC3D2E1F0
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

