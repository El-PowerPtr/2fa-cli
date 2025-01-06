module Crypt.SHA1 where

import Data.Bits
import Data.Word
import Control.Monad

hexPair :: Word8 -> [Word8]
hexPair x = [(x .>>. 4) .&. 0b11110000, x .&. 0b00001111]

padding :: [Word8] -> [Word8]
padding message = let l = length message 
                        in if l < 64
                            then message ++ [0b10000000] ++ replicate (61 - l) (toEnum 0) ++ toWord8List l
                            else message

toWord8List :: Int -> [Word8]
toWord8List number = join $ map (\x -> hexPair $ toEnum $ ((0b11111111 .>>. x) .&. number) .>>. x) [24,16..0]

fromWord8List :: [Word8] -> Int
fromWord8List numbers = sum $ zipWith (\number place -> fromEnum number .<<. place) numbers [28,24..0]

sum32 :: Int -> Int -> Int
sum32 a b = (a + b) `mod` 0x100000000 
        
constant :: Int -> [Word8]
constant t 
    |  0 <= t && t <= 19 = toWord8List 0x5A827999         
    | 20 <= t && t <= 39 = toWord8List 0x6ED9EBA1         
    | 40 <= t && t <= 59 = toWord8List 0x8F1BBCDC         
    | 60 <= t && t <= 79 = toWord8List 0xCA62C1D6         
    | otherwise = constant $ t `mod` 80

-- sha1 :: Int -> ByteString -> ByteString
-- sha1 len text = text
--     where 
--       round n b c d  
--         |  0 <= t && t <= 19 = (b .&. c) .|. ((complement b) .&. d)         
--         | 20 <= t && t <= 39 = b .^. c .^. d                        
--         | 40 <= t && t <= 59 = (b .&. c) .|. (b .&. d) .|. (c .&. d)  
--         | 60 <= t && t <= 79 = b .^. c .^. d                        
