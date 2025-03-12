module Crypt.SHA1 where

import Data.Bits
import Control.Monad
import Data.Word
import qualified Data.ByteString as BS

hexPair :: Word8 -> [Word8]
hexPair x = [x .>>. 4, x .&. 0b00001111]

padding :: [Word8] -> Int -> [Word8]
padding msg len = padding' (length msg)
        where
            len8 = len * 8
            highBound = len8 .&. 0x7FFFFFFF00000000
            lowBound = len8 .&. 0x00000000FFFFFFFF
            padding' 64 = msg
            padding' size
                | size > 55 = msg ++ [0b10000000] ++ replicate (63 - size) (toEnum 0)
                                ++ replicate 56 (toEnum 0) 
                                ++ toWord8List (toEnum highBound) ++ toWord8List (toEnum lowBound)
                | otherwise = msg ++ [0b10000000] ++ replicate (55 - size) (toEnum 0)
                                ++ toWord8List (toEnum highBound) ++ toWord8List (toEnum lowBound)

toWord8List :: Word32 -> [Word8]
toWord8List number =  map (\x -> toEnum $ ((0b11111111 .<<. x) .&. fromEnum number) .>>. x) [24,16..0]

fromWord8List :: [Word8] -> Word32
fromWord8List numbers = toEnum $ sum $ zipWith 
                            (\number place -> fromEnum number .<<. place) numbers [24,16..0]

(|+|) :: Word32 -> Word32 -> Word32
(|+|) a b = toEnum $ (fromEnum a + fromEnum b) `mod` 0x100000000

initialWords :: [Word32]
initialWords = [0xC3D2E1F0,0x10325476,0x98BADCFE,0xEFCDAB89,0x67452301]

mask :: Word32
mask = 0x0000000F

constant :: Int -> Word32
constant 0 = 0x5A827999
constant 1 = 0x6ED9EBA1
constant 2 = 0x8F1BBCDC
constant 3 = 0xCA62C1D6
constant _ = error "only 80 sha1Rounds"

sha1Round :: Int -> Word32 -> Word32 -> Word32 -> Word32
sha1Round 0 b c d = (b .&. c) .|. (complement b .&. d)
sha1Round 1 b c d = b .^. c .^. d
sha1Round 2 b c d = (b .&. c) .|. (b .&. d) .|. (c .&. d)
sha1Round 3 b c d = b .^. c .^. d
sha1Round _ _ _ _ = error "only 80 rounds"

chunks :: BS.ByteString -> [[Word8]]
chunks msg = cut 64 $ chunks' msg $ BS.length msg
    where
        chunks' m l
            | BS.null m = []
            | otherwise = let (lft, rgt) = BS.splitAt 64 m
                            in padding (BS.unpack lft) l ++ chunks' rgt l

cut :: Int -> [a] -> [[a]]
cut _    []  = []
cut size lst = let (l, r) = splitAt size lst
                in l : cut size r

sha1 :: [Word32] -> [Word32]
sha1 msg = let w = wrds msg (drop 2 msg) (drop 7 msg) (drop 13 msg) (drop 15 msg) 16
            in  processMsg initialWords w 0
    where
        wrds :: [Word32] -> [Word32] -> [Word32] -> [Word32] -> [Word32] -> Int -> [Word32]
        wrds result _ _ _ _ 80 = result
        wrds _     [] _ _ _ _ = error $ "empty list: a " ++ show msg
        wrds _     _ [] _ _ _ = error $ "empty list: b " ++ show msg
        wrds _     _ _ [] _ _ = error $ "empty list: c " ++ show msg
        wrds _     _ _ _ [] _ = error $ "empty list: d " ++ show msg
        wrds result (a:as) (b:bs) (c:cs) (d:ds) t = let w = [(a .^. b .^. c .^. d) `rotateL` 1] 
                                                        in wrds (result ++ w) (as ++ w) 
                                                            (bs ++ w) (cs ++ w) (ds ++ w) (t + 1)
        processMsg :: [Word32] -> [Word32] -> Int -> [Word32] 
        processMsg result _ 80 = zipWith (|+|) result initialWords
        processMsg [a,b,c,d,e] (w:ws) time = let t = time `mod` 20
                                                 temp =  (a `rotateL` 5) |+|
                                                    sha1Round t b c d |+| e |+| w |+| constant t
                                                 rb = b `rotateL` 30
                                            in processMsg [temp,a,rb,c,d] ws (time + 1)

msgDiggest :: [[Word8]] -> [Word32]
msgDiggest msg = join $ map (sha1 . map fromWord8List . cut 4) msg

sha1Encoding :: BS.ByteString -> BS.ByteString
sha1Encoding = BS.pack . join . map toWord8List . msgDiggest . chunks 
