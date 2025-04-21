module Crypt.HOTP where

import Crypt.HMAC (hmac)
import Crypt.SHA1 (fromWord8List, sha1Encoding)
import Data.Bits
import Data.ByteString qualified as BS
import Data.Int (Int64)
import Data.Word (Word32, Word8)

hmacSha1 :: BS.ByteString -> BS.ByteString -> BS.ByteString
hmacSha1 = hmac sha1Encoding 64

hotp :: BS.ByteString -> Int64 -> Int -> Word32
hotp key counter =
  let bsCounter = BS.pack $ fromInt64 counter
   in trunc (hmacSha1 key bsCounter)

trunc :: BS.ByteString -> Int -> Word32
trunc str digits = dynTrunc' (BS.take 20 str) `mod` toEnum (10 ^ digits)
  where
    dynTrunc' :: BS.ByteString -> Word32
    dynTrunc' s =
      let offset = 0b00001111 .&. BS.index s 19
          bits = BS.take 4 $ BS.drop (fromEnum offset) s
       in 2147483647 .&. fromWord8List (BS.unpack bits)

fromInt64 :: Int64 -> [Word8]
fromInt64 number = map (toEnum . fromIntegral . (.&. 0xFF) . shiftR number) [56, 48 .. 0]
