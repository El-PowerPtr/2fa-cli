module Crypt.HOTP where

import Crypt.HMAC (hmac)
import Crypt.SHA1 (fromWord8List, sha1Encoding)
import Data.Bits
import Data.ByteString as BS
import Data.Word

hmacSha1 :: BS.ByteString -> BS.ByteString -> BS.ByteString
hmacSha1 = hmac sha1Encoding 64

hotp :: BS.ByteString -> BS.ByteString -> Int -> Word32
hotp key text = trunc (hmacSha1 key text)

trunc :: BS.ByteString -> Int -> Word32
trunc str digits = dynTrunc' (BS.take 20 str) `mod` toEnum (10 ^ digits)
  where
    dynTrunc' :: BS.ByteString -> Word32
    dynTrunc' s =
      let offset = 0b00001111 .&. index s 19
          bits = BS.take 4 $ BS.drop (fromEnum offset) s
       in 2147483647 .&. fromWord8List (BS.unpack bits)
