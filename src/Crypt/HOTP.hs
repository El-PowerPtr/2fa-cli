module Crypt.HOTP where

import Crypt.HMAC (hmac)
import Crypt.SHA1 (sha1Encoding)
import Data.Bits
import Data.ByteString as BS
import Data.Word

hmacSha1 :: BS.ByteString -> BS.ByteString -> BS.ByteString
hmacSha1 = hmac sha1Encoding 64

hotp :: BS.ByteString -> BS.ByteString -> Int -> Word32
hotp key text digits = trunc $ hmacSha1 key text

trunc :: BS.ByteString -> Int -> Word32
trunc str digits = dynTrunc' (take 20 str) `mod` (10 ^ (digits - 1))
  where
    dynTrunc' s =
      let offset = 0b00001111 .&. (s !! 19)
          bits   = take 4 $ drop (offset - 1) s
      in 2147483647 .&. fromWord8List bits
