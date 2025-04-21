module Crypt.HMAC where

import Data.Bits
import Data.ByteString qualified as BS

hmac :: (BS.ByteString -> BS.ByteString) -> Int -> BS.ByteString -> BS.ByteString -> BS.ByteString
hmac hf blockSize key text
  | blockSize >= BS.length key = hf $ opad <> hf (ipad <> text)
  | otherwise = hmac hf blockSize (hf key) text
  where
    k = key <> BS.replicate (blockSize - BS.length key) 0
    ipad = BS.map (xor 0x36) k
    opad = BS.map (xor 0x5C) k
