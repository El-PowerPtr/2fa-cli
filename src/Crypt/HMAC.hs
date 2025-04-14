module Crypt.HMAC where

import Data.Bits
import Data.ByteString qualified as BS

hmac :: (BS.ByteString -> BS.ByteString) -> Int -> BS.ByteString -> BS.ByteString -> BS.ByteString
hmac hf blockSize key text
  | blockSize == BS.length key = hf $ (k `xorBS` opad) <> hf ((k `xorBS` ipad) <> text)
  | otherwise = hmac hf blockSize (hf key) text
  where
    xorBS a b = BS.pack $ BS.zipWith (.^.) a b
    k = key <> BS.replicate blockSize (toEnum 0)
    ipad = BS.replicate blockSize $ toEnum 0x36
    opad = BS.replicate blockSize $ toEnum 0x5C
