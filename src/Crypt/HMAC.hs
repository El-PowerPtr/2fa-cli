module Crypt.HMAC where

import Data.Bits
import Data.ByteString qualified as BS

hmac :: (BS.ByteString -> BS.ByteString) -> Int -> BS.ByteString -> BS.ByteString -> BS.ByteString
hmac hf size key text = hf $ (k `xorBS` opad) <> hf ((k `xorBS` ipad) <> text)
  where
    xorBS a b = BS.pack $ BS.zipWith (.^.) a b
    k = key <> BS.replicate size (toEnum 0)
    ipad = BS.replicate size $ toEnum 0x36
    opad = BS.replicate size $ toEnum 0x5C
