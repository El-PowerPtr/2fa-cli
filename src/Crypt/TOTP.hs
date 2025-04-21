module Crypt.TOTP where

import Crypt.HOTP (hotp)
import Data.ByteString as BS
import Data.Time.Clock.System
import Data.Word

totp :: Int -> Int -> BS.ByteString -> SystemTime -> Word32
totp steps digits token time = hotp token (systemSeconds time `div` fromIntegral steps) digits

totpDefault :: BS.ByteString -> SystemTime -> Word32
totpDefault = totp 30 6
