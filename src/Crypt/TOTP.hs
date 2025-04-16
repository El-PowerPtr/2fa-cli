module Crypt.TOTP where

import Crypt.HOTP
import Data.ByteString as BS
import Data.Time.Clock.System
import Data.Word

totp :: Int -> BS.ByteString -> BS.ByteString -> IO Word32
totp steps key text = do 
                        time <- getSystemTime
                        return $ hotp key text (fromIntegral (systemSeconds time) `div` steps)

totpDefault :: BS.ByteString -> BS.ByteString -> IO Word32
totpDefault = totp 30
