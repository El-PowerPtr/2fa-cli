module Main (main) where

-- import qualified Data.ByteString as BS
import Crypt.SHA1
-- import Data.Char
import Test.Hspec
import Data.Word
import CSV 


main :: IO ()
main = hspec $ do 
                describe "CSV" $ do
                    it "normal use case" $ do 
                        separateValues "hola , mundo, mundial" `shouldBe` ["hola", "mundo", "mundial"]
                    it "processing a row with all blank spaces" $ do 
                        separateValues ", , , , , " `shouldBe` ["","","","","",""]
                    it "processing a row with a blank space in the middle" $ do 
                        separateValues "hola , , mundial"  `shouldBe` ["hola","","mundial"]
                    it "processing a row with a blank space in the left" $ do 
                        separateValues ", hola , mundial"  `shouldBe` ["","hola","mundial"]
                    it "processing a row with a blank space in the right" $ do 
                        separateValues "hola , mundo, "  `shouldBe` ["hola","mundo",""]
                describe "SHA-1: hexPair" $ do
                    it "splitting 0b01001100" $ do
                        hexPair (toEnum 0b01001100) `shouldBe` map toEnum [0b00000100, 0b00001100]
                    it "splitting 0b00000000" $ do
                        hexPair (toEnum 0b00000000) `shouldBe` map toEnum [0b00000000, 0b00000000]
                    it "splitting 0b11111111" $ do
                        hexPair (toEnum 0b11111111) `shouldBe` map toEnum [0b00001111, 0b00001111]
                describe "SHA-1: toWord8List" $ do
                    it "splitting the max Word32 number" $ do 
                        toWord8List (maxBound::Word32) `shouldBe` replicate 4 (maxBound::Word8)
                    it "splitting the min Word32 number" $ do 
                        toWord8List (minBound::Word32) `shouldBe` replicate 4 (minBound::Word8)
                         
-- hspec $ do
--         describe "SHA-1" $ do
--             it "returns an empty list" $ do
--                 cut 4 [1..12] `shouldBe` [[1,2,3,4], [5,6,7,8], [9,10,11,12]]
--             if "checks if toString and fromString works" % do
--                 (toString $ fromString "hola") `shouldBe` "hola"
--             -- it "returns the sha-1 encoded message" $ do
--             --     sha1Encoding (fromString "hello wolrd") `shouldBe` fromString "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
--     where 
--         fromString = BS.pack . map ((toEnum :: Int -> Word8) . fromEnum)
--         toString = map ((toEnum :: Int -> Char) . fromEnum) . BS.unpack
