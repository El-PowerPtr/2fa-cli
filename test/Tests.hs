module Main (main) where

import qualified Data.ByteString as BS
import Crypt.SHA1
import Data.Char
import Test.Hspec
import Test.QuickCheck
import Data.Word
import Control.Monad
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
                    it "splitting the min word32 number" $ do 
                        toWord8List (minBound::Word32) `shouldBe` replicate 4 (minBound::Word8)
                    it "splitting 0xFF03A15A " $ do 
                        toWord8List 0xFF03A15B `shouldBe` map toEnum [0xFF,0x03,0xA1,0x5B]
                describe "SHA-1: fromWord8List" $ do
                    it "fromWord8List is the reverse of toWord8List" $ do
                        quickCheck (\x ->  x == fromWord8List (toWord8List x) )
                describe "SHA-1: cut" $ do
                    it "cutting lists with size == 1" $ do
                        cut 1 [1,2,3,4] `shouldBe` [[ 1 ],[ 2 ],[ 3 ],[ 4 ]]
                    it "cutting lists with size == 2" $ do
                        cut 2 [1,1,2,2,3,3,4,4] `shouldBe` [[ 1,1 ],[ 2,2 ],[ 3,3 ],[ 4,4 ]]
                    it "cutting lists with size == 4" $ do
                        cut 4 [1..12] `shouldBe` [[1,2,3,4], [5,6,7,8], [9,10,11,12]]
                describe "SHA-1: padding" $ do
                    it "RFC example" $ do 
                        padding ( map toEnum [0b01100001, 0b01100010, 0b01100011, 0b01100100, 0b01100101]) 5 `shouldBe` (Right $ (toWord8List . toEnum) =<< [0x61626364, 0x65800000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000028])
                describe "SHA-1: diggest" $ do
                    it "RFC example diggest" $ do 
                        msgDiggest [[0x61, 0x62, 0x63, 0x64, 0x65, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28]] `shouldBe` [0x61626364, 0x65800000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000028]
                describe "SHA-1: toString and fromString" $ do
                    it "checks if toString and fromString works" $ do
                        toString ( fromString "hola") `shouldBe` "hola"
                describe "SHA-1: encoding different messages: " $ do
                    it "hello world" $ do
                        sha1Encoding (fromString "hello world") `shouldBe` fromString "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
                    it "The quick brown fox jumps over the lazy dog" $ do
                        sha1Encoding (fromString "The quick brown fox jumps over the lazy dog") `shouldBe` fromString "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
                    it "The quick brown fox jumps over the lazy cog" $ do
                        sha1Encoding (fromString "The quick brown fox jumps over the lazy cog") `shouldBe` fromString "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"
                    it "empty message" $ do
                        sha1Encoding (fromString "") `shouldBe` fromString "da39a3ee5e6b4b0d3255bfef95601890afd80709"
