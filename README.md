This code originated from https://github.com/svpcom/wifibroadcast
It was re-written in c++ with the intention to break up the FEC encoding / decoding and the 
Encryption / Decryption part into its own modules (represented by FECEncoder/Decoder and Encryptor/Decryptor).
By doing so I was able to write simple tests that don't require a wifi card for these modules.
I also added a lot of features, like disabling FEC completely (use k==0 in this case) or disabling encryption to save
cpu resources.