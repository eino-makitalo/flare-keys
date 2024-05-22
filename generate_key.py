import os
import binascii
from eth_keys import keys
from bip_utils.addr.atom_addr import AtomAddrEncoder
from bip_utils import Bip44, Bip44Coins, Bip39SeedGenerator
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins,  Bip39MnemonicGenerator,  Bip39WordsNum,  Bip44Changes
import hashlib
import base58

def add_checksum(buff):
    """Calculate SHA-256 hash of the buffer, take the last 4 bytes as checksum, and append them to the buffer."""
    hash_obj = hashlib.sha256(buff)
    hash_bytes = hash_obj.digest()
    checksum = hash_bytes[28:]  # Taking the last 4 bytes
    return buff + checksum

def cb58_encode(data_bytes):
    """Encode data with base58 and append a checksum."""
    checksum_data = add_checksum(data_bytes)
    return base58.b58encode(checksum_data).decode('utf-8')


def generate_private_keys(hexkey=None, mnemonic=None,index=0, hrp="flare"):
    # give either hexkey or mnemonic if nothing it generates one metamask compatible key
    # hrp can be "flare", "costwo","localflare","avax" etc
    if mnemonic:
        seed = Bip39SeedGenerator(mnemonic).Generate("")
        bip44_mst_key = Bip44.FromSeed(seed, Bip44Coins.FLARE_P_CHAIN).Purpose().Coin().Account(index).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
        #bip44_mst_key = Bip44.FromSeed(seed, Bip44Coins.FLARE_P_CHAIN).DeriveDefaultPath()
        private_key2 = bip44_mst_key.PrivateKey()
        
        priv_bytes = private_key2.m_priv_key.Raw().ToBytes()
        private_key_hex = binascii.hexlify(priv_bytes).decode('utf-8')
        private_key = keys.PrivateKey(priv_bytes)
        
        
    else:        
        if hexkey is None:
            priv_bytes = os.urandom(32)
            private_key_hex = binascii.hexlify(priv_bytes).decode('utf-8')
            private_key = keys.PrivateKey(priv_bytes)
        else:
            priv_bytes = binascii.unhexlify(hexkey)
            private_key = keys.PrivateKey(priv_bytes)
            private_key_hex = binascii.hexlify(priv_bytes).decode('utf-8')
        bip44_mst_key = Bip44.FromPrivateKey(priv_bytes, Bip44Coins.FLARE_P_CHAIN)
        
    public_key = private_key.public_key
    public_key_hex = public_key.to_hex()[2:]  # Convert public_key to hex and remove 0x
    
    eth_address = public_key.to_checksum_address()
    
        
    #Paddress = bip44_mst_key.PublicKey().ToAddress()
    Paddress = "P-" + AtomAddrEncoder.EncodeKey(bip44_mst_key.PublicKey().m_pub_key.KeyObject(),
                                                     hrp=hrp)    


    cb58EncodedPrivateKey = cb58_encode(priv_bytes)

    # Prefix with "PrivateKey-" to match Avalanche's expected input format
    avalanchePrivateKey = f"PrivateKey-{cb58EncodedPrivateKey}"
    return priv_bytes, private_key, private_key_hex, public_key, eth_address, Paddress, avalanchePrivateKey

print("MNEMONIC ....")
mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_24)
print(mnemonic)
mnemonic = ""
avaimet = []
for index in range(50):    
    privkeybytes, private_key, metamask_private_key, publickey, ethaddr, Paddress, avalanchePrivateKey = generate_private_keys(mnemonic=mnemonic, index=index)
    print(f"Private Key Bytes: {privkeybytes}")
    print(f"Private Key: {private_key}")
    print(f"Metamask Private Key: {metamask_private_key}")
    print(f"Public Key: {publickey}")
    print(f"Ethereum Address: {ethaddr}")
    print(f"P-Chain Address: {Paddress}")
    print(f"Avalanche Private Key: {avalanchePrivateKey}")
    avaimet.append((index, metamask_private_key, ethaddr, Paddress))
print(avaimet)

