/// Encryption of tagion documents
module tagion.crypto.Cipher;

import std.exception : assumeUnique, ifThrown; 
import tagion.basic.Types : Buffer;
import tagion.crypto.Types : Pubkey;
import tagion.crypto.random.random;
import tagion.hibon.Document;
import tagion.hibon.HiBONRecord;

/// @safe: Memory-safe subset; Enforces a subset of D that prevents memory bugs from occurring by design.
@safe /// @safe code can only call other @safe or @trusted functions

struct Cipher { 
    import tagion.crypto.secp256k1.NativeSecp256k1;
    import std.digest.crc : crc64ECMAOf;
    import tagion.basic.ConsensusExceptions : ConsensusException, ConsensusFailCode, SecurityConsensusException;
    import tagion.crypto.SecureInterfaceNet : SecureNet;
    import tagion.crypto.SecureNet : check;
    import tagion.crypto.random.random;
    import tagion.crypto.aes.AESCrypto : AESCrypto;

    alias AES = AESCrypto!256; 
    enum CRC_SIZE = crc64ECMAOf.length;

    @recordType("TCD")
    struct CipherDocument {
        @label("$m") Buffer ciphermsg;
        @label("$n") Buffer nonce;
        @label("$a") Buffer authTag;
        @label("$k") Pubkey cipherPubkey;
        mixin HiBONRecord;
    }

    /// static means it belongs to the Cipher struct, const refers to the return type of the function, 
    /// i.e., the method returns a cipherDocument that is constant 
    /// encrypt is the name of the function
    /// const(SecureNet) net is a constant SecureNet object
    /// const(Pubkey) pubkey is a constant Pubkey object
    /// A 'Document' object that is to be encrypted (obs. not marked const as we want to modify it)
    static const(CipherDocument) encrypt(const(SecureNet) net, const(Pubkey) pubkey, Document msg) {
        /// Allocate a buffer for the secret key and ensure it is cleared when the function exits
        /// A buffer is a block of memory that stores data temporarily while it is being moved
        scope ubyte[32] secret_key_alloc;
        scope ubyte[] secret_key = secret_key_alloc;
        scope (exit) {
            secret_key[] = 0; /** Ensures that the secret key is not stored after use - Is there more data that could be cleared similarly? */
        }
        /// Generate random secret key /** Should one ensure that the same one isn't used multiple times? */
        /** I'm not sure that could be done without storing other keys, which in itself would pose a threat*/
        getRandom(secret_key);
        /// Initialise the result CipherDocument
        CipherDocument result;
        /// Get the public key associated with the secret key 
        result.cipherPubkey = net.getPubkey(secret_key);
        /// Allocate a buffer for the nonce and generate a random nonce
        /// A nonce is a unique value that is only used once in cryptographic communication
        /** Again, should you ensure that there are no duplicates? */
        scope ubyte[AES.BLOCK_SIZE] nonce_alloc;
        scope ubyte[] nonce = nonce_alloc;
        getRandom(nonce);
        ///Store a copy of the nonce in the result
        result.nonce = nonce.idup;
        // Appand CRC ///Allocate a buffer for the encrypted message including the CRC size
        auto ciphermsg = new ubyte[AES.enclength(msg.data.length + CRC_SIZE)];

        // Put random padding to in the last block
        auto last_block = ciphermsg[$ - AES.BLOCK_SIZE + CRC_SIZE .. $];
        getRandom(last_block);
        ///Compute the CRC of the message data
        const crc = msg.data.crc64ECMAOf;
        ciphermsg[0 .. msg.data.length] = msg.data;
        ciphermsg[msg.data.length .. msg.data.length + CRC_SIZE] = crc;
        /// Derive a shared ECC key using ECDH  /** Is the key exchange secure? */
        scope sharedECCKey = net.ECDHSecret(secret_key, pubkey);
        AES.encrypt(sharedECCKey, result.nonce, ciphermsg, ciphermsg);
        /// result.ciphermsg is assigned the encrypted message buffer
        Buffer get_ciphermsg() @trusted {
            return assumeUnique(ciphermsg);
        }
        /// The fully constructed and encrypted CipherDocument is returned
        result.ciphermsg = get_ciphermsg;
        return result;
    }

    static const(CipherDocument) encrypt(const(SecureNet) net, const(Document) msg) {
        return encrypt(net, net.pubkey, msg);
    }

    /// Decryption function
    static const(Document) decrypt(const(SecureNet) net, const(CipherDocument) cipher_doc) {
        /// Retrieves the public key used for encryption from the CipherDocument
        scope sharedECCKey = net.ECDHSecret(cipher_doc.cipherPubkey);
        /// Allocates a buffer to hold the decrypted message
        auto clearmsg = new ubyte[cipher_doc.ciphermsg.length];
        /// Decrypts the message using the shared ECC key
        AES.decrypt(sharedECCKey, cipher_doc.nonce, cipher_doc.ciphermsg, clearmsg);
        /// Converts the decrypted message into a document using a buffer
        Buffer data = (() @trusted => assumeUnique(clearmsg))();
        const result = Document(data);
        ///Verifying the integrity of the message
        immutable full_size = result.full_size;
        check(full_size + CRC_SIZE <= data.length && full_size !is 0,
                ConsensusFailCode.CIPHER_DECRYPT_ERROR);
        const crc = data[full_size .. full_size + CRC_SIZE];
        check(data[0 .. full_size].crc64ECMAOf == crc, 
                ConsensusFailCode.CIPHER_DECRYPT_CRC_ERROR);
        /// Returns the successfully decrypted document and verified data.
        return result;
    }
/** Error handling - Do any errors that occur leak sensitive data in any way? */
    ///
    unittest {
        import std.algorithm.searching : all, any;
        import tagion.basic.Types : FileExtension;
        import tagion.basic.basic : fileId;
        import tagion.crypto.SecureNet;
        import tagion.hibon.Document : Document;
        import tagion.hibon.HiBON : HiBON;
        import tagion.utils.Miscellaneous : decode;

        /// A passphrase is set to generate a key pair
        immutable passphrase = "Secret pass word";
        auto net = new StdSecureNet; /// Only works with ECDSA for now 
        net.generateKeyPair(passphrase);
        /// A secret message is defined and stored in a HiBON document (what is that?)
        immutable some_secret_message = "Text to be encrypted by ECC public key and " ~
            "decrypted by its corresponding ECC private key";
        auto hibon = new HiBON;
        hibon["text"] = some_secret_message;
        const secret_doc = Document(hibon);
        ///Creates a new network and encrypts secret_doc using Cipher.encrypt, then serialised, then decrypted and matched with original
        { // Encrypt and Decrypt secret message
            auto dummy_net = new StdSecureNet;
            auto secret_cipher_doc = Cipher.encrypt(dummy_net, net.pubkey, secret_doc).serialize;
            const encrypted_doc = Cipher.decrypt(net, CipherDocument(Document(secret_cipher_doc)));
            assert(encrypted_doc["text"].get!string == some_secret_message);
            assert(secret_doc.data == encrypted_doc.data);
        }

        ///Creates a new network with a different passphrase, encrypts secret.doc using wrong key
        /// Attempt to decrypt with correct key, then expects "consensusException"
        { // Use of the wrong privat-key
            auto dummy_net = new StdSecureNet;
            auto wrong_net = new StdSecureNet;
            immutable wrong_passphrase = "wrong word";
            wrong_net.generateKeyPair(wrong_passphrase);
            bool cipher_decrypt_error;
            bool cipher_decrypt_crc_error;
            while (!cipher_decrypt_error || !cipher_decrypt_crc_error) {
                const secret_cipher_doc = Cipher.encrypt(dummy_net, wrong_net.pubkey, secret_doc);
                try {
                    const encrypted_doc = Cipher.decrypt(net, secret_cipher_doc);
                    assert(secret_doc != encrypted_doc);
                    if (!encrypted_doc.empty) {
                        break; /// Run the loop until the decrypt does not fail
                    }
                }
                catch (ConsensusException e) {
                    cipher_decrypt_error |= (e.code == ConsensusFailCode.CIPHER_DECRYPT_ERROR);
                    cipher_decrypt_crc_error |= (e.code == ConsensusFailCode.CIPHER_DECRYPT_CRC_ERROR);
                }
            }
        }
        /// Encrypt using owner's private key, decrypt using Cipher.decrypt with net, and verify correct message
        { // Encrypt and Decrypt secrte message with owner privat-key
            const secret_cipher_doc = Cipher.encrypt(net, secret_doc);
            const encrypted_doc = Cipher.decrypt(net, secret_cipher_doc);
            assert(encrypted_doc["text"].get!string == some_secret_message);
            assert(secret_doc.data == encrypted_doc.data);
        }

    }

}
