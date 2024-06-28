/// We change it to include the encryption flag:
    /** Do we need a @safe here for it to work? */
    this(uint schema, uint level, immutable(ubyte)[] data, bool isEncrypted) pure{ // Incl. flag that determines whether or not the data should be encrypted
        this.header = EnvelopeHeader(shema, level); // Unchanged
        this.isEncrypted = encrypted; // Using the flag
        this.errorstate = false; // Unchanged

        if (encrypted = true) {
            SecureNet net; // Initialising the parameters of the function Cipher.encrypt
            Pubkey pubkey; // --||--
            CipherDocument cipherDoc = Cipher.encrypt(net, pubkey, Document(data)); // Encrypting the data
            this.data = cipherDoc.toBuffer; // Transport to buffer
            this.isEncrypted = true; // We have encrypted it, so we now flag the data as being encrypted (Is this necessary? Does the property follow the data?)
        }
        else {
            this.data = data; // If we do not wish to encrypt the package, we just keep the data as is
            this.isEncrypted = false; // And we flag the data as not being encrypted
        }
    }