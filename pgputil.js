/*
 name: pgputil.js
 description: wrapper class for simplified OpenPGP.js operations, and localstorage support for keys
 author(s): crashdemons
 */

if (typeof openpgp === "undefined") {
    var openpgp = {};//suppress warnings in editor - doesn't change anything.
    console.error("PGPUtil loaded before OpenPGP");
}

var pgputil = {
    //keyring held in memory, keys are stored as armor text, indexed by fingerprint
    
    warning:{//things to inform the user about that don't really impact verification.
        VERIFY_FORMAT_DATA_OUTSIDE_MESSAGE: 2001,
        VERIFY_FORMAT_EMPTY_MESSAGE: 2002,
        VERIFY_FORMAT_COMMENTS: 2003,
        messages:{
            2001: "Text outside of the message body cannot be verified",
            2002: "Whitespace inside of empty messages cannot be verified to be authentic",
            2003: "Comment headers cannot be verified to be authentic"
        }
    },
    error:{
        GIT_BITLENGTH_INVALID_KEY: "",
        NONE:0,
        VERIFY_NO_SIGNATURE:1,
        VERIFY_VALIDITY_NULL:2, VERIFY_INCORRECT_KEY:2,
        VERIFY_RESULT_INVALID:3,
        VERIFY_RESULT_BAD_SIGNATURE:4,
        VERIFY_EXCEPTION:5,
        VERIFY_FORMAT_BAD_MESSAGE_HEADER:1001,
        VERIFY_FORMAT_BAD_SIG_HEADER:1002,
        VERIFY_FORMAT_INVALID:1003,//generic error for incomplete messages
        VERIFY_FORMAT_HASH_MISMATCH:1004,
        VERIFY_FORMAT_HASH_IN_SIG:1005,
        VERIFY_FORMAT_EMPTY:1006,
        messages:{
            0: "Success",
            1: "No valid signature present",
            2: "Incorrect signature keyid (signed by someone else)",
            3: "Error processing message",
            4: "Bad signature (does not match message)",
            5: "Exception",
            1001: "Invalid message header",
            1002: "Invalid signature header",
            1003: "Invalid format",
            1004: "Conflicting Hash header values",
            1005: "Hash header is not allowed in signature"
        }
    },
    
    pubkeys: {},
    privkeys: {},
    //default privkey index/fingerprint
    default_fingerprint: "",

    //get number of pubkeys held by keyring.
    pubkeys_length: function () {
        return Object.keys(this.pubkeys).length;
    },
    //get number of privkeys held
    privkeys_length: function () {
        return Object.keys(this.privkeys).length;
    },

    //estimate the bit length (eg: 4096) for the key. NOTE: only RSA keys are supported.
    get_keyobj_bitlength: function (publicKey) {
        var publicKeyPacket = publicKey.keys[0].primaryKey;
        if (publicKeyPacket !== null) {
            var size = '';
            if (publicKeyPacket.mpi.length > 0) {
                size = (publicKeyPacket.mpi[0].byteLength() * 8);
            }
            return size;
        }
        return pgputil.error.GIT_BITLENGTH_INVALID_KEY;
    },

    //check if a keyobject (from readArmored) is a private key or not.
    is_keyobj_private: function (keyobj) {
        if (keyobj.keys.length === 0)
            return false;
        return keyobj.keys[0].isPrivate();
    },
    //save keyring to localstorage by name of keyring (internal)
    save_keys_to: function (keyname, keylistobject) {
        localStorage.setItem('htmlpgp.' + keyname, JSON.stringify(keylistobject));
    },
    //load keyring from localstorage by name
    load_keys_from: function (keyname) {
        var keys = localStorage.getItem('htmlpgp.' + keyname);
        if (keys === null)
            keys = {length: 0};
        else
            keys = JSON.parse(keys);
        return keys;
    },
    //load pub+priv keyings from localstorage and get default key fp
    load_keys: function () {
        this.pubkeys = this.load_keys_from('pubkeys');
        this.privkeys = this.load_keys_from('privkeys');
        this.default_fingerprint = localStorage.getItem('htmlpgp.defaultfp');
    },
    //set default key index/fp
    set_default: function (fp) {
        this.default_fingerprint = fp;
        this.save_keys();
    },
    //save both keyrings to localstorage
    save_keys: function () {
        this.save_keys_to('pubkeys', this.pubkeys);
        this.save_keys_to('privkeys', this.privkeys);
        localStorage.setItem('htmlpgp.defaultfp', this.default_fingerprint);
    },
    //add an text armored key to a keyring conditionally (pub or priv)
    add_unknownkey: function (strKey) {
        var keyobj = openpgp.key.readArmored(strKey);
        if (this.is_keyobj_private(keyobj)) {
            return ['priv', this.add_privkey(strKey)];
        } else {
            return ['pub', this.add_pubkey(strKey)];
        }
    },
    //add a text-armored public key to the public keyring
    add_pubkey: function (strPubkey) {
        var opub = openpgp.key.readArmored(strPubkey);
        if (opub.keys.length) {
            var fp = opub.keys[0].primaryKey.fingerprint;
            if (this.is_keyobj_private(opub))
                return false;
            this.pubkeys[fp] = strPubkey;
            this.save_keys();
            return fp;
        } else
            return false;
        return true;
    },
    //add a text-armored private key to the private keyring
    add_privkey: function (strPubkey) {
        var opub = openpgp.key.readArmored(strPubkey);
        if (opub.keys.length) {
            var fp = opub.keys[0].primaryKey.fingerprint;
            if (!this.is_keyobj_private(opub))
                return false;
            this.privkeys[fp] = strPubkey;
            this.save_keys();
            return fp;
        } else
            return false;
        return true;
    },
    //remove a public key from the keyring
    remove_pubkey: function (fp) {
        if (typeof this.pubkeys[fp] === 'undefined')
            return null;
        delete this.pubkeys[fp];
        this.save_keys();
    },
    //remove a private key from the keyring
    remove_privkey: function (fp) {
        if (typeof this.privkeys[fp] === 'undefined')
            return null;
        delete this.privkeys[fp];
        this.save_keys();
    },
    //retrieve and decode a public key from the keyring (by fingerprint) into a keyobject (readArmored)
    get_pub: function (fp) {
        if (typeof this.pubkeys[fp] === 'undefined')
            return null;
        return openpgp.key.readArmored(this.pubkeys[fp]);
    },
    //retrieve and decode (readArmored) a private key from the keyring into a keyobject
    get_priv: function (fp) {
        if (typeof this.privkeys[fp] === 'undefined')
            return null;
        return openpgp.key.readArmored(this.privkeys[fp]);
    },
    //format a fingerprint into 4-character spacing for display purposes
    format_fingerprint: function (fp) {
        return fp.toUpperCase().match(/.{1,4}/g).join(' ');
    },
    //format a fingerprint or longid into an 8-character shortid for display purposes.
    format_fingerprint_shortid: function (fp) {
        return "0x" + fp.slice(-8);
    },
    //request a search for a public key on a remote keyserver (eg: pgp.mit.edu). Calls the callback function with the result.
    //callback arguments:
    //	keyid = the search query succeeded and this was the first key returned.
    //	null  = the search query returned no results
    //	false = there was an error performing the search query
    fetch_pub: function (server, squery, callback_func) {
        var hkp = new openpgp.HKP('https://' + server);
        var options = {
            query: squery
        };
        var p = hkp.lookup(options).then(function (strPubkey) {
            var opub = openpgp.key.readArmored(strPubkey);
            if (opub.keys.length === 0)
                return callback_func(null);
            return callback_func(strPubkey);
        }).catch(function (e) {
            return callback_func(false);
        });
        return p;
    },
    //decrypts an encrypted private keyobject by password
    //returns true or false depending on if the key could be decrypted. NOTE: succeeds if the key was not encrypted to begin with.
    unlock_privobj: function (privobj, pass) {
        var privKeyObj = privobj.keys[0];
        if (privKeyObj.primaryKey.isDecrypted)
            return true;
        privKeyObj.decrypt(pass);
        return privKeyObj.primaryKey.isDecrypted;
    },

    //sign a string with a decrypted private keyobj and call 'callback_signed' with the resullts
    //optionally, opt to detatch the signature.
    //the callback will receive an object with clearsigned data in callbackargument.data (and callbackargument.signature if detached)
    sign_data: function (sdata, unlocked_privobj, callback_signed, detach) {
        if (typeof detach === "undefined")
            detach = false;
        var privKeyObj = unlocked_privobj.keys[0];
        var options = {
            data: sdata, // input as String (or Uint8Array)
            privateKeys: privKeyObj, // for signing
            detached: detach
        };
        return openpgp.sign(options).then(callback_signed);
    },

    //sign data with a decrypted priv keyobject and call 'callback_signed' with the results.
    //
    sign_data_binary: function (sdata, unlocked_privobj, callback_signed) {
        var msg = openpgp.message.fromBinary(sdata);
        var privKey2 = unlocked_privobj.keys[0];
        var sig = msg.signDetached([privKey2]);
        var obj = {signature: sig.armor()};
        callback_signed(obj);

    },

    //encrypt data with a decrypted priv keyobject intended for a destination pub keyobject to read and call 'callback_signed' with the results
    //the callback will receive an object with encrypted message stored in callbackargument.data
    encrypt_data_binary: function (bdata, destination_pubobj, unlocked_privobj, callback_signed) {
        var privKeyObj = unlocked_privobj.keys[0];
        var options;

        options = {
            data: bdata, // input as Uint8Array (or String)
            publicKeys: destination_pubobj.keys,
            privateKeys: [privKeyObj],
            armor: false                              // don't ASCII armor (for Uint8Array output)
        };

        openpgp.encrypt(options).then(callback_signed);
    },
    
    
    //combines format validation and signature verification into a single function.
    verify_text: function (cleartext, pubobj, callback_verified, callback_failure) {
        try{
            var formaterror = this.verify_text_format(cleartext);
            console.log("formaterror: "+formaterror);
            if(formaterror === pgputil.error.NONE){
                return this.verify_text_signature(cleartext,pubobj,callback_verified);
            }else{
                callback_verified(false, null, formaterror);
                return Promise.resolve( {validity:false,verified:null, error:formaterror} );
            }
        }catch(exception){
            callback_failure(exception,cleartext);
            return Promise.resolve( {validity:false, verified:null, error:pgputil.error.VERIFY_EXCEPTION, exception:exception} );
        }
        return null;
    },
    

    //checks a clearsigned armor message against a pubkeyobj and calls a callback with the result
    //	validity = true (message was verified against the key)
    //	validity = false (message could not be verified against the key)
    //		error=0: Unknown reason
    //		error=1: No signatures found
    //		error=2: Signature key does not match given pubkey
    //		error=3: verification result object was not valid.
    //		error=4: bad signature for this message
    //the calback will receive the validity, a verification result object, and the error code
    // the verification object holds a list of signatures in verobj.signatures, of which you can check the validity with verobj.signatures[i].valid
    verify_text_signature: function (cleartext, pubobj, callback_verified) {
        var options = {
            message: openpgp.cleartext.readArmored(cleartext), // parse armored message
            publicKeys: pubobj.keys   // for verification
        };//NOTE: only exceptions from Read will be caught from this function
        var result = openpgp.verify(options).then(function (verified) {
            var validity = null;
            var error = pgputil.error.NONE;
            if (typeof verified !== 'object') {
                error = pgputil.error.VERIFY_RESULT_INVALID;
            } else if (verified.signatures.length === 0) {//verification can fail on null without any signature entries.
                error = pgputil.error.VERIFY_NO_SIGNATURE;
            } else {
                validity = verified.signatures[0].valid;
                if (validity === null)//verification won't produce a validty for nonmatching keys, so we verified a message with a different keyid
                    error = pgputil.error.VERIFY_VALIDITY_NULL;
            }
            if(validity===false && error===pgputil.error.NONE){
                error=pgputil.error.VERIFY_RESULT_BAD_SIGNATURE;//validity returned false above, but no errors - so the signature was formatted correctly, but doesn't match the message.
            }

            if (validity === null){
                validity = false;
            }
            callback_verified(validity, verified, error);
            return {validity:validity,verified:verified, error:error};
        });
        return result;
    },
    

    //checks a clearsigned armor message for discrepancies in formatting that are ignored by OpenPGP.js
    //refer to this infographic for how this function validates messages https://i.imgur.com/AvultlA.png
    verify_text_format: function (cleartext) {
        if(cleartext.length===0) return pgputil.error.VERIFY_FORMAT_EMPTY;
        cleartext = cleartext.replace(/\/r/g, '');//remove Carriage Returns so that we can split the message by linefeeds
        var lines = cleartext.split("\n");
        var context = "outside-before";
        var hash = "";//current hash for the message - can be unset but cannot conflict between headers.
        for (var i = 0; i < lines.length; i++) {
            var precontext = context;//unused but can be used in future processing to determine the previous context (stage/section) of data being processed.
            var line = lines[i];
            line = line.replace(/\s+$/g, '');//right-trim whitespace from end of line

            //state-based parsing in normal message order (yes this looks bad, feel free to refactor this)
            if (context === "outside-before" && line === "-----BEGIN PGP SIGNED MESSAGE-----") {//if we're outside and encounter a BEGIN, then we're in the preamble (containing headers)
                context = "msg-headers";
            } else if (context === "msg-headers" && line !== "") {//if we're in the preamble (hashes etc) and encounter a non-blank line, then it MUST be a valid header
                var header_split = {name: "", value: ""};//create object to hold results
                if (!this.verify_text_header(line, header_split))
                    return pgputil.error.VERIFY_FORMAT_BAD_MESSAGE_HEADER;//verify and split header into object
                if (header_split.name === "Hash") {
                    if (header_split.value !== hash && hash !== "")
                        return pgputil.error.VERIFY_FORMAT_HASH_MISMATCH;//if the current hash is known and this header doesn't match it - there's a conflict.
                    else
                        hash = header_split.value;//if the hash header is not known (or inconsequentially matches the current), set the current hash to this header value
                }
            } else if (context === "msg-headers" && line === "") {//if we're in the preamble (hashes etc) and encounter a blank line, then we're not in the message
                context = "content";
            } else if (context === "content" && line === "-----BEGIN PGP SIGNATURE-----") {
                context = "sig-headers";
            } else if (context === "sig-headers" && line !== "") {//if we're in the signature header section and encounter a non-blank line then it MUST be a valid header
                var header_split = {name: "", value: ""};//create object to hold results
                if (!this.verify_text_header(line,header_split))
                    return pgputil.error.VERIFY_FORMAT_BAD_SIG_HEADER;
                if(header_split.name==="Hash")
                    return pgputil.error.VERIFY_FORMAT_HASH_IN_SIG;
            } else if (context === "sig-headers" && line === "") {//if we are in the signature header section and encounter a blank line, now we're in the signature
                context = "signature";
            } else if (context === "signature" && line === "-----END PGP SIGNATURE-----") {
                context = "outside-after";
            }
            //console.log("`"+line+"` "+line.length+" "+(line==="")+"  ["+precontext+" -> "+context+"]");
        }
        if (context !== "outside-after"){
            return pgputil.error.VERIFY_FORMAT_INVALID;
        }
        return pgputil.error.NONE;
    },
    verify_text_header: function (header, dest_object) {
        if (typeof dest_object === "undefined")
            dest_object = null;
        var parts = header.split(": ");
        //console.log(parts);
        if (parts.length < 2)
            return false;
        if (parts[0] !== "Hash" && parts[0] !== "Version" && parts[0] !== "Comment")
            return false;
        if (dest_object !== null) {
            dest_object.name = parts[0];
            dest_object.value = parts[1];
        }
        return true;
    }
};



