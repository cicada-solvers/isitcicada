/*
name: pgputil.js
description: wrapper class for simplified OpenPGP.js operations, and localstorage support for keys
author(s): crashdemons
*/

var pgputil={

	//keyring held in memory, keys are stored as armor text, indexed by fingerprint
	pubkeys:{},
	privkeys:{},
	//default privkey index/fingerprint
	default_fingerprint:"",

	//get number of pubkeys held by keyring.
	pubkeys_length:function(){
		return Object.keys(this.pubkeys).length;
	},
	//get number of privkeys held
	privkeys_length:function(){
		return Object.keys(this.privkeys).length;
	},

	//estimate the bit length (eg: 4096) for the key. NOTE: only RSA keys are supported.
	get_keyobj_bitlength:function(publicKey){
		var publicKeyPacket = publicKey.keys[0].primaryKey;
		if (publicKeyPacket !== null) {
			var size = '';
			if (publicKeyPacket.mpi.length > 0) {
				size = (publicKeyPacket.mpi[0].byteLength() * 8);
			}
			return size;
		}
		return '';
	},

	//check if a keyobject (from readArmored) is a private key or not.
	is_keyobj_private:function(keyobj){
		if(keyobj.keys.length===0) return false;
		return keyobj.keys[0].isPrivate();
	},
	//save keyring to localstorage by name of keyring (internal)
	save_keys_to:function(keyname,keylistobject){
		localStorage.setItem('htmlpgp.'+keyname,JSON.stringify(keylistobject));
	},
	//load keyring from localstorage by name
	load_keys_from:function(keyname){
		var keys = localStorage.getItem('htmlpgp.'+keyname);
		if(keys===null) keys={length:0};
		else keys=JSON.parse(keys);
		return keys;
	},
	//load pub+priv keyings from localstorage and get default key fp
	load_keys:function(){
		this.pubkeys=this.load_keys_from('pubkeys');
		this.privkeys=this.load_keys_from('privkeys');
		this.default_fingerprint = localStorage.getItem('htmlpgp.defaultfp');
	},
	//set default key index/fp
	set_default:function(fp){
		this.default_fingerprint = fp;
		this.save_keys();
	},
	//save both keyrings to localstorage
	save_keys:function(){
		this.save_keys_to('pubkeys',this.pubkeys);
		this.save_keys_to('privkeys',this.privkeys);
		localStorage.setItem('htmlpgp.defaultfp',this.default_fingerprint);
	},
	//add an text armored key to a keyring conditionally (pub or priv)
	add_unknownkey:function(strKey){
		var keyobj = openpgp.key.readArmored(strKey);
		if(this.is_keyobj_private(keyobj)){
			return ['priv',this.add_privkey(strKey)];
		}else{
			return ['pub',this.add_pubkey(strKey)];
		}
	},
	//add a text-armored public key to the public keyring
	add_pubkey:function(strPubkey){
		var opub = openpgp.key.readArmored(strPubkey);
		if(opub.keys.length){
			var fp = opub.keys[0].primaryKey.fingerprint;
			if(this.is_keyobj_private(opub))
				return false;
			this.pubkeys[fp]=strPubkey;
			this.save_keys();
			return fp;
		}else return false;
		return true;
	},
	//add a text-armored private key to the private keyring
	add_privkey:function(strPubkey){
		var opub = openpgp.key.readArmored(strPubkey);
		if(opub.keys.length){
			var fp = opub.keys[0].primaryKey.fingerprint;
			if(!this.is_keyobj_private(opub))
				return false;
			this.privkeys[fp]=strPubkey;
			this.save_keys();
			return fp;
		}else return false;
		return true;
	},
	//remove a public key from the keyring
	remove_pubkey:function(fp){
		if(typeof this.pubkeys[fp] === 'undefined') return null;
		delete this.pubkeys[fp];
		this.save_keys();
	},
	//remove a private key from the keyring
	remove_privkey:function(fp){
		if(typeof this.privkeys[fp] === 'undefined') return null;
		delete this.privkeys[fp];
		this.save_keys();
	},
	//retrieve and decode a public key from the keyring (by fingerprint) into a keyobject (readArmored)
	get_pub:function(fp){
		if(typeof this.pubkeys[fp] === 'undefined') return null;
		return openpgp.key.readArmored(this.pubkeys[fp]);
	},
	//retrieve and decode (readArmored) a private key from the keyring into a keyobject
	get_priv:function(fp){
		if(typeof this.privkeys[fp] === 'undefined') return null;
		return openpgp.key.readArmored(this.privkeys[fp]);
	},
	//format a fingerprint into 4-character spacing for display purposes
	format_fingerprint(fp){
		return fp.toUpperCase().match(/.{1,4}/g).join(' ');
	},
	//format a fingerprint or longid into an 8-character shortid for display purposes.
	format_fingerprint_shortid(fp){
		return "0x"+fp.slice(-8);
	},
	//request a search for a public key on a remote keyserver (eg: pgp.mit.edu). Calls the callback function with the result.
	//callback arguments:
	//	keyid = the search query succeeded and this was the first key returned.
	//	null  = the search query returned no results
	//	false = there was an error performing the search query
	fetch_pub(server,squery,callback_func){
		var hkp = new openpgp.HKP('https://'+server);
		var options = {
			query: squery
		};
		var p=hkp.lookup(options).then(function(strPubkey) {
			var opub = openpgp.key.readArmored(strPubkey);
			if(opub.keys.length===0) return callback_func(null);
			return callback_func(strPubkey);
		}).catch(function(e){
			return callback_func(false);
		});
		return p;
	},
	//decrypts an encrypted private keyobject by password
	//returns true or false depending on if the key could be decrypted. NOTE: succeeds if the key was not encrypted to begin with.
	unlock_privobj:function(privobj,pass){
		var privKeyObj=privobj.keys[0];
		if(privKeyObj.primaryKey.isDecrypted) return true;
		privKeyObj.decrypt(pass);
		return privKeyObj.primaryKey.isDecrypted;
	},

	//sign a string with a decrypted private keyobj and call 'callback_signed' with the resullts
	//optionally, opt to detatch the signature.
	//the callback will receive an object with clearsigned data in callbackargument.data (and callbackargument.signature if detached)
	sign_data:function(sdata,unlocked_privobj,callback_signed,detach=false){
		var privKeyObj=unlocked_privobj.keys[0];
		var options = {
		 data: sdata,             // input as String (or Uint8Array)
		  privateKeys: privKeyObj, // for signing
		  detached:detach
		};
		console.log(options);
		return openpgp.sign(options).then(callback_signed);
	},

	//sign data with a decrypted priv keyobject and call 'callback_signed' with the results.
	//
	sign_data_binary:function(sdata,unlocked_privobj,callback_signed){
		var msg = openpgp.message.fromBinary(sdata)
		var privKey2 = unlocked_privobj.keys[0];
		var sig = msg.signDetached([privKey2]);
		var obj={signature:sig.armor()};
		callback_signed(obj);

	},

	//encrypt data with a decrypted priv keyobject intended for a destination pub keyobject to read and call 'callback_signed' with the results
	//the callback will receive an object with ascii-armored message stored in callbackargument.data
	encrypt_data_binary:function(bdata,destination_pubobj,unlocked_privobj,callback_signed){
		var privKeyObj=unlocked_privobj.keys[0];
		var options, encrypted;

		options = {
			data: bdata, // input as Uint8Array (or String)
			publicKeys: destination_pubobj.keys,
			privateKeys: [privKeyObj],
			armor: false                              // don't ASCII armor (for Uint8Array output)
		};

		openpgp.encrypt(options).then(callback_signed);
	},

	//checks a clearsigned armor message against a pubkeyobj and calls a callback with the result
	//	validity = true (message was verified against the key)
	//	validity = false (message could not be verified against the key)
	//		error=0: Unknown reason
	//		error=1: No signatures found
	//		error=2: Signature key does not match given pubkey
	//		error=3: verification result object was not valid.
	//the calback will receive the validity, a verification result object, and the error code
	// the verification object holds a list of signatures in verobj.signatures, of which you can check the validity with verobj.signatures[i].valid
	verify_text:function(cleartext,pubobj,callback_verified){
		options = {
			message: openpgp.cleartext.readArmored(cleartext), // parse armored message
			publicKeys: pubobj.keys   // for verification
		};//NOTE: only exceptions from Read will be caught from this function
		var result=openpgp.verify(options).then(function(verified) {
			console.log(verified);
			var validity=null;
			var error=0;
			if(typeof verified !== 'object'){
				error=3
			}else if(verified.signatures.length===0){//verification can fail on null without any signature entries.
				error=1;
			}else{
				validity = verified.signatures[0].valid;
				if(validity===null) error=2;
			}
			if(validity===null) validity=false;
			callback_verified(validity,verified,error);
		});
		return result;
	}
}



