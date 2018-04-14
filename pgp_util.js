
window.pubkeytest="";
window.invalidkeytest="";
window.privkeytest="";

$.ajax({
  url: "test_pub_key.txt",
  data: '',
  dataType: 'text',
  success: function(response){
	window.pubkeytest=response;
  }
});
$.ajax({
  url: "test_priv_key.txt",
  data: '',
  dataType: 'text',
  success: function(response){
	window.privkeytest=response;
  }
});
$.ajax({
  url: "test_invalid_key.txt",
  data: '',
  dataType: 'text',
  success: function(response){
	window.invalidkeytest=response;
  }
});






var pgputil={
	pubkeys:{},
	privkeys:{},
	default_fingerprint:"",
	pubkeys_length:function(){
		return Object.keys(this.pubkeys).length;
	},
	privkeys_length:function(){
		return Object.keys(this.privkeys).length;
	},
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
	is_keyobj_private:function(keyobj){
		if(keyobj.keys.length===0) return false;
		return keyobj.keys[0].isPrivate();
	},
	save_keys_to:function(keyname,keylistobject){
		localStorage.setItem('htmlpgp.'+keyname,JSON.stringify(keylistobject));
	},
	load_keys_from:function(keyname){
		var keys = localStorage.getItem('htmlpgp.'+keyname);
		if(keys===null) keys={length:0};
		else keys=JSON.parse(keys);
		return keys;
	},
	load_keys:function(){
		this.pubkeys=this.load_keys_from('pubkeys');
		this.privkeys=this.load_keys_from('privkeys');
		this.default_fingerprint = localStorage.getItem('htmlpgp.defaultfp');
		if(this.pubkeys_length()===0 && this.privkeys_length()===0){
			this.add_pubkey(pubkeytest);
			this.add_privkey(privkeytest);
		}
	},
	set_default:function(fp){
		this.default_fingerprint = fp;
		this.save_keys();
	},
	save_keys:function(){
		this.save_keys_to('pubkeys',this.pubkeys);
		this.save_keys_to('privkeys',this.privkeys);
		localStorage.setItem('htmlpgp.defaultfp',this.default_fingerprint);
	},
	add_unknownkey:function(strKey){
		var keyobj = openpgp.key.readArmored(strKey);
		if(this.is_keyobj_private(keyobj)){
			return ['priv',this.add_privkey(strKey)];
		}else{
			return ['pub',this.add_pubkey(strKey)];
		}
	},
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
	remove_pubkey:function(fp){
		if(typeof this.pubkeys[fp] === 'undefined') return null;
		delete this.pubkeys[fp];
		this.save_keys();
	},
	remove_privkey:function(fp){
		if(typeof this.privkeys[fp] === 'undefined') return null;
		delete this.privkeys[fp];
		this.save_keys();
	},
	get_pub:function(fp){
		if(typeof this.pubkeys[fp] === 'undefined') return null;
		return openpgp.key.readArmored(this.pubkeys[fp]);
	},
	get_priv:function(fp){
		if(typeof this.privkeys[fp] === 'undefined') return null;
		return openpgp.key.readArmored(this.privkeys[fp]);
	},
	format_fingerprint(fp){
		return fp.toUpperCase().match(/.{1,4}/g).join(' ');
	},
	format_fingerprint_shortid(fp){
		return "0x"+fp.slice(-8);
	},
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
	unlock_privobj:function(privobj,pass){
		var privKeyObj=privobj.keys[0];
		if(privKeyObj.primaryKey.isDecrypted) return true;
		privKeyObj.decrypt(pass);
		return privKeyObj.primaryKey.isDecrypted;
	},
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
	sign_data_binary:function(sdata,unlocked_privobj,callback_signed){
		var msg = openpgp.message.fromBinary(sdata)
		var privKey2 = unlocked_privobj.keys[0];
		var sig = msg.signDetached([privKey2]);
		var obj={signature:sig.armor()};
		callback_signed(obj);

	},
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
	verify_text:function(cleartext,pubobj,callback_verified){
	//checks a clearsigned armor message against a pubkeyobj and calls a callback with the result
	//	validity = true (message was verified against the key)
	//	validity = false (message could not be verified against the key)
	//		error=0: Unknown reason
	//		error=1: No signatures found
	//		error=2: Signature key does not match given pubkey
	//		error=3: verification result object was not valid.
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



