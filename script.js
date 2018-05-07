String.prototype.hashCode = function(){
    var hash = 0;
    for (var i = 0; i < this.length; i++) {
        var character = this.charCodeAt(i);
        hash = ((hash<<5)-hash)+character;
        hash = hash & hash; // Convert to 32bit integer
    }
    return hash+"X"+this.length;
}

$(function() {
	console.log('jquery ready');
	preload_wait();
	$("#input_text").val('');
	window.input_dirty=false;
	load_key();
});

function preload_wait(){
	$('#loadcover').show();
}
function preload_finish(){
	$('#loadcover').hide();
}

function input_setup_actions(){
	window.input_check=true;
	setInterval(input_check_changed,500);
	$('#input_text').change(input_check_changed);
	setInterval(function(){
		if(window.input_dirty){
			if(!window.input_check) return;
			window.input_dirty=false;
			input_verify();
		}
	},250);

}

function input_check_changed(){
	if(!window.input_check) return;
	var newhash = $("#input_text").val().hashCode();
	if(window.input_hash!==newhash){
		console.log(window.input_hash+ " !== "+newhash)
		window.input_hash = newhash;
		window.input_dirty=true;
	}
}





function input_verify(){
	var pubkeyobj = pgputil.get_pub('6d854cd7933322a601c3286d181f01e57a35090f')
	var text = $("#input_text").val();
	$('#result_text').html('&nbsp;');
	try{
		return pgputil.verify_text(text,pubkeyobj, input_verified);
	}catch(err){
		input_failed(err,text);
		return 'error';
	}
}

function input_verified(validity,verified,error){
	if(validity===true){
		$('#result_text').html('<span style="color:green">YES - Good Signature</span>');
	}else{//could decode but not verify - usually because a different (incorrect) key signed the message. we can check if this is the case.
		switch(error){
			case 1:
				$('#result_text').html('<span style="color:orange">NO - No valid signature present</span>');
				break;
			case 2:
				console.log('incorrect keyid: '+verified.signatures[0].keyid.toHex())
				$('#result_text').html('<span style="color:red">NO - Signed with wrong key</span>');
				break;
			case 3:
				$('#result_text').html('<span style="color:orange">NO - Error processing message</span>');
				break;
			default:
				$('#result_text').html('<span style="color:red">NO - Bad Signature for this message</span>');
		}
	}
}
function input_failed(err,text){
	if(err.message="Unknown ASCII armor type"){
		if(text.length===0) err.message="&nbsp;";
		else err.message='Malformed ASCII armor message';
	}
	if(text.length!==0) err.message='<span style="color:orange">NO - '+err.message+'</span>'
	$('#result_text').html(err.message);
}

function load_key(){
	$.ajax({
	  url: "cicada_3301_key.txt",
	  data: '',
	  dataType: 'text',
	  success: function(response){
		window.testx=response;
		pgputil.add_pubkey(response);
		input_setup_actions();
		preload_finish();
		$('#input_text').focus();
	  }
	});
}