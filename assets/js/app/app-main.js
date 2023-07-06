if (typeof pgputil === "undefined") {
    var pgputil = {};//suppress warnings in editor - doesn't change anything.
    console.error("isitcicada code loaded before pgputil");
}


String.prototype.hashCode = function () {
    var hash = 0;
    for (var i = 0; i < this.length; i++) {
        var character = this.charCodeAt(i);
        hash = ((hash << 5) - hash) + character;
        hash = hash & hash; // Convert to 32bit integer
    }
    return hash + "X" + this.length;
};

$(function () {
    console.log('jquery ready');
    preload_wait();
    $("#input_text").val('');
    window.input_dirty = false;
    load_key();
});

$(document).ready(function() {
    // A PGP-message to verify can be passed using the URL parameter "message"
    // If present, load it.
    
    // Use the #hash instead of GET parameters, so that servers cannot issue "414 Too long request"
    let parameters = location.hash.substr(1).split("&");

    let message_parameter = "message";
    let message = parameters.find(p => p.startsWith(message_parameter + "="));

    if (message !== undefined) {
	message = message.substr(message_parameter.length + 1);
	message = decodeURIComponent(message);

	$("#input_text").val(message);
    }
});

function preload_wait() {
    $('#loadcover').show();
}
function preload_finish() {
    $('#loadcover').hide();
}

function input_setup_actions() {
    window.input_check = true;
    setInterval(input_check_changed, 500);
    $('#input_text').change(input_check_changed);
    setInterval(function () {
        if (window.input_dirty) {
            if (!window.input_check)
                return;
            window.input_dirty = false;
            input_verify();
        }
    }, 250);

}

function input_check_changed() {
    if (!window.input_check)
        return;
    var newhash = $("#input_text").val().hashCode();
    if (window.input_hash !== newhash) {
        //console.log(window.input_hash+ " !== "+newhash)
        window.input_hash = newhash;
        window.input_dirty = true;
    }
}





function input_verify() {
    var pubkeyobj = pgputil.get_pub('6d854cd7933322a601c3286d181f01e57a35090f');
    var text = $("#input_text").val();
    $('#result_text').html('&nbsp;');
    $('#warning_text').html('&nbsp;');
    
    return pgputil.verify_text(text,pubkeyobj,input_verified,input_failed);
}

function input_verified(validity, verified, error, warnings) {
    if (validity === true) {
        $('#result_text').html('<span style="color:green">YES - Good Signature</span>');

        var warningmessage="";
        for(var i=0;i<warnings.length;i++){
            var warning=warnings[i];
            if(warningmessage.length>0) warningmessage+="<br>";
            warningmessage+="Warning: "+pgputil.warning.messages[warning];
        }
        if(warningmessage.length===0) warningmessage="&nbsp;";
        $('#warning_text').html(warningmessage);
        
    } else {//could decode but not verify - usually because a different (incorrect) key signed the message. we can check if this is the case.
        var color="red";
        var message = pgputil.error.messages[error];
        if(typeof message === "undefined") message="Unknown error "+error;
        
        switch (error) {
            case pgputil.error.VERIFY_FORMAT_EMPTY:
                $('#result_text').html('&nbsp');
                return;
            case pgputil.error.NONE:
                message="Internal error (report this)";
            case pgputil.error.VERIFY_NO_SIGNATURE:
            case pgputil.error.VERIFY_RESULT_INVALID:
            case pgputil.error.VERIFY_FORMAT_BAD_MESSAGE_HEADER:
            case pgputil.error.VERIFY_FORMAT_BAD_SIG_HEADER:
            case pgputil.error.VERIFY_FORMAT_HASH_MISMATCH:
            case pgputil.error.VERIFY_FORMAT_HASH_IN_SIG:
            case pgputil.error.VERIFY_FORMAT_INVALID:
                color="orange";
        }
        $('#result_text').html('<span style="color:'+color+'">NO - '+message+'</span>');
        
    }
}
function input_failed(err, text) {
    console.log(err);
    var message = err.message;
    if (message === "Unknown ASCII armor type") {
        if (text.length === 0)
            message = "&nbsp;";
        else
            message = 'Malformed ASCII armor message';
    }
    if (text.length !== 0)
        message = '<span style="color:orange">NO - ' + err.message + '</span>';
    $('#result_text').html(message);
}

function load_key() {
    $.ajax({
        url: "assets/pgp/cicada_3301_key.txt",
        data: '',
        dataType: 'text',
        success: function (response) {
            window.testx = response;
            pgputil.add_pubkey(response);
            input_setup_actions();
            preload_finish();
            $('#input_text').focus();
        }
    });
}
