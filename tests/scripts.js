window.testPgpLock=new Promise(function(r,f){r('dummy');});//create a dummy promise so we can chain successive tests onto it sequentially.


function addResult_callback(testcase){
	console.log('add result');
	var result_string = '<span style="color:red;font-weight:bold;">FAIL</span>';
	if(testcase.result) result_string = '<span style="color:green;font-weight:bold;">PASS</span>';
	$("#results").append("<tr><td>"+testcase.id+"</td><td>"+testcase.name+"</td><td>"+testcase.expectation+"</td><td>"+testcase.actual+"</td><td>"+result_string+"</td></tr>");
}


function testPgpInput(input_str,resolve,reject){
	$("#input_text").val(input_str);
	window.input_check=true;
	window.input_dirty=true;
	var retval = input_verify();
        console.log("retval: ");
        console.log(retval);
	resolve(retval);
	return retval;
}

function testPgpInput_delayed(input_str){

	window.testPgpLock = window.testPgpLock.then(function(){
		return new Promise(function(resolve, reject) {
			setTimeout(testPgpInput, 500, input_str, resolve,reject);
		});
	});
	return window.testPgpLock;
}

$(function(){
	tester.load_cases('pgp_cases.json',function(){
		$('#status').text('Running test-cases...');
		tester.test_cases(testPgpInput_delayed, addResult_callback,function(){
			$('#status').text('Tests Ran.');
		});
	});
});