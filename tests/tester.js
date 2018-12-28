function isPromise(value) {
    return value && Object.prototype.toString.call(value) === "[object Promise]";
}

var tester = {
    cases: [],
    cases_ready: 0,
    load_cases: function (url, loaded_callback) {
        if (typeof loaded_callback === "undefined")
            loaded_callback = null;
        this.cases_ready = 0;
        var tester_instance = this;
        $.getJSON(url, null, function (data) {
            tester_instance.cases = data;
            //loaded_callback();
            tester_instance.cases.forEach(function (element, i) {
                tester_instance.load_case_data(i, function () {
                    console.log('loaded! ' + (tester_instance.cases_ready));
                    tester_instance.cases_ready += 1;

                    if (tester_instance.cases_ready === tester_instance.cases.length && loaded_callback !== null)
                        loaded_callback();


                });
            });
        });
    },
    load_case_data: function (i, loaded_callback) {
        var filename = "./cases/" + this.cases[i].id.toString() + ".txt";
        var tester_instance = this;
        $.ajax({
            dataType: "text",
            url: filename,
            data: null,
            success: function (data) {
                //console.log(data)
                //console.log(tester_instance.cases[i]);
                tester_instance.cases[i].input = data;
                loaded_callback();
            }
        });
    },
    test_cases: function (test_function, test_callback, test_finished) {
        if (typeof test_callback === "undefined")
            test_callback = null;
        if (typeof test_finished === "undefined")
            test_finished = null;
        var tester_instance = this;
        for(var i=0;i<this.cases.length;i++){
            tester_instance.test_case(i, test_function, test_callback);
        }
        //this.cases.forEach(function (element, i) {
        //    tester_instance.test_case(i, test_function, test_callback);
        //});
        if (test_finished !== null)
            test_finished();//foreach is synchronous so this will be when the tests are 'ran', but a test function itself may be async
    },
    test_case: function (i, test_function, test_callback) {
        if (typeof test_callback === "undefined")
            test_callback = null;
        var tester_instance = this;
        var test_output = test_function(this.cases[i].input);

        console.log("test_case");
        console.log(test_output);
        console.log("isPromise: "+isPromise(test_output));
        if (isPromise(test_output) || typeof test_output==="object") {//if we get a promise (async function still running), wait for the result to complete the test-case
            console.log(test_output);
            test_output.then(function (final_output) {
                tester_instance.test_case(i, function () {
                    console.log(final_output);
                    return final_output;
                }, test_callback);
            });
            return;
        }

        this.cases[i].actual = test_output;
        this.cases[i].result = (this.cases[i].expectation === this.cases[i].actual);
        if (test_callback !== null)
            test_callback(this.cases[i]);
    }
};