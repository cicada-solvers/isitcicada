/* 
 * Copyright (C) 2018 crashdemons (crashenator at gmail.com)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


if (typeof Lineparser === "undefined") {
    var Lineparser = {};//suppress warnings in editor - doesn't change anything.
    console.error("pgpparser code loaded before Lineparser");
}

function PgpParser(line_callback,section_complete_callback){
    this.reset();
    this.line_callback=line_callback;
    this.section_complete_callback=section_complete_callback;
    this.final.error=0;
    this.final.warnings=[];
}

//this is ugly and I hate prototypal inheritance + backporting
PgpParser.prototype = new Lineparser([
    ["msg-headers","-----BEGIN PGP SIGNED MESSAGE-----"],
    ["content",""],
    ["sig-headers","-----BEGIN PGP SIGNATURE-----"],
    ["signature",""],
    ["outside-after","-----END PGP SIGNATURE-----"]
],"outside-before");

PgpParser.prototype.fail=function(error){
    this.final.error=error;
    this.stop();
};
PgpParser.prototype.warn=function(warning){
    if(this.final.warnings.indexOf(warning)===-1)
        this.final.warnings.push(warning);
};

var test_parser = new PgpParser();
var test_document=null;


        var filename = "./tests/cases/23.txt";
        $.ajax({
            dataType: "text",
            url: filename,
            data: null,
            success: function (data) {
                //console.log(data)
                //console.log(tester_instance.cases[i]);
                test_document= data;
            }
        });