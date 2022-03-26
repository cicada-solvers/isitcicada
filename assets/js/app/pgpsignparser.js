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

//a stateful text-line parser for pgp cleartext messages.
//the line callback is called when each line in a section of the message is processed
//the section-complete callback is called when all data for a section has been collected (the section was ended or moved onto the next section)
function PgpSignParser(line_callback,section_complete_callback){
    this.reset();
    this.line_callback=line_callback;
    this.section_complete_callback=section_complete_callback;
    this.final.error=0;
    this.final.warnings=[];
}

//this is ugly and I hate prototypal inheritance + backporting
PgpSignParser.prototype = new Lineparser([
    ["sig-headers","-----BEGIN PGP MESSAGE-----"],//define the starting conditions for each section
    ["signature",""],
    ["outside-after","-----END PGP MESSAGE-----"]
],"outside-before");//define the initial section name

//record a fatal error from a callback function (stored in parserobject.final.error)
PgpSignParser.prototype.fail=function(error){
    this.final.error=error;
    this.stop();
};

//record a warning from a callback function (stored in parserobject.final.warnings)
PgpSignParser.prototype.warn=function(warning){
    if(this.final.warnings.indexOf(warning)===-1)
        this.final.warnings.push(warning);
};
