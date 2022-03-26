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

if (typeof PgpClearsignParser === "undefined") {
    var PgpClearsignParser = {};//suppress warnings in editor - doesn't change anything.
    console.error("pgpparser code loaded before PgpClearsignParser");
}
if (typeof PgpSignParser === "undefined") {
    var PgpSignParser = {};//suppress warnings in editor - doesn't change anything.
    console.error("pgpparser code loaded before PgpSignParser");
}

if (typeof InitialLineMatcher === "undefined") {
    var InitialLineMatcher = {};//suppress warnings in editor - doesn't change anything.
    console.error("pgpparser code loaded before InitialLineMatcher");
}

var PgpParsing = {
    parsers:{
        CLEARSIGNED: 0,
        SIGNED: 1
    },
    guessMessageType:function(cleartext){
        var matcher = new InitialLineMatcher(["-----BEGIN PGP SIGNED MESSAGE-----","-----BEGIN PGP MESSAGE-----"]);
        matcher.parse(cleartext);
        if(matcher.match!==null) return matcher.match;
        return PgpParsing.parsers.CLEARSIGNED;//choose this as default if we cannot determine the type, though this should mean that it is rejected anyway.
    },
    
    createParser:function(type,line_callback,section_complete_callback){
        console.log("CreateParser",type);
        switch(type){
            case PgpParsing.parsers.SIGNED:
                return new PgpSignParser(line_callback,section_complete_callback);
            case PgpParsing.parsers.CLEARSIGNED:
                return new PgpClearsignParser(line_callback,section_complete_callback);
        }
        return null;
    }
};
