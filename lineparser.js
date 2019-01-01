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

/*
 * Creates a state-based text parser that looks for section markers and holds an internal data for the section being parsed
 * 
 * The sections argument must be an array of internal section name and marker string that appears as a line in the text.
 */
function Lineparser(sections,initial_section_name, line_callback, section_complete_callback){
    if(typeof line_callback==="undefined") line_callback=this.dummy_callbacks.line;
    if(typeof section_complete_callback==="undefined") section_complete_callback=this.dummy_callbacks.section_complete;
    this.initial_section = initial_section_name;
    this.sections=sections;
    this.line_callback=line_callback;
    this.section_complete_callback=section_complete_callback;
    
    this.reset();
}

Lineparser.prototype={
    debug:function(){
      console.log(this.sections);  
    },
    dummy_callbacks:{
        line:function(obj){
            //console.log(obj);
            console.log("dummy line callback: "+obj.current.section+" > "+obj.current.line);
            return Lineparser.prototype.callback_result.CONTINUE;
        },
        section_complete:function(obj){
            //console.log(obj);
            console.log("dummy section-complete callback: "+obj.current.section+": "+obj.current.section_data);
            return Lineparser.prototype.callback_result.CONTINUE;
        }
    },
    callback_result:{
        CONTINUE:undefined,
        STOP:1
    },
    stop:function(){
        throw "lineparser-stop";
    },
    reset:function(){
        this.previous={},
        this.current={
            section_id:-1,
            section:null,
            section_data:"",
            line:""
        };
        this.final={
            exception:null
        };
    },
    parse:function(text){
        text = text.replace(/\/r/g, '');
        var lines = text.split("\n");
        this.parse_begin();
        try{
            this.change_section_nocallback(-1,this.initial_section,null);
            //console.log(this);
            //console.log(this.initial_section);
            //console.log("Lines: "+lines.length);
            for (var i = 0; i < lines.length; i++) {
                var line = lines[i].replace(/\s+$/g, '');
                this.current.line=line;
                if(!this.change_section_by_marker(line)){
                    this.current.section_data += line + "\n";
                    this.parse_line(line);
                }
            }
            this.triggerCallback(this.section_complete_callback);
        }catch(exception){
            this.final.exception=exception;
        }
        
        
        this.parse_end();
    },
    parse_begin:function(){
    },
    parse_end:function(){
        Object.assign( this.final ,this.current);
    },
    parse_line:function(line){
        this.triggerCallback(this.line_callback);
    },
    change_section_by_marker:function(line){
        //console.log("Sections: ");
        //console.log(this.sections);
        var next_section=this.current.section_id+1;
        if(next_section<this.sections.length){
            var section_name=this.sections[next_section][0];
            var section_marker=this.sections[next_section][1];
            //console.log("possible next section: "+next_section+" "+section_name+" `"+section_marker+"` / `"+line+"`");
            if(line===section_marker){
                this.change_section(next_section,section_name,section_marker);
                return true;
            }
        }
        return false;
    },
    change_section_nocallback:function(id,name,marker){
        this.previous=Object.assign({}, this.current);
        this.current.section_id=id;
        this.current.section=name;
        this.current.section_data="";
    },
    change_section:function(id,name,marker){
        console.log("Section: "+this.current.section +" -> "+name);
        this.triggerCallback(this.section_complete_callback);
        this.change_section_nocallback(id,name,marker);
    },
    triggerCallback:function(callback){
        var result = callback(this);
        if(result===this.callback_result.STOP) this.stop();
    }
};





//MDN Polyfill for Object.assign
if (typeof Object.assign != 'function') {
  // Must be writable: true, enumerable: false, configurable: true
  Object.defineProperty(Object, "assign", {
    value: function assign(target, varArgs) { // .length of function is 2
      'use strict';
      if (target == null) { // TypeError if undefined or null
        throw new TypeError('Cannot convert undefined or null to object');
      }

      var to = Object(target);

      for (var index = 1; index < arguments.length; index++) {
        var nextSource = arguments[index];

        if (nextSource != null) { // Skip over if undefined or null
          for (var nextKey in nextSource) {
            // Avoid bugs when hasOwnProperty is shadowed
            if (Object.prototype.hasOwnProperty.call(nextSource, nextKey)) {
              to[nextKey] = nextSource[nextKey];
            }
          }
        }
      }
      return to;
    },
    writable: true,
    configurable: true
  });
}