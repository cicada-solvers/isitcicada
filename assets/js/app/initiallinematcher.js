/* 
 * Copyright (C) 2022 crashdemons (crashenator at gmail.com)
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


function InitialLineMatcher(section_markers){
    this.reset();
    this.match = null;
    this.section_markers = section_markers;
}

//this is ugly and I hate prototypal inheritance + backporting
InitialLineMatcher.prototype = new Lineparser([],"outside-before");

InitialLineMatcher.prototype.change_section_by_marker = function(line){
    for(var i=0;i<this.section_markers.length;i++){
        if(line===this.section_markers[i]){
            this.change_section(0,'message-started',this.section_markers[i]);
            this.match = i;
            this.stop();
            return true;
        }
    }
    return false;
};