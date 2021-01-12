<?php
if(isset($_GET['link'])){
	$check="https://pastebin.com/";
	$link = $_GET['link'];
	$linkcheck = substr($link, 0, strlen($check));
	if($check === $linkcheck){
		include("index.html");
		echo '<script src="pb?link='.urlencode($link).'"></script>';//bad method of adding a script but it works.
	}else{
            die("invalid pastebin link - must start with https://pastebin.com/");
        }
}
?>