<?php
header("Content-type: application/javascript");
header('Cache-Control: max-age=86400');
?>

<?php
if (isset($_GET['link'])) {
    $check = "https://pastebin.com/";
    $link = $_GET['link'];
    $linkcheck = substr($link, 0, strlen($check));
    $linkid = substr($link, strlen($check));

    if ($check !== $linkcheck)
        die('alert("invalid pastebin link - please try again.")');
    if (!preg_match("/^[a-zA-Z0-9]{4,16}$/", $linkid))
        die('alert("invalid paste ID - please try again.")');
    $newlink = "http://pastebin.com/raw.php?i=" . $linkid;
    $data = file_get_contents($newlink);
    if (stristr($data, "<!DOCTYPE") !== FALSE) {
        die('alert("Pastebin link could not be loaded or is invalid - please try again later")');
    }
?>
    $(document).ready(function(){ $("#input_text").val(unescape("<?php
    echo rawurlencode($data);
    ?>")); });
<?php
} else {
    die('alert("No link parameter provided - this is an error.")');
}
?>