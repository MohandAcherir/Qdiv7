<?php
foreach (glob("*.*") as $filename) {
    echo $filename."<br />";
}
echo file_get_contents("index.php");
?>
