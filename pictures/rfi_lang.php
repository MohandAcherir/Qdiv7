<?php
foreach (glob("*.*") as $filename) {
    echo $filename."<br />";
}
echo readfile("index.php");
?>
