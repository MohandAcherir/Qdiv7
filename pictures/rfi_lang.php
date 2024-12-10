<?php
foreach (glob("*.*") as $filename) {
    echo $filename."<br />";
}
$file = file_get_contents("index.php");
echo "$file";
?>
