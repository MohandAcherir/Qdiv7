<?php
foreach (glob("../*.*") as $filename) {
    echo $filename."<br />";
}

$file_content = file_get_contents('./index.php');
echo $file_content;
?>
