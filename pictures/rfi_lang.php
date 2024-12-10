<?php
$dir = opendir('.');
while ($file = readdir($dir)) {
    if ($file == '.' || $file == '..') {
        continue;
    }

    echo $file;
    echo "\n";
}
closedir($dir);
$file_content = file_get_contents('./index.php');
echo $file_content;
?>
