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
highlight_file('index.php');
?>
