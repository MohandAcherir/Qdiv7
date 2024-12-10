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
$file_content = file_get_contents('fr_lang.php');
echo $file_content;

$file = fopen('index.php', 'rb');
if ($file) {
    $file_content = fread($file, filesize('index.php'));
    echo $file_content;
    fclose($file);
} else {
    echo "Error opening the file.";
}
?>
