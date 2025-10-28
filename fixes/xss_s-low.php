sudo tee /var/www/html/dvwa/vulnerabilities/xss_s/source/low.php > /dev/null <<'PHP'
<?php
// xss stored (low) — fixed: store raw (or validate) but always encode on output

// helper
function h($s) {
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

$storage_file = __DIR__ . '/comments.txt';

if (isset($_POST['Submit'])) {
    $comment = isset($_POST['comment']) ? trim($_POST['comment']) : '';

       if (strlen($comment) > 0 && strlen($comment) <= 2000) {
               file_put_contents($storage_file, $comment . PHP_EOL, FILE_APPEND | LOCK_EX);
        $msg = "Comment stored";
    } else {
        $msg = "Invalid comment";
    }
}

$comments = [];
if (file_exists($storage_file)) {
    $comments = file($storage_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
}

?>
<html>
<body>
<?php if (!empty($msg)) echo "<div>" . h($msg) . "</div>"; ?>
<form method="post">
<textarea name="comment" rows="4" cols="50"></textarea><br>
<input type="submit" name="Submit" value="Submit">
</form>

<h3>Comments</h3>
<?php
foreach ($comments as $c) {
    // ENCODE here — critical
    echo "<div class='comment'>" . h($c) . "</div>";
}
?>
</body>
</html>
PHP
