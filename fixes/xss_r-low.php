sudo tee /var/www/html/dvwa/vulnerabilities/xss_r/source/low.php > /dev/null <<'PHP'
<?php
// xss reflected (low) — fixed: output encoding

if (isset($_REQUEST['Submit'])) {
    $html = '';

    // simple helper for safe output
    function h($s) {
        return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    $name = isset($_REQUEST['name']) ? $_REQUEST['name'] : '';

    $html .= "<pre>Welcome, " . h($name) . "</pre>";

    echo $html;
}
?>
PHP
