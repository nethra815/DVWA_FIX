sudo tee /var/www/html/dvwa/vulnerabilities/sqli/source/low.php > /dev/null <<'PHP'
<?php
// Fixed low.php - prepared statements + validation + safe output
if (isset($_REQUEST['Submit'])) {
    $html = '';

    // Get input and trim
    $id_raw = isset($_REQUEST['id']) ? trim($_REQUEST['id']) : '';

    if ($id_raw === '' || !ctype_digit($id_raw)) {
        $html .= "<pre>Invalid ID supplied.</pre>";
        echo $html;
        exit;
    }

    $id = (int) $id_raw;

    switch ($_DVWA['SQLI_DB']) {
        case MYSQL:
            $link = $GLOBALS["___mysqli_ston"];

            $stmt = mysqli_prepare($link, "SELECT first_name, last_name FROM users WHERE user_id = ?;");
            if ($stmt === false) {
                $html .= "<pre>Database error (prepare failed).</pre>";
                echo $html;
                exit;
            }

            mysqli_stmt_bind_param($stmt, "i", $id);

            if (!mysqli_stmt_execute($stmt)) {
                $html .= "<pre>Database error (execute failed).</pre>";
                mysqli_stmt_close($stmt);
                echo $html;
                exit;
            }

            $result = mysqli_stmt_get_result($stmt);
            if ($result) {
                while ($row = mysqli_fetch_assoc($result)) {
                    $first = $row["first_name"];
                    $last  = $row["last_name"];

                    $html .= "<pre>ID: " . htmlspecialchars($id_raw, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')
                          . "<br />First name: " . htmlspecialchars($first, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')
                          . "<br />Surname: " . htmlspecialchars($last, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')
                          . "</pre>";
                }
                mysqli_free_result($result);
            } else {
                $html .= "<pre>No results.</pre>";
            }

            mysqli_stmt_close($stmt);
            break;

        case SQLITE:
            global $sqlite_db_connection;

            if (!($sqlite_db_connection instanceof SQLite3)) {
                $html .= "<pre>SQLite DB connection not available.</pre>";
                echo $html;
                exit;
            }

            $q = "SELECT first_name, last_name FROM users WHERE user_id = :id;";
            $s = $sqlite_db_connection->prepare($q);
            if (!$s) {
                $html .= "<pre>Database error (prepare failed).</pre>";
                echo $html;
                exit;
            }

            $s->bindValue(':id', $id, SQLITE3_INTEGER);

            $results = $s->execute();
            if ($results) {
                while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
                    $first = $row["first_name"];
                    $last  = $row["last_name"];

                    $html .= "<pre>ID: " . htmlspecialchars($id_raw, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')
                          . "<br />First name: " . htmlspecialchars($first, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')
                          . "<br />Surname: " . htmlspecialchars($last, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')
                          . "</pre>";
                }
                $results->finalize();
            } else {
                $html .= "<pre>No results.</pre>";
            }
            break;

        default:
            $html .= "<pre>Unsupported database.</pre>";
            break;
    }

    echo $html;
}
PHP
