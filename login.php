<?php
define('SMARTCAPTCHA_SERVER_KEY', 'Используйте ключ');

function check_captcha($token) {
    $ch = curl_init();
    $args = http_build_query([
        "secret" => SMARTCAPTCHA_SERVER_KEY,
        "token" => $token,
        "ip" => $_SERVER['REMOTE_ADDR'], // Нужно передать IP-адрес пользователя.
    ]);
    curl_setopt($ch, CURLOPT_URL, "https://smartcaptcha.yandexcloud.net/validate?$args");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 1);

    $server_output = curl_exec($ch);
    $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpcode !== 200) {
        // Логируем ошибку, но не выводим её пользователю
        error_log("Allow access due to an error: code=$httpcode; message=$server_output");
        return true;
    }
    $resp = json_decode($server_output);
    return $resp->status === "ok";
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $login = trim($_POST['login']);
    $password = trim($_POST['password']);
    $captcha_response = $_POST['smart-token'];

    $errors = [];

    // Проверка капчи
    if (!check_captcha($captcha_response)) {
        $errors[] = "Проверка капчи не пройдена";
    }

    if (empty($errors)) {
        $servername = "localhost";
        $username = "root"; // Имя пользователя по умолчанию
        $password_db = ""; // Пароль по умолчанию пустой
        $dbname = "task-3";

        $conn = new mysqli($servername, $username, $password_db, $dbname);

        if ($conn->connect_error) {
            die("Connection failed: " . $conn->connect_error);
        }

        $stmt = $conn->prepare("SELECT id, password FROM users WHERE email=? OR phone=? LIMIT 1");
        $stmt->bind_param("ss", $login, $login);
        $stmt->execute();
        $stmt->store_result();
        $stmt->bind_result($user_id, $hashed_password);
        $stmt->fetch();

        if ($stmt->num_rows > 0 && password_verify($password, $hashed_password)) {
            session_start();
            $_SESSION['user_id'] = $user_id;
            header('Location: profile.php');
            exit();
        } else {
            $errors[] = "Неверный логин или пароль";
        }

        $stmt->close();
        $conn->close();
    }

    foreach ($errors as $error) {
        echo $error . "<br>";
    }
}
?>

<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Авторизация</title>
    <script src="https://smartcaptcha.yandexcloud.net/captcha.js" defer></script>
</head>
<body>
    <h2>Авторизация</h2>
    <form method="post">
        Email/Телефон: <input type="text" name="login" required><br>
        Пароль: <input type="password" name="password" required><br>
        <div id="captcha-container" class="smart-captcha" data-sitekey="Используйте ключ"></div>
        <input type="hidden" name="smart-token" id="smart-token">
        <input type="submit" value="Войти">
    </form>
    <p>Нет учетной записи? <a href="register.php">Зарегистрируйтесь</a></p>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            window.smartCaptchaCallback = function(token) {
                document.getElementById('smart-token').value = token;
            };
        });
    </script>
</body>
</html>