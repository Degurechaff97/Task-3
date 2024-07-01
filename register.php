<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $name = trim($_POST['name']);
    $phone = trim($_POST['phone']);
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);
    $confirm_password = trim($_POST['confirm_password']);

    $errors = [];

    // Валидация почты
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Неверный формат почты";
    }

    // Валидация телефона
    if (!preg_match('/^\+\d+$/', $phone)) {
        $errors[] = "Телефон должен начинаться с + и содержать только цифры";
    }

    // Валидация пароля
    if (strlen($password) < 6) {
        $errors[] = "Пароль должен быть не менее 6 символов";
    }

    // Проверка совпадения паролей
    if ($password !== $confirm_password) {
        $errors[] = "Пароли не совпадают";
    }

    if (empty($errors)) {
        $servername = "localhost";
        $username = "root"; // Имя пользователя по умолчанию
        $password_db = ""; // Пароль по умолчанию пустой у меня
        $dbname = "task-3";

        $conn = new mysqli($servername, $username, $password_db, $dbname);

        if ($conn->connect_error) {
            die("Connection failed: " . $conn->connect_error);
        }

        $email_check_query = $conn->prepare("SELECT * FROM users WHERE email=? LIMIT 1");
        $email_check_query->bind_param("s", $email);
        $email_check_query->execute();
        $email_check_query->store_result();

        $phone_check_query = $conn->prepare("SELECT * FROM users WHERE phone=? LIMIT 1");
        $phone_check_query->bind_param("s", $phone);
        $phone_check_query->execute();
        $phone_check_query->store_result();

        if ($email_check_query->num_rows > 0) {
            echo "Почта уже зарегистрирована";
        } elseif ($phone_check_query->num_rows > 0) {
            echo "Телефон уже зарегистрирован";
        } else {
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);
            $insert_query = $conn->prepare("INSERT INTO users (name, phone, email, password) VALUES (?, ?, ?, ?)");
            $insert_query->bind_param("ssss", $name, $phone, $email, $hashed_password);

            if ($insert_query->execute()) {
                echo "Пользователь успешно зарегистрирован";
            } else {
                echo "Ошибка при регистрации пользователя: " . $conn->error;
            }
        }

        $email_check_query->close();
        $phone_check_query->close();
        $conn->close();
    } else {
        foreach ($errors as $error) {
            echo $error . "<br>";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Регистрация</title>
</head>
<body>
    <h2>Регистрация</h2>
    <form method="post">
        Имя: <input type="text" name="name" required><br>
        Телефон: <input type="text" name="phone" required><br>
        Почта: <input type="email" name="email" required><br>
        Пароль: <input type="password" name="password" required><br>
        Повтор пароля: <input type="password" name="confirm_password" required><br>
        <input type="submit" value="Регистрация">
    </form>
    <p>Уже есть учетная запись? <a href="login.php">Войдите</a></p>
</body>
</html>
