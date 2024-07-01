<?php
session_start();
// Проверка авторизации пользователя
if (!isset($_SESSION['user_id'])) {
    header('Location: index.php'); // Перенаправление на главную страницу, если пользователь не авторизован
    exit();
}

$servername = "localhost";
$username = "root"; // Имя пользователя по умолчанию
$password_db = ""; // Пароль по умолчанию пустой у меня
$dbname = "task-3";

$conn = new mysqli($servername, $username, $password_db, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$user_id = $_SESSION['user_id'];
$user_query = $conn->prepare("SELECT name, phone, email FROM users WHERE id=?");
$user_query->bind_param("i", $user_id);
$user_query->execute();
$user_query->bind_result($name, $phone, $email);
$user_query->fetch();
$user_query->close();

// Обработка изменения данных пользователя
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $name = trim($_POST['name']);
    $phone = trim($_POST['phone']);
    $email = trim($_POST['email']);
    $new_password = trim($_POST['new_password']);

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
    if (!empty($new_password) && strlen($new_password) < 6) {
        $errors[] = "Пароль должен быть не менее 6 символов";
    }

    if (empty($errors)) {
        if (!empty($name) && !empty($phone) && !empty($email)) {
            // Проверка уникальности почты и телефона, исключая текущего пользователя
            $email_check_query = $conn->prepare("SELECT id FROM users WHERE email=? AND id!=?");
            $email_check_query->bind_param("si", $email, $user_id);
            $email_check_query->execute();
            $email_check_query->store_result();

            $phone_check_query = $conn->prepare("SELECT id FROM users WHERE phone=? AND id!=?");
            $phone_check_query->bind_param("si", $phone, $user_id);
            $phone_check_query->execute();
            $phone_check_query->store_result();

            if ($email_check_query->num_rows > 0) {
                echo "Почта уже зарегистрирована другим пользователем";
            } elseif ($phone_check_query->num_rows > 0) {
                echo "Телефон уже зарегистрирован другим пользователем";
            } else {
                // Обновление данных пользователя
                $update_query = $conn->prepare("UPDATE users SET name=?, phone=?, email=? WHERE id=?");
                $update_query->bind_param("sssi", $name, $phone, $email, $user_id);

                if ($update_query->execute()) {
                    echo "Данные пользователя успешно обновлены<br>";
                } else {
                    echo "Ошибка при обновлении данных пользователя: " . $conn->error;
                }

                if (!empty($new_password)) {
                    $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
                    $update_password_query = $conn->prepare("UPDATE users SET password=? WHERE id=?");
                    $update_password_query->bind_param("si", $hashed_password, $user_id);

                    if ($update_password_query->execute()) {
                        echo "Пароль успешно обновлен<br>";
                    } else {
                        echo "Ошибка при обновлении пароля: " . $conn->error;
                    }
                }
            }

            $email_check_query->close();
            $phone_check_query->close();
        } else {
            echo "Пожалуйста, заполните все обязательные поля";
        }
    } else {
        foreach ($errors as $error) {
            echo $error . "<br>";
        }
    }
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Профиль</title>
</head>
<body>
    <h2>Профиль</h2>
    <form method="post">
        Имя: <input type="text" name="name" value="<?php echo htmlspecialchars($name, ENT_QUOTES, 'UTF-8'); ?>" required><br>
        Телефон: <input type="text" name="phone" value="<?php echo htmlspecialchars($phone, ENT_QUOTES, 'UTF-8'); ?>" required><br>
        Почта: <input type="email" name="email" value="<?php echo htmlspecialchars($email, ENT_QUOTES, 'UTF-8'); ?>" required><br>
        Новый пароль: <input type="password" name="new_password"><br>
        <input type="submit" value="Сохранить изменения">
    </form>
    <p><a href="logout.php">Выйти</a></p>
</body>
</html>
