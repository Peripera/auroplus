<?php
session_start();

// Conexión a la base de datos
$con = mysqli_connect('localhost', 'root', '', 'auroluxe');
if (!$con) {
    die("Connection failed: " . mysqli_connect_error());
}

// Verificar si los datos fueron enviados desde el formulario
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = $_POST['email'];
    $password = $_POST['password'];

    // Consulta para verificar si ya existe un administrador
    $check_admin_query = "SELECT * FROM users WHERE role = 'admin'";
    $admin_result = mysqli_query($con, $check_admin_query);

    // Si no existe un administrador, permitir el registro
    if (mysqli_num_rows($admin_result) == 0) {
        // Registrar al administrador
        $name = $_POST['name']; // Nombre ingresado en el formulario
        $hashed_password = password_hash($password, PASSWORD_DEFAULT); // Hashear la contraseña
        $insert_query = "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, 'admin')";
        $stmt = mysqli_prepare($con, $insert_query);
        mysqli_stmt_bind_param($stmt, "sss", $name, $email, $hashed_password);

        if (mysqli_stmt_execute($stmt)) {
            echo "<script>alert('Administrator registered successfully. You can now log in.'); window.location.href = '../login.html';</script>";
            exit();
        } else {
            echo "<script>alert('Failed to register administrator.'); window.location.href = '../signup.html';</script>";
            exit();
        }
    } else {
        // Si ya existe un administrador, manejar el inicio de sesión
        $query = "SELECT * FROM users WHERE email = ?";
        $stmt = mysqli_prepare($con, $query);
        mysqli_stmt_bind_param($stmt, "s", $email);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);

        // Verificar si el usuario existe
        if (mysqli_num_rows($result) > 0) {
            $user = mysqli_fetch_assoc($result);

            // Verificar la contraseña
            if (password_verify($password, $user['password'])) {
                // Iniciar sesión y redirigir según el rol
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['role'] = $user['role'];  // Guardamos el rol en la sesión

                // Redirigir al dashboard correspondiente
                if ($user['role'] == 'admin') {
                    header("Location: admindash.php");  // Redirige al dashboard de admin
                } else {
                    header("Location: userdash.php");  // Redirige al dashboard de usuario
                }
                exit();
            } else {
                echo "<script>alert('Incorrect password.'); window.location.href = 'login.html';</script>";
            }
        } else {
            echo "<script>alert('User not found.'); window.location.href = 'login.html';</script>";
        }
    }
}

mysqli_close($con);
?>




