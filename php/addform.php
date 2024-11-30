<?php
session_start();
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header("Location: login.html"); // Redirigir a login si no es admin
    exit();
}
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $con = mysqli_connect('localhost', 'root', '', 'auroluxe');
    if (!$con) {
        die("Connection failed: " . mysqli_connect_error());
    }

    // Agregar nuevo usuario
    $name = $_POST['name'];
    $email = $_POST['email'];
    $password = $_POST['password'];
    $role = $_POST['role'];

    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
    $insert_query = "INSERT INTO users (name, email, password, role) VALUES ('$name', '$email', '$hashed_password', '$role')";

    if (mysqli_query($con, $insert_query)) {
        echo "<div class='alert alert-success'>User added successfully</div>";
    } else {
        echo "<div class='alert alert-danger'>Error: " . mysqli_error($con) . "</div>";
    }

    mysqli_close($con);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard</title>
    <link href="../assets/css/stylesda.css" rel="stylesheet"/>
<form action="admindash.php" method="POST">
                    <div class="mb-3">
                        <label for="name" class="form-label">Nombre Completo</label>
                        <input type="text" name="name" id="name" class="form-control" required>
                    </div>
                    <div class="mb-3">
                        <label for="email" class="form-label">Correo Electrónico</label>
                        <input type="email" name="email" id="email" class="form-control" required>
                    </div>
                    <div class="mb-3">
                        <label for="password" class="form-label">Contraseña</label>
                        <input type="password" name="password" id="password" class="form-control" required>
                    </div>
                    <div class="mb-3">
                        <label for="role" class="form-label">Rol</label>
                        <select name="role" id="role" class="form-select" required>
                            <option value="user">Usuario</option>
                            <option value="admin">Administrador</option>
                        </select>
                    </div>
                    <button type="submit" class="btn btn-primary" name="add_user">Agregar Usuario</button>
                </form>
            </main>
        </div>
    </div>