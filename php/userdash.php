<?php
// Asegúrate de iniciar la sesión
session_start();
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'user') {
    header("Location: login.html"); // Redirige si no es un administrador
    exit();
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $con = mysqli_connect('localhost', 'root', '', 'auroluxe');
    if (!$con) {
        die("Connection failed: " . mysqli_connect_error());
    }

    mysqli_close($con);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AuroLuxe Mainpage</title>
    <link rel="stylesheet" href="../assets/css/main_user.css">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">


</head>
<body>
    <div class="dashboard">
        <!-- Sidebar -->
        <aside class="sidebar">
            <div class="profile">
                <img src="../assets/images/Genericavatar.png" alt="User Avatar" class="avatar">
                <p class="username">Username</p>
            </div>
            <nav class="nav flex-column">
                <div class="dropdown">
                    <button class="btn botoncito dropdown-toggle" id="dropdownMenuButton" data-bs-toggle="dropdown" aria-expanded="false">
                        Usuario Administrador
                    </button>
                    <ul class="dropdown-menu" aria-labelledby="dropdownMenuButton">
                        <li><a class="dropdown-item" href="#">AdminUser</a></li>
                    </ul>
                </div>
            </nav>
            <img src="../assets/images/Logo.png" alt="AuroLuxe Logo" class="logo">
        </aside>

        <!-- Main Content -->
        <main class="main">
            <h1>ÁREAS</h1>
            <div class="dashboard2">
                <button class="area-btn">SALA</button>
                <button class="area-btn">COCINA</button>
            </div>
        </main>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    <script src="../js/script_prot.js"></script>
    <script src="../js/scripts.js"></script>
</body>
</html>