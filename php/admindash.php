<?php
// Asegúrate de iniciar la sesión
session_start();
$con = mysqli_connect('localhost', 'root', '', 'auroluxe');
if (!$con) {
    die("Connection failed: " . mysqli_connect_error());
}

if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header("Location: login.html"); // Redirige si no es un administrador
    exit();
}
$query = "SELECT * FROM users"; // Cambia la tabla 'users' si es diferente
$result = mysqli_query($con, $query);
if ($result) {
    echo "Consulta exitosa<br>"; 
    $users = mysqli_fetch_all($result, MYSQLI_ASSOC);}

$query1 = "SELECT * FROM areas"; // Consulta para obtener todas las áreas
$result1= mysqli_query($con, $query1);
if ($result1) {
    $areas = mysqli_fetch_all($result1, MYSQLI_ASSOC); // Obtén las áreas como un array asociativo
} else {
    $areas = []; // Si no hay áreas o hay un error, asigna un array vacío
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
    <title>Admin Dashboard</title>
    <link href="../assets/css/stylesda.css" rel="stylesheet"/>
    <!-- Bootstrap JS and Popper.js -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js" crossorigin="anonymous"></script>
    <script src="../assets/js/scripts.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/2.8.0/Chart.min.js" crossorigin="anonymous"></script>
    <script src="../assets/js/chart-area-demo.js"></script>
    <script src="../assets/js/chart-bar-demo.js"></script>
        <script src="../assets/js/chart-area-demo.js"></script>
        <script src="../assets/js/chart-bar-demo.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/simple-datatables@7.1.2/dist/umd/simple-datatables.min.js" crossorigin="anonymous"></script>
        <script src="js/datatables-simple-demo.js"></script>

</head>

    <div class="container-fluid">
        <div class="row">
            <!-- Barra Lateral -->
            <nav class="col-md-3 col-lg-2 d-md-block bg-light sidebar">
                <div class="position-sticky">
                    <ul class="nav flex-column">
                        <li class="nav-item">
                            <a class="nav-link active" href="#">
                                <h4>Control panel</h4>
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="../php/addform.php">ADD USER</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#" data-bs-toggle="collapse" data-bs-target="#userDropdown" aria-expanded="false">
                                Registed users
                            </a>
                            <div id="userDropdown" class="collapse">
                                <ul class="nav flex-column ms-3">
                                    <?php foreach ($users as $user): ?>
                                        <li class="nav-item">
                                            <a class="nav-link" href="#"><?=htmlspecialchars( $user['name']) ?></a>
                                        </li>
                                    <?php endforeach; ?>
                                </ul>
                            </div>
                        </li>
                    </ul>
                </div>
            </nav>

            <!-- Contenido Principal -->
            <main class="col-md-9 ms-sm-auto col-lg-10 px-4">
                <h4>Welcome, admin </h4>
                <ul class="nav flex-column ms-3">
    <?php foreach ($areas as $area): ?>
        <li class="nav-item">
            <a class="nav-link" href="areas.php?id=<?= $area['id'] ?>"><?= htmlspecialchars($area['area']) ?></a>

        </li>
    <?php endforeach; ?>
</ul>


                <!-- Formulario para agregar un nuevo usuario -->


    <!-- Bootstrap JS and Popper.js -->
    <!--<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>

   <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js" crossorigin="anonymous"></script>
        <script src="js/scripts.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/2.8.0/Chart.min.js" crossorigin="anonymous"></script>
        <script src="assets/demo/chart-area-demo.js"></script>
        <script src="assets/demo/chart-bar-demo.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/simple-datatables@7.1.2/dist/umd/simple-datatables.min.js" crossorigin="anonymous"></script>
        <script src="js/datatables-simple-demo.js"></script> -->
</body>
</html>
