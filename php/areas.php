<?php
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    // Conectar a la base de datos
    $con = mysqli_connect('localhost', 'root', '', 'auroluxe');
    if (!$con) {
        die("Connection failed: " . mysqli_connect_error());
    }

    // Obtener los datos del formulario
    $area = $_POST['area'];
    $description = $_POST['description'];

    // Insertar la nueva área en la base de datos
    $query1 = "INSERT INTO areas (area, description) VALUES ('$area', '$description')";
    if (mysqli_query($con, $query1)) {
        echo "<div class='alert alert-success'>Área agregada correctamente</div>";
    } else {
        echo "<div class='alert alert-danger'>Error: " . mysqli_error($con) . "</div>";
    }


    // Cerrar la conexión
    mysqli_close($con);
}
?>

<!-- Formulario para agregar nueva área -->
<form action="areas.php" method="POST">
    <div class="mb-3">
        <label for="area" class="form-label">Nombre del Área</label>
        <input type="text" name="area" id="area" class="form-control" required>
    </div>
    <div class="mb-3">
        <label for="description" class="form-label">Descripción</label>
        <textarea name="description" id="description" class="form-control" required></textarea>
    </div>
    <button type="submit" class="btn btn-primary">Agregar Área</button>
</form>
