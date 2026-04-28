<?php
$db = new PDO("sqlite:/var/www/html/data.db");
if ($_SERVER["REQUEST_METHOD"] == "POST") {
$username = $_POST["username"];
$password = $_POST["password"];
$query = "SELECT * FROM users WHERE name = '$username' AND passwd = '$password'";
echo "Consulta ejecutada: " . $query . "<br>";
$result = $db->query($query);
if ($result) {
if ($result->fetchColumn() > 0) {
echo "Inicio de sesión exitoso<br>";
// Modificación: Mostrar datos extraídos de la consulta
foreach ($result as $row) {
echo "ID: " . $row['id'] . " - Usuario: " . $row['name'] . " -
Contraseña: " . $row['passwd'] . "<br>";
}
} else {
echo "Usuario o contraseña incorrectos";
}
} else {
echo "Error en la consulta: " . $db->errorCode();
}
}
?>
<form method="post">
<input type="text" name="username" placeholder="Usuario">
<input type="password" name="password" placeholder="Contraseña">
<button type="submit">Iniciar Sesión</button>
</form>
