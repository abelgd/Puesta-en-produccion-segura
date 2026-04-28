<?php
$db = new PDO("sqlite:/var/www/html/data.db");

if ($_SERVER["REQUEST_METHOD"] == "POST" || $_SERVER["REQUEST_METHOD"] == "GET") {
    $username = $_REQUEST["username"];
    $password = $_REQUEST["password"];

    print("Usuario: " . $username . "<br>");
    print("Contraseña: " . $password . "<br>");

    $query = "SELECT * FROM users WHERE name = '$username' AND passwd = '$password'";
    echo "Consulta SQL: " . $query . "<br>";
    $result = $db->query($query);
    if ($result) {
        if ($result->fetchColumn() > 0) {
            echo "Inicio de sesión exitoso<br>";
        } else {
            echo "Usuario o contraseña incorrectos";
        }
    } else {
        echo "Error en la consulta: " . $db->errorCode();
    }
}
?>