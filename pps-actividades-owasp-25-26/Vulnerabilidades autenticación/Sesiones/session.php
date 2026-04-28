<?php
session_start();
$_SESSION['user'] = $_GET['user'];
echo "Sesión iniciada como: " . $_SESSION['user'];
?>