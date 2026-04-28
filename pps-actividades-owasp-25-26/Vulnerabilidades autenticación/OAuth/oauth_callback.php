<?php
if (isset($_GET['code'])) {
echo "Código OAuth recibido: " . htmlspecialchars($_GET['code'], ENT_QUOTES, 'UTF-8');
} else {
echo "Error: No se recibió ningún código OAuth.";
}
?>