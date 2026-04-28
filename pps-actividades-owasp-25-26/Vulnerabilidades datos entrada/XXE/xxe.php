<?php
// Crear un objeto DOMDocument
$dom = new DOMDocument();
// Habilitar la carga de entidades externas (solo para pruebas, no usar en producción)
$dom->loadXML(file_get_contents('php://input'), LIBXML_NOENT | LIBXML_DTDLOAD);
// Convertir el XML a SimpleXMLElement (opcional)
$parsed = simplexml_import_dom($dom);
// Mostrar el resultado
echo $parsed;
?>