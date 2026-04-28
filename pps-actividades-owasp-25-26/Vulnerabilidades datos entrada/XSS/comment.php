<?php
if (isset($_POST['comment'])) {
echo "Comentario publicado: " . $_POST['comment'];
}
?>
<form method="post">
<input type="text" name="comment">
<button type="submit">Enviar</button>
</form>
