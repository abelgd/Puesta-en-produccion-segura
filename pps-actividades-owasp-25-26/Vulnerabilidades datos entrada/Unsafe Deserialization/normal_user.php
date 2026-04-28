<?php
class User {
    public $username = "usuario_normal";
    public $isAdmin = false;
}
echo urlencode(serialize(new User()));
?>