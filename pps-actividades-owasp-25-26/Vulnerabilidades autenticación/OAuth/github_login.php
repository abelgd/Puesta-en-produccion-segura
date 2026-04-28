<?php
$auth_url = "https://github.com/login/oauth/authorize?" . http_build_query([
"client_id" => "Ov23livFnpm90Ii5wxhC",
"client_secret" => "3310dcb82dc5019cf95e2e70727e8b991c840341",
"redirect_uri" => "http://localhost/oauth_callback.php",
"state" => "pepe",
"scope" => "read:user"
]);
header("Location: " . $auth_url);
exit();