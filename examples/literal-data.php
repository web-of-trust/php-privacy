<?php declare(strict_types=1);

require_once dirname(__DIR__) . "/vendor/autoload.php";

use OpenPGP\OpenPGP;

$passphase = "GnB_dxv5^t.=+h:qmTq*3}}>3G5=FpdU";

$keyData = <<<EOT
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: PHP Privacy v1
Comment: https://github.com/web-of-trust/php-privacy

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
=Aj7S
-----END PGP PRIVATE KEY BLOCK-----
EOT;
$rsaPrivateKey = OpenPGP::decryptPrivateKey($keyData, $passphase);

$keyData = <<<EOT
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: PHP Privacy v1
Comment: https://github.com/web-of-trust/php-privacy

xcK5BGb2FXsRCADYVW3kOEPjDNC7d+qfMMv0gK5h2uT1yEF0LHLkx+o4Fty5aRyEkfsKF50tzniR
eM1C3s9rLYEs1KboUZI0cez5fcqJUm6Jtk4VrM/R6q2Cx+ufSg44kf+Xk0cI868pGbs/JDfS9rSV
oB4N9s3ugMDPueXDwgMWzGVhZD8693UmMczgnIx1o5JA8RneUAYpeGnmjadB1ZJrimGooDd/MO9R
L1ieK9CR6zUOoAOiysu97Ndh+cgNwCsp6qtPiTI8NhVtG+RmrokCjkrDYUI+T8TpLt8IL4rspdlm
PLPd9LZBvqTHyLD1eDUG2Q/Sa+UzxvxBYxL5NFw3bxseDBFd8SfPAOCnZ84dEdNhoF0DIbUY8u+y
gzS17kvbabHjhYXXB/99reTpj5D5+UkkBRoRHSsVlqi9HRbJD1+bhBsXjAhHO0LCWynMRNvR/Gts
SsQzyXijqVWbWYv5DoYN/O4HeKY5HiLV7InW3+zMHOs8ungo3RqgAv99WXUrmKM1lvCE1Pn1TY4l
L5uANyFBLrOK4SyDNK8c0t8LCgMg4elpwo2OIVi7lDI7szBj24E45D8nNCllH1RpLqQxJ3z35Ajg
IStRbYwpjGKSbvhAIFCQ+XWfG2woTmqT0LmACaEcK283h26vKdE6M8uksDx/0kNeSp61irhAZoFy
qkH2fsTfGsni/GJGGMnsbF0AikW66wNZD10MwH8myKG+qNc9/XA/nSwaCACfHbDsvNm7PSYiGUOc
frcyol5UZyd0ghG+T7/yi0sp46PILYjL+A+kL7F7cxOrUBUqnT5d5pzjAdAnFyRHDCUYE5a1dkHp
UclHs5hJim8ZpyLpasKTkVRq8cvaCqyYjQvfEI2dwORx3wAidKHXEoaHxSXbktZN4gx3tUSvdF1I
PgTgw8C/K0+RgWVJOTfRP/u6A9sYBcYzkjZfveudHuVmbiWiifox4QiNc0E6tnLUIHttg2DtAljl
nQ0RzbNlyLsxix3yd0qU3w+JHgYHleKcERVPjcbxDKpQhl2jxhg1e5HudQ9q9Ly3xtInzg/tjavD
PCQY+vrsguP7BiEXWu4i/gcDCMypK+xWNbMG4H+DM3U83GeAuoYVKdhuAoaU/mjIpLE/SgPPOKoB
tsBxu8CDhpPqyHuiS+NNdjWwtQ+9H+ElTeQiL+W98gMKDdpwLc0qTmd1eWVuIFZhbiBOZ3V5ZW4g
PG5ndXllbm52MTk4MUBnbWFpbC5jb20+wq8EEBEIAGkFAmb2FXwWIQSqVIwGlAi/UywkMLR9jKFq
PvFhPAkQfYyhaj7xYTwpFAAAAAAAEAAQc2FsdEBvcGVucGdwLm9yZ2v7Q30sF0SKKvjbys7pwlcC
GwMECwcICQMVCAoFFgABAgMCHgMCGQEAAFpHAOCQr5F2PUa1a7mevAfHMFNkfglgUFb4zQnuIGNz
AN0WNtrQq0sCjH8rqRWjiRy/Qv9Lb5OR3nGupRhZzSxOZ3V5ZW4gVmFuIE5ndXllbiA8bmd1eWVu
bnZAaXdheXZpZXRuYW0uY29tPsKsBBARCABmBQJm9hV8FiEEqlSMBpQIv1MsJDC0fYyhaj7xYTwJ
EH2MoWo+8WE8KRQAAAAAABAAEHNhbHRAb3BlbnBncC5vcmeRd2hW7xXvNDaIDoCRWmJ2AhsDBAsH
CAkDFQgKBRYAAQIDAh4DAAAuVwDeO8Wb3/y8TG29TVPvSwzstedyuh9m/Ecke+83AwDeP2y5qjiP
ZVHJrs4djorpZqsQJlI5C5yQQnQvD8fCmwRm9hV7EAgAntDUYIWUI4VQ9iX9xiALfjGUsbv/rPi3
XkBwdRXFsOnWaV5+7i/ql1oH4I6Gq9UHnPaTahAWOagRNiVgJTzhuRwqXQq9tL1qCWRscEIFhrTu
eM0lea7ofqdUCDKZR37EAMm387Lg75jS1U5zb4DQv0ZTms6TeaMM9Fx4dCbb2vBJJLv4u40IbCq0
+TX6+wnkuR42m/tfgs5B5JMadJG37vIvXBMd4xc76j5dpYCn/Z+o0I3XA3v/pqNn+HvaYH/53thk
pBZMsQlbVCi08O4dU6DAMb0idWJ6tHezeNzgS51Fhm9KVvyqPBh2SfKbAKVkoggkZEq8xnYYva9m
GbkHLwf/Z4OKGcUfidpErzmWrZeQubyeJLuttoZRKi8YUz3kJJ30cPBp2RLr7Yz09JYJtC4eGobg
ihueMtmGa6D8o2Q7i4jqyLrkps8FHd/Fw2MMVJzAhO7+8D1ZyrB1PPdIFT37xsASYFKBKQ/atkFL
zy8+PfugKKhlWymnCHfixXAKzrU+iYJWRhg/8PNnJMzwNxg5/ZWDmCqVfHP+iY5tcOBLboSw6Fgs
PuGhe9xgnJxPC1wKGYbi9yArKkPCbmCtLHcbvzG7aQfq1CPUWrEMxOtmryn+3RqVTiBCgmj0rBl9
SSjPIhM2o+JShxLJDEHDck3ZzKuDj/b9i+cAZYB5PCiHZQf/drxZtKWm2USOaFpJ44PntamQUb2b
aTEyZyca6bTeu5k3kVh/6BZEaGnJCdBvhvDEuOpnt2G4QlS40mnclv+v3kDrMR+Usk5Beh2cj3LF
ObhApjZmKIZ8sLheVzU/GT6nLTnu4raxpjc7f4+6SUF/D1lUfeLrabgKuDMKXQpVQGZWfES2QryZ
hCizcZBl70j2aCitfmU5hySqSwBascGSx9aqqPGpZ3fAQwAHmup3X3jvnWvHRu2/RVkukDAw3w6d
eQFhjRh5n3qp9Sxaz5/6mzWfPQy7Uyxw4+k/whkld6FlJtO9RyXB278TxB9TeQrfrEwQp0ErO4d5
rRH7Hun9Uv4HAwhnP8ID8rl5hOBnAyAjqMjyByVGTIVXzqBeaOR06ReBZBOByiLWHVSjR+I8la4d
3F3vE0Pg3PW3It8j4sqQd2V/2/vmoYJpjIz263vCmgQYEQgAVAUCZvYVfBYhBKpUjAaUCL9TLCQw
tH2MoWo+8WE8CRB9jKFqPvFhPCkUAAAAAAAQABBzYWx0QG9wZW5wZ3Aub3JnUocJBn7vtdEqTBUm
kWzh5AIbDAAAn8kA3RtmLN5rP1tLTN9idnd5q+OWF6W1N7127Vi7BAcA30ADVmzeZ4CTxHLTvCGy
3N0vKCLgYYnCxuEkaXA=
=31ub
-----END PGP PRIVATE KEY BLOCK-----
EOT;
$dsaPrivateKey = OpenPGP::decryptPrivateKey($keyData, $passphase);

$keyData = <<<EOT
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: PHP Privacy v1
Comment: https://github.com/web-of-trust/php-privacy

xcBHBGb2FXwTBSuBBAAjBCMEAK5mpkVYfixkA83l2o4C6zHiosYOJ8w2dPxPI2kKwYLWk80GeM7m
nRUGfsPX5B1HCLMDe4uaHbyniBvESbRNfpi+AbHCY+S0KqE3iauFiMFQtOYjHOt/kmq5tN2BpLGB
WVdi33X01EAbGd1Y0wMjFF7bQJfTXqNnImrOVzkSsUIOyrN3/gcDCJ8ns1zgXI9N4AKDnrjc/G4i
8oNjoma6eKvfXhQjrOqrxb1pOzJnNA1hFOmQajBk8Ikq6jjX6K1Lj104AKH4TytbNQTeQE8qOtTj
7sc49AziipRXF7jLV4Vx5DJjrsRjNqdoKJEW1Suoz+/ee9p7uoHNKk5ndXllbiBWYW4gTmd1eWVu
IDxuZ3V5ZW5udjE5ODFAZ21haWwuY29tPsLASQQQEwoAeQUCZvYVfBYhBG5eSxv8pVCeSS3+Wvvp
JxLuZtvdCRD76ScS7mbb3TkUAAAAAAAQACBzYWx0QG9wZW5wZ3Aub3Jnodo62mxVpBuwJnB99k4O
Rc3lJemBl+4ZkK/LEbegsdACGwMECwcICQMVCAoFFgABAgMCHgMCGQEAAHYnAgjad075+iBLuJO2
CN1n2lPA8JmN0FNCuEEHxXh9vNGExl7ec/IV/iipe/YRTmnbLG017+lBoriXXu4tpQQyGYSc3QIH
bmNkbYmCdtj0b8T2EYw7Xb07bHvDmCoj5JBLjpUCj+9kF3IZ5jdeU8xK2PnnHI1pKFW47LhOaRrz
Glkadm+KUuzNLE5ndXllbiBWYW4gTmd1eWVuIDxuZ3V5ZW5udkBpd2F5dmlldG5hbS5jb20+wsBF
BBATCgB2BQJm9hV8FiEEbl5LG/ylUJ5JLf5a++knEu5m290JEPvpJxLuZtvdORQAAAAAABAAIHNh
bHRAb3BlbnBncC5vcmevNWZ4/rdg3ir8ZXDNJhx5+lKzH+qbWRd+Y4Ga58EwvwIbAwQLBwgJAxUI
CgUWAAECAwIeAwAAcjUCANNsG56wDWT8sGzk/LVURKtU5PU3351qtUSx6AcNuz0PP8ooEk3w5gmq
Ov3dvjsgFHXcN7RzqzW/tMhaYDatdYoCB1MXlg5vR65NOhubs77rOk2LQ2EEwPZeMZafjd/BvUXz
9E6OaW8+Dj3HKjzY6jSBcCChZuEEF2JoCkIYDLDGAOhFx8BLBGb2FXwSBSuBBAAjBCMEAOWnLm2o
yuAUeVvL/BBdVhAPS3t4zLYkgSGORo4iS4ylt/Ku5VMZPPYgeHRnrHGKoHXqTUvlc6jnI5tZSmKD
cq7JAK0sy96EAKei0BELrSPDKwG6VT7GRfzWib5XA/n2SrQtcXFAxUdhaVJDYR922PTD6/Wmculd
dsEnZ1vQmC8vK7MPAwAKCf4HAwh2/hpDLxdGdODp4snjgr10Bl/mT+TchCQlvhqo0uq+I+m7lsq1
E1OWMWzhQv8zFRN2s8el+ZJQthNII+xDl4h79aaZ7OeXXunycsH4Q0D76D9wC2NTH3oB2j+IRv+X
iD9ouBubr0L3JQZZV5rRebMzwsA1BBgTCgBkBQJm9hV8FiEEbl5LG/ylUJ5JLf5a++knEu5m290J
EPvpJxLuZtvdORQAAAAAABAAIHNhbHRAb3BlbnBncC5vcmdhjl/++3cYDd3wS3lVTUFAe6i1L+D6
QhQED7WfaPg5EgIbDAAAzVoCCQE++nSJnlE4nC7zlKW1RzL9LWx7OoanDFP/0yK//ATlGB6ptxxX
KTpDIslOqpcR3J6UvleScn6ZyDtWBPMZKZmscQIHSQFNtEVzEK9y8HuOCKoCQf2F3AB4Q54TbZ3n
PYu5YoAKY4Z97M+nNMq8TBJa1biPh9r8xrCFHYF2Bwgb6wYg5V0=
=0GZt
-----END PGP PRIVATE KEY BLOCK-----
EOT;
$ecDsaPrivateKey = OpenPGP::decryptPrivateKey($keyData, $passphase);

$keyData = <<<EOT
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: PHP Privacy v1
Comment: https://github.com/web-of-trust/php-privacy

xYYEZvYVfBYJKwYBBAHaRw8BAQdAovX6ZsqDSbfNMBHDpHzz8aSSrglOxFCHSW8Yi53Hckj+BwMI
oTYyS/ah84XgPwPOCCwK5b5svEYoM5cpokGs+gOq36N6MB6LDkWb0Y7yCn7tihAbYn8x53T1Mq/n
M1ZBN/x/buJA73lFBbgQqO2mqcT3Cs0qTmd1eWVuIFZhbiBOZ3V5ZW4gPG5ndXllbm52MTk4MUBn
bWFpbC5jb20+wsAHBBAWCgB5BQJm9hV9FiEE8Sy4irnSeys+lGJ+lX7WX5reQwwJEJV+1l+a3kMM
ORQAAAAAABAAIHNhbHRAb3BlbnBncC5vcmdgI8GrdjAB0oZSquh/8KpVA9CUr7Fppv2CmyXvcdCf
RQIbAwQLBwgJAxUICgUWAAECAwIeAwIZAQAAD40BAEcZGlC7JLfJ+pxmqqLPcBLJRuvK6yQe3fTb
c4QaFqhDAQAXqBX4rfDuIgzFKpXrxo0YYwf1jCHCivfDIlYnS2rnDs0sTmd1eWVuIFZhbiBOZ3V5
ZW4gPG5ndXllbm52QGl3YXl2aWV0bmFtLmNvbT7CwAQEEBYKAHYFAmb2FX0WIQTxLLiKudJ7Kz6U
Yn6VftZfmt5DDAkQlX7WX5reQww5FAAAAAAAEAAgc2FsdEBvcGVucGdwLm9yZ+qxz9FXFSMP03WE
C86oTeGqGwARkIWvSH8/LCr4pQf5AhsDBAsHCAkDFQgKBRYAAQIDAh4DAAD3/AEA3/wdNMvSlhTI
Af3L8Vj1xfixbSm1/8CwwPvwnlte6WYBAEY3UaT58tqVPGdd8pExkLKLbXV8x74cde8HsPLI3DoL
x4sEZvYVfRIKKwYBBAGXVQEFAQEHQHDc4Zj2OfUXYqOIIhroSdtGljARj8hYNatd3mS2etM3AwAI
B/4HAwj9fT+WFxC1S+DlvxXFWPi5JPGkf+6VCldZNHACG7IYJne1IhIBQAFMoLSqIeyqcLgDDHld
a+r6NyNiH0agrCvJYZH34sGUFtJ+3WWAUONswrIEGBYKAGQFAmb2FX0WIQTxLLiKudJ7Kz6UYn6V
ftZfmt5DDAkQlX7WX5reQww5FAAAAAAAEAAgc2FsdEBvcGVucGdwLm9yZ5ztze6WBWpOk2gxiAm7
HauMjkbG50Q0ZE0eijifVJ6mAhsMAAD9YAEAot0MgBly44gvozP3Yml9q46bpmWhoLYxB1QZP6vc
7IEBALvtZN+DuLSvcmS53C8khCI5+vDt0WHiWqpH9SPFifsC
=QN3m
-----END PGP PRIVATE KEY BLOCK-----
EOT;
$edDsaPrivateKey = OpenPGP::decryptPrivateKey($keyData, $passphase);

echo "Sign & encrypt literal data message:" .
    PHP_EOL .
    PHP_EOL;
$literalMessage = OpenPGP::createLiteralMessage(random_bytes(10000));
$encryptedMessage = OpenPGP::encrypt(
    $literalMessage,
    [
        $rsaPrivateKey->toPublic(),
        $dsaPrivateKey->toPublic(),
        $ecDsaPrivateKey->toPublic(),
        $edDsaPrivateKey->toPublic(),
    ],
    [$passphase],
    [$rsaPrivateKey, $dsaPrivateKey, $ecDsaPrivateKey, $edDsaPrivateKey]
);
echo $armored = $encryptedMessage->armor() . PHP_EOL;

echo "Decrypt with passphase & verify signatures:" . PHP_EOL . PHP_EOL;
$literalMessage = OpenPGP::decrypt($encryptedMessage, passwords: [$passphase]);
$verifications = $literalMessage->verify([
    $rsaPrivateKey->toPublic(),
    $dsaPrivateKey->toPublic(),
    $ecDsaPrivateKey->toPublic(),
    $edDsaPrivateKey->toPublic(),
]);
foreach ($verifications as $verification) {
    echo "Key ID: {$verification->getKeyID(true)}" . PHP_EOL;
    echo "Signature is verified: {$verification->isVerified()}" .
        PHP_EOL .
        PHP_EOL;
}

echo "Decrypt with rsa key & verify signatures:" . PHP_EOL . PHP_EOL;
$literalMessage = OpenPGP::decrypt($encryptedMessage, [$rsaPrivateKey]);
$verifications = $literalMessage->verify([
    $rsaPrivateKey->toPublic(),
    $dsaPrivateKey->toPublic(),
    $ecDsaPrivateKey->toPublic(),
    $edDsaPrivateKey->toPublic(),
]);
foreach ($verifications as $verification) {
    echo "Key ID: {$verification->getKeyID(true)}" . PHP_EOL;
    echo "Signature is verified: {$verification->isVerified()}" .
        PHP_EOL .
        PHP_EOL;
}

echo "Decrypt with dsa key & verify signatures:" . PHP_EOL . PHP_EOL;
$literalMessage = OpenPGP::decrypt($encryptedMessage, [$dsaPrivateKey]);
$verifications = $literalMessage->verify([
    $rsaPrivateKey->toPublic(),
    $dsaPrivateKey->toPublic(),
    $ecDsaPrivateKey->toPublic(),
    $edDsaPrivateKey->toPublic(),
]);
foreach ($verifications as $verification) {
    echo "Key ID: {$verification->getKeyID(true)}" . PHP_EOL;
    echo "Signature is verified: {$verification->isVerified()}" .
        PHP_EOL .
        PHP_EOL;
}

echo "Decrypt with ec dsa key & verify signatures:" . PHP_EOL . PHP_EOL;
$literalMessage = OpenPGP::decrypt($encryptedMessage, [$ecDsaPrivateKey]);
$verifications = $literalMessage->verify([
    $rsaPrivateKey->toPublic(),
    $dsaPrivateKey->toPublic(),
    $ecDsaPrivateKey->toPublic(),
    $edDsaPrivateKey->toPublic(),
]);
foreach ($verifications as $verification) {
    echo "Key ID: {$verification->getKeyID(true)}" . PHP_EOL;
    echo "Signature is verified: {$verification->isVerified()}" .
        PHP_EOL .
        PHP_EOL;
}

echo "Decrypt with ed dsa key & verify signatures:" . PHP_EOL . PHP_EOL;
$literalMessage = OpenPGP::decrypt($encryptedMessage, [$edDsaPrivateKey]);
$verifications = $literalMessage->verify([
    $rsaPrivateKey->toPublic(),
    $dsaPrivateKey->toPublic(),
    $ecDsaPrivateKey->toPublic(),
    $edDsaPrivateKey->toPublic(),
]);
foreach ($verifications as $verification) {
    echo "Key ID: {$verification->getKeyID(true)}" . PHP_EOL;
    echo "Signature is verified: {$verification->isVerified()}" .
        PHP_EOL .
        PHP_EOL;
}
