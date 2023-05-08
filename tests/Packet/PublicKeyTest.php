<?php declare(strict_types=1);

namespace OpenPGP\Tests\Packet;

use OpenPGP\Packet\PublicKey;
use OpenPGP\Packet\PublicSubkey;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for Public key packet.
 */
class PublicKeyTest extends OpenPGPTestCase
{
    public function testRSAPublicKey()
    {
        $data = <<<EOT
BGRUrD4BCACe8iv48dGvqnbOuPv1DnnrasH/NZ5bbpGHW0gSOXb4p2d7VcfA6hfoyq1yEuZ2VDzJ
WpkhVnKMF1Ytj7d8mtnGsTQ6NfGrV9jRhGIxAYIgiDjzuhIejzMrTR/RAh9aARPTuEayRXoShTEg
cQfZxIQKwwU5hE4PDZFhq0h/T83eImWidUZwt3zw6jWq29nDtmtR96x+xznG0utZrHsbkxNtuLpX
YlrMl9Lcz9vbntpK45aq35P3cfg5UEjCLj1TAq6LPFnfiwbQcNkbsTRsxPqWpX4J6v5ZabJIFGyd
K14eiohYTbp7Uvr/e3yRhTirWYz4KnJwuFOsemuSjSAGi3C5ABEBAAE=
EOT;
        $publicKey = PublicKey::fromBytes(base64_decode($data));
        $this->assertSame('fc5004df9473277107eaa605184d0dc4f5c532b2', bin2hex($publicKey->getFingerprint()));
        $this->assertSame('184d0dc4f5c532b2', bin2hex($publicKey->getKeyID()));
    }

    public function testRSAPublicSubkey()
    {
        $data = <<<EOT
BGRUrD4BCACyRTYWSBsXFtxLOmSp3RvaW13GRh8HJ4p7adVqJpDBsvo8iInDgBt542/aoWDGIESA
MHBMlyq+QLfPuvPg187E0nsi1fh+P6sJ+gjNjSibyDdsBjHW6ZDksoB7lO5NhSCnzo63kMlP7QBH
hvOWaZSUHG3JqCsdElDSHkMrHpVzpyco+bTs7XK/E1iS0kC32yE7ShV/rltvl8hUKZF1npG3ytka
fegaEYESkM32/vygrCOWNC1Tea7kWe1A0+/ZYbgPh3blorNGICkUqiKfST9Xq26Lb67Kc38Gxjij
X9LAnOoxEyCjmCv/+ajNIDvMSQOtnTCapLpRrhLlzjvIDtOnABEBAAE=
EOT;
        $publicSubkey = PublicSubkey::fromBytes(base64_decode($data));
        $this->assertSame('42badbbe0f2acabacd6cac7c4be1b3a621ef906f', bin2hex($publicSubkey->getFingerprint()));
        $this->assertSame('4be1b3a621ef906f', bin2hex($publicSubkey->getKeyID()));
    }
}
