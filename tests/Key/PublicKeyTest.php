<?php declare(strict_types=1);

namespace OpenPGP\Tests\Cryptor;

use OpenPGP\Key\PublicKey;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for OpenPGP public key.
 */
class PublicKeyTest extends OpenPGPTestCase
{
    public function testReadRSAPublicKey()
    {
        $data = <<<EOT
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBGRUrD4BCACe8iv48dGvqnbOuPv1DnnrasH/NZ5bbpGHW0gSOXb4p2d7VcfA
6hfoyq1yEuZ2VDzJWpkhVnKMF1Ytj7d8mtnGsTQ6NfGrV9jRhGIxAYIgiDjzuhIe
jzMrTR/RAh9aARPTuEayRXoShTEgcQfZxIQKwwU5hE4PDZFhq0h/T83eImWidUZw
t3zw6jWq29nDtmtR96x+xznG0utZrHsbkxNtuLpXYlrMl9Lcz9vbntpK45aq35P3
cfg5UEjCLj1TAq6LPFnfiwbQcNkbsTRsxPqWpX4J6v5ZabJIFGydK14eiohYTbp7
Uvr/e3yRhTirWYz4KnJwuFOsemuSjSAGi3C5ABEBAAG0IXJzYSBwaHAgcGcga2V5
IDxwaHAtcGdAZHVtbXkuY29tPokBUQQTAQgAOxYhBPxQBN+UcydxB+qmBRhNDcT1
xTKyBQJkVKw+AhsDBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheAAAoJEBhNDcT1
xTKyCDoH/i7giNRzADdTN6Xg9rvXNjgzeG5bu0PwI+DBpMlQUz4R9FAbDE0WQ1zf
3Ou33QjIw3R679kI2IY/DX83wtDIxbnJfQM3V+xDOZk3Fq1U1ahefEqo2LS9VRs9
Lq79zW3HJfulJg4uYPTq3ORbC2Fyox58mazm8Q0SWWrZ9OJ00odQsqBmtJdpaJbN
PHhEwAz6FaUDsEaICbjkh1XjKwwg68uuse+H53Hc8yw2zTaRlXWsZL3VkJOuGJoQ
tZvhXw1Fn7dhC3IkqQHOAXvYQFhhxYXvg5wdX3koRPjm1fvbV2p9QmJsykehKVVN
QGgy9DFxuu4OHWxchOkwbBUE1wpijtW5AQ0EZFSsPgEIALJFNhZIGxcW3Es6ZKnd
G9pbXcZGHwcnintp1WomkMGy+jyIicOAG3njb9qhYMYgRIAwcEyXKr5At8+68+DX
zsTSeyLV+H4/qwn6CM2NKJvIN2wGMdbpkOSygHuU7k2FIKfOjreQyU/tAEeG85Zp
lJQcbcmoKx0SUNIeQyselXOnJyj5tOztcr8TWJLSQLfbITtKFX+uW2+XyFQpkXWe
kbfK2Rp96BoRgRKQzfb+/KCsI5Y0LVN5ruRZ7UDT79lhuA+HduWis0YgKRSqIp9J
P1erbotvrspzfwbGOKNf0sCc6jETIKOYK//5qM0gO8xJA62dMJqkulGuEuXOO8gO
06cAEQEAAYkBNgQYAQgAIBYhBPxQBN+UcydxB+qmBRhNDcT1xTKyBQJkVKw+AhsM
AAoJEBhNDcT1xTKyCMkH/jaRmE0o0g3s7HwlHYiLd+OSTqNIS5TXJpVeaooU1KVY
W1tnhAYzPlvUQ31x7q9GIj5xw5gfMQ+sLHRCspa4ikWQKox6NnM8lSZUQ2PZqXgM
TlkXRPTfHQzyyYlE4EvQFRtPVxRFoQXlJR6A8NfxlEqFeZfak/5GbeBJdDGZywTG
iiGObs+UtJ0nsMrOJE3heNYrfwA/Zomwjzu+27X522U3ckkto0+030sY92TijRIp
H2/hiOv4+pWW10v5OslKktJvT0n4vzKeaEsHDrRGbPmW+1oZR2l7hUkSI/mM/Dl7
sxvcbVqDydX9ng/v+FYvkaVHomV9fNVbxgDW6oKpHYM=
=82s/
-----END PGP PUBLIC KEY BLOCK-----
EOT;

        $publicKey = PublicKey::fromArmored($data);
        $this->assertSame('fc5004df9473277107eaa605184d0dc4f5c532b2', $publicKey->getFingerprint(true));
        $this->assertSame('184d0dc4f5c532b2', $publicKey->getKeyID(true));
        $this->assertSame(2048, $publicKey->getKeyStrength());

        $subkey = $publicKey->getSubKeys()[0];
        $this->assertSame('42badbbe0f2acabacd6cac7c4be1b3a621ef906f', $subkey->getFingerprint(true));
        $this->assertSame('4be1b3a621ef906f', $subkey->getKeyID(true));
        $this->assertSame(2048, $subkey->getKeyStrength());
        $this->assertTrue($subkey->verify());

        $user = $publicKey->getUsers()[0];
        $this->assertSame('rsa php pg key <php-pg@dummy.com>', $user->getUserID());
        $this->assertTrue($user->verify());

        $this->assertEquals($publicKey, PublicKey::fromArmored($publicKey->armor()));
    }

    public function testReadDSAPublicKey()
    {
        $data = <<<EOT
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
R3JqasbC8wY2k26FGxusArLY
=7rwT
-----END PGP PUBLIC KEY BLOCK-----
EOT;

        $publicKey = PublicKey::fromArmored($data);
        $this->assertSame('3e57913d5f6ccbdb9022f7dee3b11d642248a092', $publicKey->getFingerprint(true));
        $this->assertSame('e3b11d642248a092', $publicKey->getKeyID(true));
        $this->assertSame(2048, $publicKey->getKeyStrength());

        $subkey = $publicKey->getSubKeys()[0];
        $this->assertSame('420a452a98ea130c7747e0b2c0453c8aabe775db', $subkey->getFingerprint(true));
        $this->assertSame('c0453c8aabe775db', $subkey->getKeyID(true));
        $this->assertSame(2048, $subkey->getKeyStrength());
        $this->assertTrue($subkey->verify());

        $user = $publicKey->getUsers()[0];
        $this->assertSame('dsa php pg key <php-pg@dummy.com>', $user->getUserID());
        $this->assertTrue($user->verify());

        $this->assertEquals($publicKey, PublicKey::fromArmored($publicKey->armor()));
    }

    public function testReadEcP384PublicKey()
    {
        $data = <<<EOT
-----BEGIN PGP PUBLIC KEY BLOCK-----

mG8EZFh3tRMFK4EEACIDAwTdn+WYmsMadge9PvF7l6LzEV+wKysf7oCOZJ+1wkRg
IJPLgK6leW+nnBsUtDaSV24LZzT0vONQtUWfi5Ap0xpxhvtfRSMjarowsY/V+maD
uargXybJUnHqWS+kcrjjEOG0JmVjIHAtMzg0IHBocCBwZyBrZXkgPHBocC1wZ0Bk
dW1teS5jb20+iLMEExMJADsWIQQFwIVJLRT5CXbnwrayAtni6tpEDAUCZFh3tQIb
AwULCQgHAgIiAgYVCgkICwIEFgIDAQIeBwIXgAAKCRCyAtni6tpEDMW/AYC1apN+
QaOfn7p6Ghshc7dRJ3vo9vXI/6nXBrzPgc8+F2I3nikdbEE7Pv1Te9hFWXEBgNnn
jtam09jySUNqs0CrV70b1wM4sa3ZVBKx/O04uIMdC2qaopUsaxuX4BpR4iIqTbhz
BGRYd7USBSuBBAAiAwMEEWHAaBdPHihwch9e3b4VqOB89WeHI6fGWDLpKj6bJ/ME
1VbDPhf0DN0Nc1s1wntRUFb9OjS06I8YQVBIPdyegmsMZj9J/fa0qFkd2r3siXb2
x3zGqsxe1lvrYDVj9gDYAwEJCYiYBBgTCQAgFiEEBcCFSS0U+Ql258K2sgLZ4ura
RAwFAmRYd7UCGwwACgkQsgLZ4uraRAyrmwGAo/mljpkefOBz6/T0FV3R5V7hr68S
27q+hVOJTo3ld+CvvYvUiyQs3KohLKzULb1xAXoCWv57kl0kXZ14dPzoilKlxxYt
bdD/dzH9pEv/jSZT+qKSSrWalKQR09/qVMH3UrU=
=gJFE
-----END PGP PUBLIC KEY BLOCK-----
EOT;

        $publicKey = PublicKey::fromArmored($data);
        $this->assertSame('05c085492d14f90976e7c2b6b202d9e2eada440c', $publicKey->getFingerprint(true));
        $this->assertSame('b202d9e2eada440c', $publicKey->getKeyID(true));
        $this->assertSame(384, $publicKey->getKeyStrength());

        $subkey = $publicKey->getSubKeys()[0];
        $this->assertSame('7d5bfac8919d26290b28ec56c0b7b9c6bf5824b6', $subkey->getFingerprint(true));
        $this->assertSame('c0b7b9c6bf5824b6', $subkey->getKeyID(true));
        $this->assertSame(384, $subkey->getKeyStrength());
        $this->assertTrue($subkey->verify());

        $user = $publicKey->getUsers()[0];
        $this->assertSame('ec p-384 php pg key <php-pg@dummy.com>', $user->getUserID());
        $this->assertTrue($user->verify());
    }

    public function testReadEcBrainpoolPublicKey()
    {
        $data = <<<EOT
-----BEGIN PGP PUBLIC KEY BLOCK-----

mFMEZFhcwRMJKyQDAwIIAQEHAgMEcqHnF1ehN+Kejq+6VkHDh+XmUy0qDNch4b3O
Em4EiekTuA6XF6zTv8ljZv1ohSmHR8CS7XET6WM/kj/mkjmqtLQwZWMgYnJhaW5w
b29sIHAtMjU2IHBocCBwZyBrZXkgPHBocC1wZ0BkdW1teS5jb20+iJMEExMIADsW
IQQG/uMIXUbcAHwOwvAcvNBD20TF1gUCZFhcwQIbAwULCQgHAgIiAgYVCgkICwIE
FgIDAQIeBwIXgAAKCRAcvNBD20TF1sz3AP9S7zggjuhp6eW/cjmKWtZMXUf7rIEu
MZZGlhA/ZdTj8AEAopjyjTIgZE1nMYh043cvr2TB14P97t04BiYe4ledjGG4VwRk
WFzBEgkrJAMDAggBAQcCAwSDb4npzJxciSQm5RASdifbAWf4QgBxi24A2Twgvpky
6gySceO0qwd2YFpq8dTUaE9qUHw9qqmKPI0CSvF5YMqiAwEIB4h4BBgTCAAgFiEE
Bv7jCF1G3AB8DsLwHLzQQ9tExdYFAmRYXMECGwwACgkQHLzQQ9tExdbFLAD/RfCg
dSmSQpsw8be1EPidj4aJivLRVaG1JifMzod6GG0A/i6NRj2AL+UeKRDJiPA3euPW
gqc+cgcSrumboIKbe+E6
=wjEj
-----END PGP PUBLIC KEY BLOCK-----
EOT;

        $publicKey = PublicKey::fromArmored($data);
        $this->assertSame('06fee3085d46dc007c0ec2f01cbcd043db44c5d6', $publicKey->getFingerprint(true));
        $this->assertSame('1cbcd043db44c5d6', $publicKey->getKeyID(true));
        $this->assertSame(256, $publicKey->getKeyStrength());

        $subkey = $publicKey->getSubKeys()[0];
        $this->assertSame('457b5979545fba09be179db808a55bdb1d673d5d', $subkey->getFingerprint(true));
        $this->assertSame('08a55bdb1d673d5d', $subkey->getKeyID(true));
        $this->assertSame(256, $subkey->getKeyStrength());
        $this->assertTrue($subkey->verify());

        $user = $publicKey->getUsers()[0];
        $this->assertSame('ec brainpool p-256 php pg key <php-pg@dummy.com>', $user->getUserID());
        $this->assertTrue($user->verify());
    }

    public function testReadEcCurve25519PublicKey()
    {
        $data = <<<EOT
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEZFhdBRYJKwYBBAHaRw8BAQdAu9HRWiJVK3f7HPFJJCtHv/KszNAbw5e54yEi
RBvRQ8y0KWN1cnZlIDI1NTE5IHBocCBwZyBrZXkgPHBocC1wZ0BkdW1teS5jb20+
iJMEExYKADsWIQQcQRbrK1jPoZbFfdu9/xNRYMVqCwUCZFhdBQIbAwULCQgHAgIi
AgYVCgkICwIEFgIDAQIeBwIXgAAKCRC9/xNRYMVqC/i9AP9r3z0aFMwMq6jDAA88
wj0gsm8QjuC1eMebqYvPzDnj6AEAy1O9BM3ZB9tpFmNeHCNehfiWtguZ+in50oyc
U+KVZQm4OARkWF0FEgorBgEEAZdVAQUBAQdAQm1BTahWSqRSwQd9/XGa6e7naL6I
b1TIhu6j/foo+gEDAQgHiHgEGBYKACAWIQQcQRbrK1jPoZbFfdu9/xNRYMVqCwUC
ZFhdBQIbDAAKCRC9/xNRYMVqCywFAP0YmwkXy3mY5abLlf8wKLGeb/pOOGVIwOIR
1qitYcgShwD/WPr8SbRnlwunKrHo9foigZpPevI0hhxruX8E76bzOA8=
=MWpN
-----END PGP PUBLIC KEY BLOCK-----
EOT;

        $publicKey = PublicKey::fromArmored($data);
        $this->assertSame('1c4116eb2b58cfa196c57ddbbdff135160c56a0b', $publicKey->getFingerprint(true));
        $this->assertSame('bdff135160c56a0b', $publicKey->getKeyID(true));
        $this->assertSame(255, $publicKey->getKeyStrength());

        $subkey = $publicKey->getSubKeys()[0];
        $this->assertSame('8efa53a375fc569aa9ca564a044eac93f0b69ea0', $subkey->getFingerprint(true));
        $this->assertSame('044eac93f0b69ea0', $subkey->getKeyID(true));
        $this->assertSame(255, $subkey->getKeyStrength());
        $this->assertTrue($subkey->verify());

        $user = $publicKey->getUsers()[0];
        $this->assertSame('curve 25519 php pg key <php-pg@dummy.com>', $user->getUserID());
        $this->assertTrue($user->verify());
    }
}
