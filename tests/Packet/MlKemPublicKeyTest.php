<?php declare(strict_types=1);

use OpenPGP\Enum\KeyAlgorithm;
use OpenPGP\Packet\PublicSubkey;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for MlKem public key packet.
 */
class MlKemPublicKeyTest extends OpenPGPTestCase
{
    public function testV6MlKem768PublicKey()
    {
        $data = <<<EOT
Bmd0hYAjAAAEwCIVC0MM9yTsGbi+Vd+byq3jJwhXETaUBKV1yAI0Q7BfXkJC3YN0sGULB1LIvZBS
lFEx/9op4ncn+0J9IKeKzuu449mu2UdNA/XK+5wl+sGGdTVNrJq3s7R/BktVNWBMG0t+eYBtItQa
xwYucsOntcO344uH1BA+ZHIALxsHN6KrZPCeqfF9ppTB8UAlvVR0JATPtyyuxFw6MUex06GlYzir
MXafH8jK5KqZJbjBKWwPo7bIsBBbLpqk9yQxb7YYJ6VQMGkitrRwWNwQxTGDTee8/FyUMIYklGMe
wmG65RkKrBMKICsBX7lD1cQ7fisEp7Y+WoOVqass6FuOWKJLIhyrg+A93oUsNBhGz/iEgJehP2g8
AQPNMnO+IicgIwQdV+YJRreWKvQosYMHxtopQRWKRXmmrGKPFYeozvoo6qR+JImvIDgy0gV/eEun
8iVoQbxuBXPIQXJOicOFPiWjXisG/0G3rOyRE9o0ivlxZPku2qKayfFtMwxbNWg54ieV/uRfrjRR
HOnL0SaxigY8N0FIwaTB4uMeyqphG+Ri7nSgnLVxaES9/tzNiKlgsuAuC5k7E+XPAonGy9Ikm+oH
J9hg0XKNzvyNR/uwWhB2WFmFDRB3ldVE3/whLLe7yPmptIFWZ3J2LaaFqTyUhoNW6spRkUWeNMgo
3MxRS3QgmBGXqou6/7RT2tdVrWIY8WJO5SmMnZcrJ6oX3qKYgFiJJgCTuUegr/cNNJNLE/shyedk
dxfG6jaQSzrLxOWg0fBHtrd1snWWryCofwi7ray3HjNnKjNddfiChjWkLpu5H2dYM/CzdnmmOlk9
71vJgeZ6SrivUlwLTHDIkVqVr5F+iPXHU+Wd6hcUxrIH4eUXTJFIUYiamSqb35cgAAzOBBS/DKwD
46pOURchwRNRUbu47qiJE4AT6Ia0dTFkCSRezaJXBNe9+oisPDctQTx/VZaktkvK4hc+DLwuMiQu
QMoev0CgzLlr7XpxvCaEGYOiFTJydFtlhepmheZ3k0puE5lY8AOJBEd1PKPEDzwqD0wOBxaMTEQG
iPqH39ENs4q08BcOXjANqwtjxVotJIurlBcxgsZ16RZOyiaRcCs358AMrExMScNfU+HBIONqxRkz
CPOqn3sCMzQO+dwJuxNUoEYDcUAtYos8+1BdaHvGaeNMY3EuxQWeAJQEN4dpYfe29qlcYOwcHRtY
osmLc7OaHMQ7wnCzdJeyiHobAIgVZGZvAyW6w9cTlQd2pTdsDgSmO8or69gYPKxsmLeib3Joytej
tBhnaexyfeCFhksHzJlu48l65fDFE3h5Pmqj8vRGfFik2qbIzrU11ala/IiJD7RnwTQCYuO++yKB
a7rC1qXCXBFZixBwwTavHeEAPNnMmWxDfna2frNnFKRodDaTM7o76Gs7rgTIeLAzQfZih1yAJpSw
jEcVDZdIRaRTrkK/4PJzVHGb4wwkOwfLoPEBCMuAYTxfqJVEgdBi6pUsPaEOQzkUeIeOVgoFnMhP
3+N22fMWkCBc/LYOThtPXFWtHkq5jmmj+aiuyGOaadccBKWTvxloBly25QADfbYI2oImtVu1JDjF
Cf6PQ74UWSEf9EvmTgsMQq/TPICLDUyoTkteLTQ=
EOT;
        $publicSubkey = PublicSubkey::fromBytes(base64_decode($data));
        $this->assertSame(
            "dafe0eebb2675ecfcdc20a23fe89ca5d12e83f527dfa354b6dcf662131a48b9d",
            $publicSubkey->getFingerprint(true)
        );
        $this->assertSame(KeyAlgorithm::MlKem768X25519, $publicSubkey->getKeyAlgorithm());
        $this->assertSame(6, $publicSubkey->getVersion());

        $data = <<<EOT
Bmd0hYAjAAAEwI0Zdym6JJULp436Pqz8uyX9pPdFy1hhWsOTRlnBQ+pdgVpfW8iNNfeB4Fe7mRqa
Z4p734q7vBseXUO0G2x3E1oX5fSwokNpcokbF4SAoeXIQUKOpixgarMcSWsR5TBF0ps5xdGuuclH
J1pXbOOcItoYotpn+TgrPHrMIXnNifymIWywENLLkggcelpQe+gcYPVv8JfP73EvtujPfTIl2nbK
rnxFnCWMWCp0p2VPnaumTQkdIWwSOEGXgYwZzks3zTmYICtFLOsTpUqnqVox1ANu4lNB0NKyi+XM
x9FQinOwslhYvjU59hh6AXNm95VhEndWWVQ2UdCwgRWrcyoCKSiuTTCanWfPzfK1MRJ2ChpElXt3
EmGB/lKVnWzIYpgriBfGwAtu8sOxFhq3yoGkm2pXSjW+6eubYfeiQlXJk/cHuqlz7dlFWkNwnrOh
Tsws6PkV75MEDtuxO8wagcm6ElzOSHvKjlst6sxct8xnq/hGkqxMr/kTb4NKHXSQh6thIWjCmaon
IKwmOxujWIos1jupAdWW9oB8m1GkmqCA8lqZJTjCbelopONuXOgxy5S7MvUe9TDGvwc3iAxnE1WD
jtDIDyl1YokknFKR7fOFYlozgwhPqKU2Umgg5yTDKthnlTfO48QBDssLgcu2NTAcCdkGR7KWRNO4
vAPPR+JCGkq2/htDNCsQpLKXNJhp5+FsIeDIqcc3FmgiOKxpfuMXfbhOS+qwYCV2+xdQ4yilSVS6
BotRxTI7uYyrlctCH9IbKAYFr2lNbGRvSEt1lxYfs2qjMcZ4bLdnafpun6kEmsII3tRwxAlcNftS
uAQ6U1UQziR9dDl+U1q6DaAatSu4RFRAHFBx+0ISIPtVcuGGLfp7YqQ+wmBuH6wlXzKGgfIeALeR
ISCRACx7iDasAMN9HOd2cmi8XgJJH3KCxJmKhsZWuadcGwQ7kooC4mQt61IyzHNz28Fx29awDCiI
aVi+yNAAkcd4mYE6lyFjE8guI3vCI7e4JrlW1Cw8znFQ/6oRULxruiYDGqmap7i6zinF/mVRlHqw
00IaQOUiZTiLzitVKKpWRJFxRkpP8fkq1GgwQNIQtxAv/ZVv6DN/CVaqDlIEmHzFUww4ykq0udU2
FZaH7myi2DEykRZpsROkYrx4QoUuugQxmBomnlyA5jcDTelG6cpTfrjIxtmOr7SYtKNkXroxiQpX
PyEgsFWnHhBgUywGBpBROTZV85Rr/ZtD/hyyYml5adspyFbOZBLP3KBGMjWAMPCZgpp8yLq9lUiS
oaiqfDSYnVwRdeAbXUUauUBD0iqFHvIEtEYY05dY3xTI0aUelLcu9eYwFKtgC8BA+ml25JQNN8bO
7XieAQI8QBtjh5SejRcuCJpes1MF36cbp0G6fHhkb5JxqLfI35YtFueZ5CqjLVtD2rpRwJwmvBm+
V1NXvmpDzzCpeVp5vaK8THHDoZZ1MGUJ8KCDlPy1XkOrheeTdXa6OQJaQBqFPAo5VSka1WDE0uMq
L9F7iUB9n6G6n4drCWZLp/JdwjafSwcrpzM3mGuB9hiyvmu/1awTnwehOtaozpJ7O4rBLJQRa0wz
cXTdmQsFve0SYZxEQT1XdobWDoAVsV1SWu1ngys=
EOT;
        $publicSubkey = PublicSubkey::fromBytes(base64_decode($data));
        $this->assertSame(
            "7dae8fbce23022607167af72a002e774e0ca379a2d7ae072384e1e8fde3265e4",
            $publicSubkey->getFingerprint(true)
        );
        $this->assertSame(KeyAlgorithm::MlKem768X25519, $publicSubkey->getKeyAlgorithm());
        $this->assertSame(6, $publicSubkey->getVersion());
    }

    public function testV4MlKem768PublicKey()
    {
        $data = <<<EOT
BGd0hYAjsIfqoDHr3VUD76sj9JP+04jzHeAhTXnoPF3N7Cs281UB+Awo6DCHkI8GuMzoPE4BOsuY
u1RyWZL7xZTGtTqua8iSHLRoqLppdL7u0M5IUafYaacURmnGARVgK6FvljpMVX33rAn3yzAV2STM
ln8wxhRJ2Qol0Ss+m4L2hyt74h0a05D9M8Iyl2J+w8G54jmcaRxmNoBlOnesM052o7TlwcZjwKJ2
po1Uw8SNqoqAKUBnu5wA87MfJ699igCog2mT8De1W7VA5V4mhWkk3IaGUG+Yahrox3Kx1Vgeeg3d
9grjNZAHCMJEt8wFKmH+Ca8GNljDAEOGQrDsFzZz0Lg7Gx/96Wuv2gNktLCgPHS+ZHn3J6pXe5kl
pWA8oFi9uLkj2JHyeqG7x1KvK3MQFb4RjJbBIE5GKkdQ0xLA+I6vwr5wBm4li27Xps81NwvwSmHl
U0bvOCl4Bwdcp7gqQ0t6JX0qs18jW8Du5l08FgTYBT3qHEwj9BezKqVCUqfXG7bR+DoN+CR4kxZx
Wa/EhXmvqhxJGllP2G+QQFSS2Zn6SFXf58OaMswI1jEPu4RjbEK698d8JiFuKXUAsH1MfGdF5aXw
5rUF4wYIBA9yUjsukD5dhGdPRxeD4hdCSiZjKTEFdDnSZwMTiSx8AFE04w2jR8OKCiN+g8TtBzYq
10TAARs29D0thFAuMr9dkYFbFAXdIFgCYl9w1Rpwg6QwpWJl+lUTc6+QiXTq+qRjQq4zIHv3KBf3
y8PM9VsWhISCqrbtRXlqQylRARExSg0eqA8pIm1n0WdpWpRDNmNERsRDy8ksBpjEskLuOn2/syUr
Gz8IKipIgWx/KURsUQDOdkWoa2gboXlf7CsD+oVemcK3YWPoa0G2WVHlLCDrNr/Yl86e120PeDDm
bKKBxY9xSwF/sZu5K3/mGYBwUmZdfGty1nOexsr0agYZSkEjBkRCWYJYqi+BswClWxr61kpYxL6a
K5HyCMvoGAa8BbIyp4ZXKXFn61KoW8UtUzUcVcZ7cnD6KwQDCgvt8zklmbraF6fCZx18gSgKJ6Eq
DBc8xM91jItq5rAonI6OyZ1pAGHNp0ucMwD2h5INVcpG5Svbcbgp8g4Nhb2YC6SbGsrMYg7r56vq
4V+PAWToljJbRZZYg86SDMnN2B7vtGIZ7EzerETOqs5FIXyENGku5MB/dswa+0qDZZJd4SvIAx4Q
ZBMD0btXIFYOVZVGsKDfl2aqQrz9dFzWGBWdukVEK1fupVeqNLSRGrunEUtuM0+duXgr+R9opk96
lAIdyiarBgglwnoE98KrWbg3VQoxpkWisiOEQZlnx6h84WUzoCDmtiNOSwGyOR0BekNxwAy3aA3b
gX1hUBk4pH1OlEK7M2w9EiVXu23Ka0dBrGJPoIgcBcbAQyC34CeptLxHfLJK1jYkt8JlEM29EUpt
hHK5mm4ACbMi6hSaKY2zhDp2NGAXBGTW8DZDdHhWIZtfdgjC9cExwJ1Y+Q5jOkhSAodehgXFEmkJ
J8diLIEr8R7aoE/BRIGgsl/P9TOoSziAukuR022b9VpaxFmAw5VKwR1p+LGSO5NNk8pHNDHO8Z1v
q2ucB6XUJZP4+KPae2VsP3szXOt9s+Q8Mg==
EOT;
        $publicSubkey = PublicSubkey::fromBytes(base64_decode($data));
        $this->assertSame(
            "e51dbfea51936988b5428fffa4f95f985ed61a51",
            $publicSubkey->getFingerprint(true)
        );
        $this->assertSame(KeyAlgorithm::MlKem768X25519, $publicSubkey->getKeyAlgorithm());
        $this->assertSame(4, $publicSubkey->getVersion());
    }

    public function testMlKem1024PublicKey()
    {
        $data = <<<EOT
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
EOT;
        $publicSubkey = PublicSubkey::fromBytes(base64_decode($data));
        $this->assertSame(
            "65090e147a8116ab7f62ab4ec7aae59d9e6532feb2af230c73cdc869fbc60c8f",
            $publicSubkey->getFingerprint(true)
        );
        $this->assertSame(KeyAlgorithm::MlKem1024X448, $publicSubkey->getKeyAlgorithm());
        $this->assertSame(6, $publicSubkey->getVersion());
    }
}
