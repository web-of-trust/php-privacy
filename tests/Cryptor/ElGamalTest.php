<?php declare(strict_types=1);

namespace OpenPGP\Tests\Cryptor;

use phpseclib3\Crypt\Random;
use phpseclib3\Math\BigInteger;
use OpenPGP\Cryptor\Asymmetric\ElGamal;
use OpenPGP\Cryptor\Asymmetric\ElGamalPrivateKey;
use OpenPGP\Cryptor\Asymmetric\ElGamalPublicKey;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for ElGamal public key algo.
 */
class ElGamalTest extends OpenPGPTestCase
{
    public function testKeyGeneration()
    {
        $one = new BigInteger(1);
        $two = new BigInteger(2);

        $privateKey = ElGamal::createKey();
        $prime = $privateKey->getPrime();
        $generator = $privateKey->getGenerator();
        $secretExponent = $privateKey->getX();
        $publicExponent = $privateKey->getY();

        // Check that 1 < g < p
        $this->assertTrue(
            $generator->compare($one) > 0 &&
            $generator->compare($prime) < 0
        );

        // Expect p-1 to be large
        $pSize = $prime->getLength();
        $this->assertTrue(
            $pSize > 1023
        );

        // g should have order p-1
        // Check that g ** (p-1) = 1 mod p
        $this->assertTrue(
            $generator->modPow($prime->subtract($one), $prime)->equals($one)
        );

        // Re-derive public key y' = g ** x mod p
        // Expect y == y'
        // Blinded exponentiation computes g**{r(p-1) + x} to compare to y
        $r = BigInteger::randomRange(
            $two->bitwise_leftShift($pSize - 1), $two->bitwise_leftShift($pSize)
        );
        $rqx = $prime->subtract($one)->multiply($r)->add($secretExponent);
        $this->assertTrue(
            $publicExponent->equals($generator->modPow($rqx, $prime))
        );

        $plainText = Random::string($prime->getLengthInBytes() - 1);
        $publicKey = $privateKey->getPublicKey();
        $encrypted = $publicKey->encrypt($plainText);
        $decrypted = $privateKey->decrypt($encrypted);
        $this->assertSame(bin2hex($plainText), bin2hex($decrypted));
    }

    public function testEncryption()
    {
        $prime = new BigInteger(
          '21842708581829896181355246474716153471799584702398145343781873612858268458790012658568509171208714431649208343296936349116172973580334664598762798393358559705621580042818388996849377434152861440023221391670968030831872591041152546055355390395164610169584848575897862985569697158568543863240507089993891556886557196474202323417190832644888994692005921518845406236886593318056471289387692729870131076001447553511077011608675277948641532603949929873743962633410696917376288603162134431896218895079026006444970460740888015606154190820808415464316451512185142037759825776982215354150775475714608377003555330213945294287583'
        );
        $generator = new BigInteger(5);
        $publicExponent = new BigInteger(
            '15590699273124096367845758349645226104138190024888407784287357837260359983637081328343487075505090749437978508505177973032496352672432943366064714761944186683268687737839702679962914617907849880272896027951360632795432278109768129193340345955504697749295122222309114553683024697759013607172925522796547740584824687858596370069179394322422986612767141828757141197590339291313205573787292371971283021600112532974909997630543606784003003770779526568284167901082742375947463384656907527559426381569970468966330515531538944216482677858434221351520007191681768077185259988739987157075690073689280587056931667283700771424191'
        );
        $secretExponent = new BigInteger(
            '1446296390097566101617671091884237397227201126182287254457502825594360365391017793839243843109598388819'
        );

        $publicKey = new ElGamalPublicKey($publicExponent, $prime, $generator);
        $privateKey = new ElGamalPrivateKey($secretExponent, $publicExponent, $prime, $generator);

        $plainText = Random::string($prime->getLengthInBytes() - 1);
        $encrypted = $publicKey->encrypt($plainText);
        $decrypted = $privateKey->decrypt($encrypted);
        $this->assertSame(bin2hex($plainText), bin2hex($decrypted));
    }
}
