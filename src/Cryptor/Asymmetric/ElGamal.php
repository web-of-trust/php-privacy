<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Cryptor\Asymmetric;

use phpseclib3\Crypt\Common\AsymmetricKey;
use phpseclib3\Math\BigInteger;

/**
 * ElGamal class
 *
 * @package  OpenPGP
 * @category Cryptor
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
abstract class ElGamal extends AsymmetricKey
{
    /**
     * Algorithm Name
     */
    const ALGORITHM = "ElGamal";

    private readonly int $bitSize;

    /**
     * Constructor
     *
     * @param BigInteger $y
     * @param BigInteger $prime
     * @param BigInteger $generator
     * @return self
     */
    public function __construct(
        private readonly BigInteger $y,
        private readonly BigInteger $prime,
        private readonly BigInteger $generator
    ) {
        $this->bitSize = $prime->getLength();
    }

    /**
     * Create public / private key pair.
     * Return the private key, from which the publickey can be extracted
     *
     * @param int $lSize
     * @param int $nSize
     * @return ElGamal\PrivateKey
     */
    public static function createKey(
        int $lSize = 2048,
        int $nSize = 224
    ): ElGamal\PrivateKey {
        $one = new BigInteger(1);
        $two = new BigInteger(2);
        $q = BigInteger::randomPrime($nSize);
        $divisor = $q->multiply($two);
        do {
            $x = BigInteger::random($lSize);
            list(, $c) = $x->divide($divisor);
            $p = $x->subtract($c->subtract($one));
        } while ($p->getLength() != $lSize || !$p->isPrime());

        $p_1 = $p->subtract($one);
        list($e) = $p_1->divide($q);

        $h = clone $two;
        while (true) {
            $g = $h->powMod($e, $p);
            if (!$g->equals($one)) {
                break;
            }
            $h = $h->add($one);
        }

        $x = BigInteger::randomRange($one, $q->subtract($one));
        $y = $g->powMod($x, $p);
        return new ElGamal\PrivateKey($x, $y, $p, $g);
    }

    /**
     * Get public key value y
     *
     * @return BigInteger
     */
    public function getY(): BigInteger
    {
        return $this->y;
    }

    /**
     * Get prime p
     *
     * @return BigInteger
     */
    public function getPrime(): BigInteger
    {
        return $this->prime;
    }

    /**
     * Get group generator g
     *
     * @return BigInteger
     */
    public function getGenerator(): BigInteger
    {
        return $this->generator;
    }

    /**
     * Get bit size
     *
     * @return int
     */
    public function getBitSize(): int
    {
        return $this->bitSize;
    }
}
