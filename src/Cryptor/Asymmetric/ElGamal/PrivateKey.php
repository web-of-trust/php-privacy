<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Cryptor\Asymmetric\ElGamal;

use phpseclib3\Math\BigInteger;
use OpenPGP\Common\Helper;
use OpenPGP\Cryptor\Asymmetric\ElGamal;

/**
 * ElGamal private key class
 *
 * @package  OpenPGP
 * @category Cryptor
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class PrivateKey extends ElGamal
{
    /**
     * Constructor
     *
     * @param BigInteger $x
     * @param BigInteger $y
     * @param BigInteger $prime
     * @param BigInteger $generator
     * @return self
     */
    public function __construct(
        private BigInteger $x,
        BigInteger $y,
        BigInteger $prime,
        BigInteger $generator,
    )
    {
        parent::__construct($y, $prime, $generator);
    }

    /**
     * Get private key value x
     *
     * @return BigInteger
     */
    public function getX(): BigInteger
    {
        return $this->x;
    }

    /**
     * {@inheritdoc}
     */
    public function getPublicKey(): PublicKey
    {
        return new PublicKey(
            $this->getY(), $this->getPrime(), $this->getGenerator()
        );
    }

    /**
     * Decryption
     *
     * @param string $cipherText
     * @return string
     */
    public function decrypt(string $cipherText): string
    {
        $one = new BigInteger(1);
        $outputSize = (int) (($this->getBitSize() - 1) / 8);
        $length = strlen($cipherText);

        $prime = $this->getPrime();
        $gamma = Helper::bin2BigInt(substr($cipherText, 0, (int) ($length / 2)));
        $phi = Helper::bin2BigInt(substr($cipherText, (int) ($length / 2)));
        list(, $m) = $gamma->modPow(
            $prime->subtract($one->add($this->getX())), $prime
        )->multiply($phi)->divide($prime);
        return $m->toBytes();
    }

    /**
     * Return the private key
     *
     * @param string $type
     * @param array<string> $options
     * @return string
     */
    public function toString($type, array $options = []): string
    {
        return implode([
            pack('n', $this->getPrime()->getLength()),
            $this->getPrime()->toBytes(),
            pack('n', $this->getGenerator()->getLength()),
            $this->getGenerator()->toBytes(),
            pack('n', $this->getX()->getLength()),
            $this->getX()->toBytes(),
            pack('n', $this->getY()->getLength()),
            $this->getY()->toBytes(),
        ]);
    }
}
