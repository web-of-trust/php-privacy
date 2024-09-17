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
        private readonly BigInteger $x,
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
        $inputSize = Helper::bit2ByteLength($this->getBitSize()) * 2;
        $length = strlen($cipherText);
        if ($length > $inputSize) {
            throw new \RuntimeException(
                'Cipher text too large for ' . self::ALGORITHM . ' cipher.'
            );
        }

        $one = new BigInteger(1);
        $prime = $this->getPrime();
        $gamma = Helper::bin2BigInt(
            substr($cipherText, 0, (int) ($length / 2))
        );
        $phi = Helper::bin2BigInt(
            substr($cipherText, (int) ($length / 2))
        );
        list(, $m) = $gamma->modPow(
            $prime->subtract($one->add($this->getX())), $prime
        )->multiply($phi)->divide($prime);

        $outputSize = ($this->getBitSize() - 1) >> 3;
        return substr($m->toBytes(), 0, $outputSize);
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
