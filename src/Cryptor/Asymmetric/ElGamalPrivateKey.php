<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Cryptor\Asymmetric;

use phpseclib3\Math\BigInteger;

/**
 * ElGamal private key class
 *
 * @package    OpenPGP
 * @category   Cryptor
 * @author     Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright  Copyright © 2023-present by Nguyen Van Nguyen.
 */
class ElGamalPrivateKey extends ElGamal
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
     * Gets private key value x
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
    public function getPublicKey()
    {
        return new ElGamalPublicKey($this->y, $this->prime, $this->generator);
    }

    /**
     * Decryption
     *
     * @param string $ciphertext
     * @return string
     */
    public function decrypt(string $cipherText): string
    {
        $inputSize = 2 * (($this->getBitSize() + 7) >> 3);
        $outputSize = (int) (($this->getBitSize() - 1) / 8);

        $length = strlen($cipherText);
        if ($length > $inputSize) {
            throw new \InvalidArgumentException('input too large for ' . static::ALGORITHM . ' cipher.');
        }

        $prime = $this->getPrime();
        $gamma = $this->bits2int(substr($cipherText, 0, (int) ($length / 2)));
        $phi = $this->bits2int(substr($cipherText, (int) ($length / 2)));
        list(, $m) = $gamma->modPow(
            $prime->subtract(self::$one->add($this->getX())), $prime
        )->multiply($phi)->divide($prime);
        return substr($m->toBytes(), 0, $outputSize);
    }

    /**
     * Returns the private key
     *
     * @param string $type
     * @param array $options optional
     * @return string
     */
    public function toString($type, array $options = [])
    {
        return json_encode([
            'p' => $this->getPrime(),
            'g' => $this->getGenerator(),
            'x' => $this->getX(),
            'y' => $this->getY(),
        ]);
    }
}
