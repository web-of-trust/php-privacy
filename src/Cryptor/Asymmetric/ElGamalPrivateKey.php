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
use OpenPGP\Common\Helper;

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
    public function getPublicKey(): ElGamalPublicKey
    {
        return new ElGamalPublicKey(
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
     * Returns the private key
     *
     * @param string $type
     * @param array<string> $options
     * @return string
     */
    public function toString($type, array $options = []): string
    {
        return json_encode([
            'p' => $this->getPrime(),
            'g' => $this->getGenerator(),
            'x' => $this->getX(),
            'y' => $this->getY(),
        ]);
    }
}
