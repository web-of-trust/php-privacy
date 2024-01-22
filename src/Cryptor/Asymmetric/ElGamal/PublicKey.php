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
 * ElGamal public key class
 *
 * @package  OpenPGP
 * @category Cryptor
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class PublicKey extends ElGamal
{
    /**
     * Encryption
     *
     * @param string $plainText
     * @return string
     */
    public function encrypt(string $plainText): string
    {
        $prime = $this->getPrime();
        $input = Helper::bin2BigInt($plainText);
        if ($input->compare($prime) > 0) {
            throw new \InvalidArgumentException(
                'plain text too large for ' . self::ALGORITHM . ' cipher.'
            );
        }

        $byteLength = Helper::bit2ByteLength($this->getBitSize());
        $one = new BigInteger(1);
        do {
            $k = BigInteger::randomRange($one, $prime->subtract($one));
            $gamma = $this->getGenerator()->modPow($k, $prime);
            list(, $phi) = $input->multiply(
                $this->getY()->modPow($k, $prime)
            )->divide($prime);
        } while (
            $gamma->getLengthInBytes() < $byteLength ||
            $phi->getLengthInBytes() < $byteLength
        );

        return implode([
            substr($gamma->toBytes(), 0, $byteLength),
            substr($phi->toBytes(), 0, $byteLength),
        ]);
    }

    /**
     * Return the public key
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
            pack('n', $this->getY()->getLength()),
            $this->getY()->toBytes(),
        ]);
    }
}
