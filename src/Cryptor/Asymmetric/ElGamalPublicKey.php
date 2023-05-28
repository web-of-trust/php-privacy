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
 * ElGamal public key class
 *
 * @package    OpenPGP
 * @category   Cryptor
 * @author     Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright  Copyright © 2023-present by Nguyen Van Nguyen.
 */
class ElGamalPublicKey extends ElGamal
{
    /**
     * Encryption
     *
     * @param string $plainText
     * @return string
     */
    public function encrypt(string $plainText): string
    {
        $one = new BigInteger(1);
        $prime = $this->getPrime();
        $input = Helper::bin2BigInt($plainText);
        if ($input->compare($prime) > 0) {
            throw new \InvalidArgumentException('input too large for ' . self::ALGORITHM . ' cipher.');
        }

        $byteLength = ($this->getBitSize() + 7) >> 3;
        do {
            $k = BigInteger::randomRange($one, $prime->subtract($one));
            $gamma = $this->getGenerator()->modPow($k, $prime);
            list(, $phi) = $input->multiply($this->getY()->modPow($k, $prime))->divide($prime);
        } while ($gamma->getLengthInBytes() < $byteLength || $phi->getLengthInBytes() < $byteLength);

        return implode([
            substr($gamma->toBytes(), 0, $byteLength),
            substr($phi->toBytes(), 0, $byteLength),
        ]);
    }

    /**
     * Returns the public key
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
            'y' => $this->getY(),
        ]);
    }
}
