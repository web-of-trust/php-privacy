<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use phpseclib3\Math\BigInteger;

use OpenPGP\Enum\HashAlgorithm;
use OpenPGP\Enum\SymmetricAlgorithm;
use OpenPGP\Helper;

/**
 * ECDH public parameters class
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class ECDHPublicParameters extends ECPublicParameters
{
    /**
     * Constructor
     *
     * @param string $oid
     * @param BigInteger $q
     * @param HashAlgorithm $kdfHash
     * @param SymmetricAlgorithm $kdfSymmetric
     * @return self
     */
    public function __construct(
        string $oid,
        BigInteger $q,
        private HashAlgorithm $kdfHash,
        private SymmetricAlgorithm $kdfSymmetric,
        private int $reserved = 0
    )
    {
        parent::__construct($oid, $q);
    }

    /**
     * Reads parameters from bytes
     *
     * @param string $bytes
     * @return ECDHPublicParameters
     */
    public static function fromBytes(string $bytes): ECDHPublicParameters
    {
        $length = ord($bytes[0]);
        $oid = substr($bytes, 1, $length);
        $q = Helper::readMPI(substr($bytes, $length + 1));
        $kdfBytes = substr($bytes, $q->getLengthInBytes() + $length + 1);
        return ECDHPublicParameters(
            $oid,
            $q,
            ord($kdfBytes[1]),
            HashAlgorithm::from(ord($kdfBytes[2])),
            SymmetricAlgorithm::from(ord($kdfBytes[3]))
        );
    }

    /**
     * Gets kdf hash
     *
     * @return HashAlgorithm
     */
    public function getKdfHash(): HashAlgorithm
    {
        return $this->kdfHash;
    }

    /**
     * Gets kdf symmetric
     *
     * @return SymmetricAlgorithm
     */
    public function getKdfSymmetric(): SymmetricAlgorithm
    {
        return $this->kdfSymmetric;
    }

    /**
     * Gets reserved
     *
     * @return int
     */
    public function getReserved(): int
    {
        return $this->reserved;
    }

    /**
     * {@inheritdoc}
     */
    public function encode(): string
    {
        return implode([
            parent::encode(),
            chr($this->reserved),
            chr($this->kdfHash->value),
            chr($this->kdfSymmetric->value),
        ]);
    }
}
