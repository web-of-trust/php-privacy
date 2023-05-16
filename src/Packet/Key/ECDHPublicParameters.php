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

use phpseclib3\Crypt\EC\PublicKey;
use phpseclib3\Math\BigInteger;

use OpenPGP\Common\Helper;
use OpenPGP\Enum\{HashAlgorithm, SymmetricAlgorithm};

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
    const DEFAULT_RESERVED = 0;

    /**
     * Constructor
     *
     * @param string $oid
     * @param BigInteger $q
     * @param HashAlgorithm $kdfHash
     * @param SymmetricAlgorithm $kdfSymmetric
     * @param int $reserved
     * @param PublicKey $publicKey
     * @return self
     */
    public function __construct(
        string $oid,
        BigInteger $q,
        private readonly HashAlgorithm $kdfHash,
        private readonly SymmetricAlgorithm $kdfSymmetric,
        private readonly int $reserved = self::DEFAULT_RESERVED,
        ?PublicKey $publicKey = null
    )
    {
        parent::__construct($oid, $q, $publicKey);
    }

    /**
     * Reads parameters from bytes
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        $offset = 0;
        $length = ord($bytes[$offset++]);
        $oid = substr($bytes, $offset, $length);

        $offset += $length;
        $q = Helper::readMPI(substr($bytes, $offset));

        $offset += $q->getLengthInBytes() + 2;
        $kdfBytes = substr($bytes, $offset);
        return new self(
            $oid,
            $q,
            HashAlgorithm::from(ord($kdfBytes[2])),
            SymmetricAlgorithm::from(ord($kdfBytes[3])),
            ord($kdfBytes[1])
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
    public function toBytes(): string
    {
        return implode([
            parent::toBytes(),
            "\x3",
            chr($this->reserved),
            chr($this->kdfHash->value),
            chr($this->kdfSymmetric->value),
        ]);
    }
}
