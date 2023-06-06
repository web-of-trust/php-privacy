<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use DateTimeInterface;
use OpenPGP\Enum\KeyAlgorithm;
use OpenPGP\Type\{
    KeyMaterialInterface,
    SubkeyPacketInterface,
};

/**
 * Public sub key packet class
 * 
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class PublicSubkey extends PublicKey implements SubkeyPacketInterface
{
    /**
     * Constructor
     *
     * @param DateTimeInterface $creationTime
     * @param KeyMaterialInterface $keyMaterial
     * @param KeyAlgorithm $algorithm
     * @return self
     */
    public function __construct(
        DateTimeInterface $creationTime,
        KeyMaterialInterface $keyMaterial,
        KeyAlgorithm $algorithm = KeyAlgorithm::RsaEncryptSign
    )
    {
        parent::__construct(
            $creationTime,
            $keyMaterial,
            $algorithm
        );
    }

    /**
     * Read public subkey packets from byte string
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        $publicKey = PublicKey::fromBytes($bytes);
        return new self(
            $publicKey->getCreationTime(),
            $publicKey->getKeyMaterial(),
            $publicKey->getKeyAlgorithm()
        );
    }
}
