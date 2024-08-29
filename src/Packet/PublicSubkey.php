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
 * Implementation an OpenPGP sub public key packet (Tag 14).
 * 
 * See RFC 9580, section 5.5.1.2.
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
     * @param int $version
     * @param DateTimeInterface $creationTime
     * @param KeyAlgorithm $algorithm
     * @param KeyMaterialInterface $keyMaterial
     * @return self
     */
    public function __construct(
        int $version,
        DateTimeInterface $creationTime,
        KeyAlgorithm $algorithm,
        KeyMaterialInterface $keyMaterial,
    )
    {
        parent::__construct(
            $version,
            $creationTime,
            $algorithm,
            $keyMaterial,
        );
    }

    /**
     * {@inheritdoc}
     */
    public static function fromBytes(string $bytes): self
    {
        $publicKey = PublicKey::fromBytes($bytes);
        return new self(
            $publicKey->getVersion(),
            $publicKey->getCreationTime(),
            $publicKey->getKeyAlgorithm(),
            $publicKey->getKeyMaterial(),
        );
    }
}
