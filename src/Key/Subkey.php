<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Key;

use OpenPGP\Packet\PacketList;
use OpenPGP\Type\{
    KeyInterface,
    PacketContainerInterface,
    SubkeyPacketInterface
};

/**
 * OpenPGP sub key class
 * 
 * @package   OpenPGP
 * @category  Key
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class Subkey implements PacketContainerInterface
{
    /**
     * Constructor
     *
     * @param KeyInterface $mainKey
     * @param SubkeyPacketInterface $keyPacket
     * @param array $revocationSignatures
     * @param array $bindingSignatures
     * @return self
     */
    public function __construct(
        private readonly KeyInterface $mainKey,
        private readonly SubkeyPacketInterface $keyPacket,
        private readonly array $revocationSignatures = [],
        private readonly array $bindingSignatures = []
    )
    {
    }

    /**
     * Gets main key
     * 
     * @return KeyInterface
     */
    public function getMainKey(): KeyInterface
    {
        return $this->mainKey;
    }

    /**
     * Gets key packet
     * 
     * @return SubkeyPacketInterface
     */
    public function getKeyPacket(): SubkeyPacketInterface
    {
        return $this->keyPacket;
    }

    /**
     * Gets revocation signatures
     * 
     * @return array
     */
    public function getRevocationSignatures(): array
    {
        return $this->revocationSignatures;
    }

    /**
     * Gets binding signatures
     * 
     * @return array
     */
    public function getBindingSignatures(): array
    {
        return $this->bindingSignatures;
    }

    public function getExpirationTime(): DateTime
    {

    }

    public function isRevoked(
        ?SignaturePacket $signature = null,
        ?DateTime $time = null
    ): bool
    {
        return false;
    }

    public function verify(?DateTime $time = null): bool
    {
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function toPacketList(): PacketList
    {
        return new PacketList([
            $this->keyPacket,
            ...$this->revocationSignatures,
            ...$this->bindingSignatures,
        ]);
    }
}
