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
use OpenPGP\Type\ContainedPacketInterface;

/**
 * OpenPGP sub key class
 * 
 * @package   OpenPGP
 * @category  Key
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class Subkey implements ContainedPacketInterface
{
    /**
     * Constructor
     *
     * @param KeyPacketInterface $keyPacket
     * @param KeyInterface $mainKey
     * @param array $revocationSignatures
     * @param array $bindingSignatures
     * @return self
     */
    public function __construct(
        private readonly KeyPacketInterface $keyPacket,
        private readonly KeyInterface $mainKey,
        private readonly array $revocationSignatures = [],
        private readonly array $bindingSignatures = []
    )
    {
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
