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
    UserIDPacketInterface
};

/**
 * OpenPGP User class
 * 
 * @package   OpenPGP
 * @category  Key
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class User implements PacketContainerInterface
{
    /**
     * Constructor
     *
     * @param KeyInterface $mainKey
     * @param UserIDPacketInterface $userID
     * @param array $selfCertifications
     * @param array $otherCertifications
     * @param array $revocationSignatures
     * @return self
     */
    public function __construct(
        private readonly KeyInterface $mainKey,
        private readonly UserIDPacketInterface $userID,
        private readonly array $selfCertifications = [],
        private readonly array $otherCertifications = [],
        private readonly array $revocationSignatures = []
    )
    {
    }

    /**
     * {@inheritdoc}
     */
    public function toPacketList(): PacketList
    {
        return new PacketList([
            $this->userID,
            ...$this->revocationSignatures,
            ...$this->selfCertifications,
            ...$this->otherCertifications,
        ]);
    }
}
