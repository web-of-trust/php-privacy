
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

use OpenPGP\Packet\UserID;
use OpenPGP\Type\{
    ArmorableInterface,
    ContainedPacketInterface,
    KeyInterface,
    KeyPacketInterface,
    SignaturePacketInterface
};

/**
 * Abstract OpenPGP key class
 * 
 * @package   OpenPGP
 * @category  Key
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
abstract class AbstractKey implements ArmorableInterface, ContainedPacketInterface, KeyInterface
{
    /**
     * Constructor
     *
     * @param KeyPacketInterface $keyPacket
     * @param array $revocationSignatures
     * @param array $directSignatures
     * @param array $users
     * @param array $subkeys
     * @return self
     */
    public function __construct(
        private readonly KeyPacketInterface $keyPacket,
        private readonly array $revocationSignatures = [],
        private readonly array $directSignatures = [],
        private readonly array $users = [],
        private readonly array $subkeys = []
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
            ...$this->directSignatures,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyPacket(): KeyPacketInterface
    {
        return $this->keyPacket;
    }

    /**
     * {@inheritdoc}
     */
    public function isRevoked(
        ?SignaturePacketInterface $certificate = null,
        ?DateTime $time = null
    ): bool
    {
        $keyID = ($certificate != null) ? $certificate->getIssuerKeyID()->getKeyID() : '';
        foreach ($this->revocationSignatures as $signature) {
            if (empty($keyID) || $keyID === $signature->getIssuerKeyID()->getKeyID()) {
                if ($signature->verify(
                    $this->toPublic()->getKeyPacket(),
                    $this->keyPacket->getSignBytes(),
                    $time
                )) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function verify(string $userID = '', ?DateTime $time = null): bool
    {
        if ($this->isRevoked(time: $time)) {
            return false;
        }
        foreach ($this->users as $user) {
            $packet = $user->getUserIDPacket();
            if ($packet instanceof UserID) {
                if (empty($userID) || $packet->getUserID() === $userID) {
                    if (!$user->verify($time)) {
                        return false;
                    }
                }
            }
        }
        foreach ($this->directSignatures as $signature) {
            if (!$signature->verify(
                $this->toPublic()->getKeyPacket(),
                $this->keyPacket->getSignBytes(),
                $time
            )) {
                return false;
            }
        }
        return true;
    }
}
