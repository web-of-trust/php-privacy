
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

use OpenPGP\Enum\PacketTag;
use OpenPGP\Packet\UserID;
use OpenPGP\Type\{
    ArmorableInterface,
    ContainedPacketInterface,
    KeyInterface,
    KeyPacketInterface,
    PacketListInterface,
    SignaturePacketInterface,
    SubkeyPacketInterface,
    UserIDPacketInterface
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
    private array $revocationSignatures;

    private array $directSignatures;

    private array $users;

    private array $subkeys;

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
        array $revocationSignatures = [],
        array $directSignatures = [],
        array $users = [],
        array $subkeys = []
    )
    {
        $this->revocationSignatures = array_filter(
            $revocationSignatures,
            static fn ($signature) => $signature instanceof SignaturePacketInterface
        );
        $this->directSignatures = array_filter(
            $directSignatures,
            static fn ($signature) => $signature instanceof SignaturePacketInterface
        );
        $this->setUsers($users)->setSubkeys($subkeys);
    }

    /**
     * {@inheritdoc}
     */
    public function toPacketList(): PacketListInterface
    {
        $userPacketList = [];
        foreach ($this->users as $user) {
            $userPacketList = array_merge(
                $userPacketList, $user->toPacketList()->toArray()
            );
        }
        $subkeyPacketList = [];
        foreach ($this->subkeys as $subkey) {
            $subkeyPacketList = array_merge(
                $subkeyPacketList, $subkey->toPacketList()->toArray()
            );
        }

        return new PacketList([
            $this->keyPacket,
            ...$this->revocationSignatures,
            ...$this->directSignatures,
            ...$userPacketList,
            ...$subkeyPacketList,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyPacket(): KeyPacketInterface
    {
        return $this->keyPacket;
    }

    public function getRevocationSignatures(): array
    {
        return $this->revocationSignatures;
    }

    public function getDirectSignatures(): array
    {
        return $this->directSignatures;
    }

    public function getUsers(): array
    {
        return $this->users;
    }

    public function getSubkeys(): array
    {
        return $this->subkeys;
    }

    protected function setUsers(array $users): self
    {
        $this->users = array_filter(
            $users,
            static fn ($user) => $user instanceof User
        );
        return $this;
    }

    protected function setSubkeys(array $subkeys): self
    {
        $this->subkeys = array_filter(
            $subkeys,
            static fn ($subkey) => $subkey instanceof Subkey
        );
        return $this;
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

    protected static function readPacketList(PacketListInterface $packetList): array
    {
        $revocationSignatures = $directSignatures = $users = $subkeys = [];
        $keyPacket = $primaryKeyID = null;

        foreach ($packetList->toArray() as $packet) {
            switch ($packet->getTag()) {
                case PacketTag::PublicKey:
                case PacketTag::SecretKey:
                    if (!empty($keyPacket)) {
                        throw new \UnexpectedValueException(
                            'Key block contains multiple keys'
                        );
                    }
                    if ($packet instanceof KeyPacketInterface) {
                        $keyPacket = $packet;
                        $primaryKeyID = $packet->getKeyID();
                    }
                    break;
                case PacketTag::PublicSubkey:
                case PacketTag::SecretSubkey:
                    if ($packet instanceof SubkeyPacketInterface) {
                        $subkeys[] = [
                            'keyPacket' => $packet,
                            'revocationSignatures' => [],
                            'bindingSignatures' => [],
                        ];
                    }
                    break;
                case PacketTag::UserID:
                case PacketTag::UserAttribute:
                    if ($packet instanceof UserIDPacketInterface) {
                        $users[] = [
                            'userIDPacket' => $packet,
                            'revocationSignatures' => [],
                            'selfCertifications' => [],
                            'otherCertifications' => [],
                        ];
                    }
                    break;
                case PacketTag::Signature:
                    if ($packet instanceof SignaturePacketInterface) {
                        switch ($packet->getSignatureType()) {
                            case SignatureType::CertGeneric:
                            case SignatureType::CertPersona:
                            case SignatureType::CertCasual:
                            case SignatureType::CertPositive:
                                $user = array_pop($users);
                                if (!empty($user)) {
                                    if ($packet->getIssuerKeyID()->getKeyID() === $primaryKeyID) {
                                        $user['selfCertifications'][] = $packet;
                                    }
                                    else {
                                        $user['otherCertifications'][] = $packet;
                                    }
                                    $users[] = $user;
                                }
                                break;
                            case SignatureType::CertRevocation:
                                $user = array_pop($users);
                                if (!empty($user)) {
                                    $user['revocationSignatures'][] = $packet;
                                    $users[] = $user;
                                }
                                else {
                                    $directSignatures[] = $packet;
                                }
                                break;
                            case SignatureType::SubkeyBinding:
                                $subkey = array_pop($subkeys);
                                if (!empty($subkey)) {
                                    $subkey['bindingSignatures'][] = $packet;
                                    $subkeys[] = $subkey;
                                }
                                break;
                            case SignatureType::SubkeyRevocation:
                                $subkey = array_pop($subkeys);
                                if (!empty($subkey)) {
                                    $subkey['revocationSignatures'][] = $packet;
                                    $subkeys[] = $subkey;
                                }
                                break;
                            case SignatureType::Key:
                                $directSignatures[] = $packet;
                                break;
                            case SignatureType::KeyRevocation:
                                $revocationSignatures[] = $packet;
                                break;
                        }
                    }
                    break;
            }
        }

        if (empty($keyPacket)) {
            throw new \UnexpectedValueException(
                'Key packet not found in packet list'
            );
        }

        return [
            'keyPacket' => $keyPacket,
            'revocationSignatures' => $revocationSignatures,
            'directSignatures' => $directSignatures,
            'users' => $users,
            'subkeys' => $subkeys,
        ];
    }
}
