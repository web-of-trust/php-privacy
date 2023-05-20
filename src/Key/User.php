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

use OpenPGP\Enum\{HashAlgorithm, SignatureType};
use OpenPGP\Packet\{PacketList, Signature, UserID};
use OpenPGP\Type\{
    KeyInterface,
    PacketContainerInterface,
    PacketListInterface,
    SignaturePacketInterface,
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
    private array $revocationSignatures;

    private array $selfCertifications;

    private array $otherCertifications;

    /**
     * Constructor
     *
     * @param KeyInterface $mainKey
     * @param UserIDPacketInterface $userIDPacket
     * @param array $revocationSignatures
     * @param array $selfCertifications
     * @param array $otherCertifications
     * @return self
     */
    public function __construct(
        private readonly KeyInterface $mainKey,
        private readonly UserIDPacketInterface $userIDPacket,
        array $revocationSignatures = [],
        array $selfCertifications = [],
        array $otherCertifications = []
    )
    {
        $this->revocationSignatures = array_filter(
            $revocationSignatures,
            static fn ($signature) => $signature instanceof SignaturePacketInterface
        );
        $this->selfCertifications = array_filter(
            $selfCertifications,
            static fn ($signature) => $signature instanceof SignaturePacketInterface
        );
        $this->otherCertifications = array_filter(
            $otherCertifications,
            static fn ($signature) => $signature instanceof SignaturePacketInterface
        );
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
     * Gets user ID packet
     * 
     * @return UserIDPacketInterface
     */
    public function getUserIDPacket(): UserIDPacketInterface
    {
        return $this->userIDPacket;
    }

    /**
     * Gets revocation signatures
     * 
     * @return array
     */
    public function getRevocationCertifications(): array
    {
        return $this->revocationSignatures;
    }

    /**
     * Gets self signatures
     * 
     * @return array
     */
    public function getSelfCertifications(): array
    {
        return $this->selfCertifications;
    }

    /**
     * Gets other signatures
     * 
     * @return array
     */
    public function getOtherCertifications(): array
    {
        return $this->otherCertifications;
    }

    /**
     * Gets user ID
     * 
     * @return string
     */
    public function getUserID(): string
    {
        return ($this->userIDPacket instanceof UserID) ? $this->userIDPacket->getUserID() : '';
    }

    /**
     * Checks if a given certificate of the user is revoked
     * 
     * @param SignaturePacketInterface $certificate
     * @param DateTime $time
     * @return bool
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
                    $this->mainKey->toPublic()->getKeyPacket(),
                    implode([
                        $this->mainKey->getKeyPacket()->getSignBytes(),
                        $this->userIDPacket->getSignBytes(),
                    ]),
                    $time
                )) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Verify user.
     * Checks for existence of self signatures, revocation signatures and validity of self signature.
     * 
     * @param DateTime $time
     * @return bool
     */
    public function verify(?DateTime $time = null): bool
    {
        if ($this->isRevoked(time: $time)) {
            return false;
        }
        foreach ($this->selfCertifications as $signature) {
            if (!$signature->verify(
                $this->mainKey->toPublic()->getKeyPacket(),
                implode([
                    $this->mainKey->getKeyPacket()->getSignBytes(),
                    $this->userIDPacket->getSignBytes(),
                ]),
                $time
            )) {
                return false;
            }
        }
        return true;
    }

    /**
     * Generate third-party certification over this user and its primary key
     * return new user with new certification.
     * 
     * @param PrivateKey $signKey
     * @param DateTime $time
     * @return self
     */
    public function certify(PrivateKey $signKey, ?DateTime $time = null): self
    {
        $otherCertifications = $this->otherCertifications;
        $otherCertifications[] = Signature::createCertGeneric(
            $signKey->getKeyPacket(),
            $this->userIDPacket,
            $time
        );
        return new User(
            $this->mainKey,
            $this->userIDPacket,
            $this->revocationSignatures,
            $this->selfCertifications,
            $otherCertifications
        );
    }

    /**
     * Revokes the user
     * 
     * @param PrivateKey $signKey
     * @param string $revocationReason
     * @param DateTime $time
     * @return self
     */
    public function revoke(
        PrivateKey $signKey,
        string $revocationReason = '',
        ?DateTime $time = null
    ): self
    {
        $revocationSignatures = $this->revocationSignatures;
        $revocationSignatures[] = Signature::createCertRevocation(
            $signKey->getKeyPacket(),
            $this->userIDPacket,
            $revocationReason,
            $time
        );
        return new User(
            $this->mainKey,
            $this->userIDPacket,
            $revocationSignatures,
            $this->selfCertifications,
            $this->otherCertifications
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toPacketList(): PacketListInterface
    {
        return new PacketList([
            $this->userIDPacket,
            ...$this->revocationSignatures,
            ...$this->selfCertifications,
            ...$this->otherCertifications,
        ]);
    }
}
