<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Key;

use DateTimeInterface;
use OpenPGP\Enum\{
    HashAlgorithm,
    RevocationReasonTag,
    SignatureType,
};
use OpenPGP\Packet\{
    PacketList,
    Signature,
    UserID,
};
use OpenPGP\Packet\Signature\RevocationReason;
use OpenPGP\Type\{
    KeyInterface,
    KeyPacketInterface,
    PacketListInterface,
    PrivateKeyInterface,
    SignaturePacketInterface,
    UserIDPacketInterface,
    UserInterface,
};

/**
 * OpenPGP user class.
 * 
 * @package  OpenPGP
 * @category Key
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class User implements UserInterface
{
    /**
     * Revocation signature packets
     * 
     * @var array
     */
    private array $revocationSignatures;

    /**
     * Self certification signature packets
     * 
     * @var array
     */
    private array $selfCertifications;

    /**
     * Other certification signature packets
     * 
     * @var array
     */
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
     * Get main key
     * 
     * @return KeyInterface
     */
    public function getMainKey(): KeyInterface
    {
        return $this->mainKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getUserIDPacket(): UserIDPacketInterface
    {
        return $this->userIDPacket;
    }

    /**
     * {@inheritdoc}
     */
    public function getRevocationCertifications(): array
    {
        return $this->revocationSignatures;
    }

    /**
     * {@inheritdoc}
     */
    public function getSelfCertifications(): array
    {
        return $this->selfCertifications;
    }

    /**
     * {@inheritdoc}
     */
    public function getOtherCertifications(): array
    {
        return $this->otherCertifications;
    }

    /**
     * {@inheritdoc}
     */
    public function getLatestSelfCertification(): ?SignaturePacketInterface
    {
        if (!empty($this->selfCertifications)) {
            $signatures = $this->selfCertifications;
            usort(
                $signatures,
                static function ($a, $b): int {
                    $aTime = $a->getSignatureCreationTime() ?? new \DateTime();
                    $bTime = $b->getSignatureCreationTime() ?? new \DateTime();
                    return $aTime->getTimestamp() - $bTime->getTimestamp();
                }
            );
            return array_pop($signatures);
        }
        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function getUserID(): string
    {
        return ($this->userIDPacket instanceof UserID) ? $this->userIDPacket->getUserID() : '';
    }

    /**
     * {@inheritdoc}
     */
    public function isPrimary(): bool
    {
        $selfCert = $this->getLatestSelfCertification();
        return !empty($selfCert) ? $selfCert->isPrimaryUserID() : false;
    }

    /**
     * {@inheritdoc}
     */
    public function isRevoked(
        ?KeyInterface $verifyKey = null,
        ?SignaturePacketInterface $certificate = null,
        ?DateTimeInterface $time = null
    ): bool
    {
        if (!empty($this->revocationSignatures)) {
            $revocationKeyIDs = [];
            $keyID = $certificate?->getIssuerKeyID();
            $keyPacket = $verifyKey?->toPublic()->getSigningKeyPacket() ??
                         $this->mainKey->toPublic()->getSigningKeyPacket();
            foreach ($this->revocationSignatures as $signature) {
                if (empty($keyID) || $keyID === $signature->getIssuerKeyID()) {
                    if ($signature->verify(
                        $keyPacket,
                        implode([
                            $this->mainKey->getKeyPacket()->getSignBytes(),
                            $this->userIDPacket->getSignBytes(),
                        ]),
                        $time
                    )) {
                        $reason = $signature->getRevocationReason();
                        if ($reason instanceof RevocationReason) {
                            $this->mainKey->getLogger()->warning(
                                'User is revoked. Reason: {reason}',
                                [
                                    'reason' => $reason->getDescription(),
                                ]
                            );
                        }
                        else {
                            $this->mainKey->getLogger()->warning(
                                'User is revoked.'
                            );
                        }
                        return true;
                    }
                }
                $revocationKeyIDs[] = $signature->getIssuerKeyID();
            }
            return count($revocationKeyIDs) > 0;
        }
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function isCertified(
        ?KeyInterface $verifyKey = null,
        ?SignaturePacketInterface $certificate = null,
        ?DateTimeInterface $time = null
    ): bool
    {
        if ($this->isRevoked($verifyKey, time: $time)) {
            return false;
        }
        $keyID = $certificate?->getIssuerKeyID();
        $keyPacket = $verifyKey?->toPublic()->getSigningKeyPacket() ??
                     $this->mainKey->toPublic()->getSigningKeyPacket();
        foreach ($this->otherCertifications as $signature) {
            if (empty($keyID) || $keyID === $signature->getIssuerKeyID()) {
                if ($signature->verify(
                    $keyPacket,
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
     * {@inheritdoc}
     */
    public function verify(?DateTimeInterface $time = null): bool
    {
        if ($this->isRevoked(time: $time)) {
            return false;
        }
        $keyPacket = $this->mainKey->toPublic()->getSigningKeyPacket();
        foreach ($this->selfCertifications as $signature) {
            if (!$signature->verify(
                $keyPacket,
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
     * {@inheritdoc}
     */
    public function certifyBy(
        PrivateKeyInterface $signKey, ?DateTimeInterface $time = null
    ): self
    {
        if ($signKey->getFingerprint() === $this->mainKey->getFingerprint()) {
            throw new \InvalidArgumentException(
                'The user\'s own key can only be used for self-certifications.'
            );
        }
        $self = clone $this;
        $self->otherCertifications[] = Signature::createCertGeneric(
            $signKey->getSigningKeyPacket(),
            $self->getMainKey()->getKeyPacket(),
            $self->getUserIDPacket(),
            $time
        );
        return $self;
    }

    /**
     * {@inheritdoc}
     */
    public function revokeBy(
        PrivateKeyInterface $signKey,
        string $revocationReason = '',
        RevocationReasonTag $reasonTag = RevocationReasonTag::NoReason,
        ?DateTimeInterface $time = null
    ): self
    {
        $self = clone $this;
        $self->revocationSignatures[] = Signature::createCertRevocation(
            $signKey->getSigningKeyPacket(),
            $self->getMainKey()->getKeyPacket(),
            $self->getUserIDPacket(),
            $revocationReason,
            $reasonTag,
            $time
        );
        return $self;
    }

    /**
     * {@inheritdoc}
     */
    public function getPacketList(): PacketListInterface
    {
        return new PacketList([
            $this->userIDPacket,
            ...$this->revocationSignatures,
            ...$this->selfCertifications,
            ...$this->otherCertifications,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function getPackets(): array
    {
        return $this->getPacketList()->getPackets();
    }
}
