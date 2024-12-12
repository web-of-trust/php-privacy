<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Key;

use DateTimeInterface;
use OpenPGP\Enum\RevocationReasonTag;
use OpenPGP\Packet\{PacketList, Signature, UserID};
use OpenPGP\Type\{
    KeyInterface,
    PacketListInterface,
    PrivateKeyInterface,
    SignaturePacketInterface,
    UserIDPacketInterface,
    UserInterface
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
    private readonly array $revocationSignatures;

    /**
     * Self certification signature packets
     *
     * @var array
     */
    private readonly array $selfCertifications;

    /**
     * Other certification signature packets
     *
     * @var array
     */
    private readonly array $otherCertifications;

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
    ) {
        $this->revocationSignatures = array_values(
            array_filter(
                $revocationSignatures,
                static fn ($signature) => $signature instanceof
                    SignaturePacketInterface && $signature->isCertRevocation()
            )
        );
        $this->selfCertifications = array_values(
            array_filter(
                $selfCertifications,
                static fn ($signature) => $signature instanceof
                    SignaturePacketInterface && $signature->isCertification()
            )
        );
        $this->otherCertifications = array_values(
            array_filter(
                $otherCertifications,
                static fn ($signature) => $signature instanceof
                    SignaturePacketInterface && $signature->isCertification()
            )
        );
    }

    /**
     * {@inheritdoc}
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
            usort($signatures, static function ($a, $b) {
                $aTime = $a->getCreationTime() ?? new \DateTime();
                $bTime = $b->getCreationTime() ?? new \DateTime();
                return $aTime->getTimestamp() - $bTime->getTimestamp();
            });
            return array_pop($signatures);
        }
        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function getUserID(): string
    {
        return $this->userIDPacket instanceof UserID
            ? $this->userIDPacket->getUserID()
            : "";
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
    ): bool {
        if (!empty($this->revocationSignatures)) {
            $revocationKeyIDs = [];
            $keyID = $certificate?->getIssuerKeyID();
            $keyPacket =
                $verifyKey?->toPublic()->getSigningKeyPacket() ??
                $this->mainKey->toPublic()->getSigningKeyPacket();
            foreach ($this->revocationSignatures as $signature) {
                if (
                    empty($keyID) ||
                    strcmp($keyID, $signature->getIssuerKeyID()) === 0
                ) {
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
    ): bool {
        $keyID = $certificate?->getIssuerKeyID();
        $keyPacket =
            $verifyKey?->toPublic()->getSigningKeyPacket() ??
            $this->mainKey->toPublic()->getSigningKeyPacket();
        foreach ($this->otherCertifications as $signature) {
            if (
                empty($keyID) ||
                strcmp($keyID, $signature->getIssuerKeyID()) === 0
            ) {
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
        PrivateKeyInterface $signKey,
        ?DateTimeInterface $time = null
    ): self {
        if (
            strcmp(
                $signKey->getFingerprint(),
                $this->mainKey->getFingerprint()
            ) === 0
        ) {
            throw new \RuntimeException(
                'The user\'s own key can only be used for self-certifications.'
            );
        }
        return new self(
            $this->mainKey,
            $this->userIDPacket,
            $this->revocationSignatures,
            $this->selfCertifications,
            [
                ...$this->otherCertifications,
                Signature::createCertGeneric(
                    $signKey->getSecretKeyPacket(),
                    $this->mainKey->getKeyPacket(),
                    $this->userIDPacket,
                    $time
                ),
            ]
        );
    }

    /**
     * {@inheritdoc}
     */
    public function revokeBy(
        PrivateKeyInterface $signKey,
        string $revocationReason = "",
        ?RevocationReasonTag $reasonTag = null,
        ?DateTimeInterface $time = null
    ): self {
        return new self(
            $this->mainKey,
            $this->userIDPacket,
            [
                ...$this->revocationSignatures,
                Signature::createCertRevocation(
                    $signKey->getSecretKeyPacket(),
                    $this->mainKey->getKeyPacket(),
                    $this->userIDPacket,
                    $revocationReason,
                    $reasonTag,
                    $time
                ),
            ],
            $this->selfCertifications,
            $this->otherCertifications
        );
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
