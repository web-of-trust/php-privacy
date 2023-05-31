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

use DateTime;
use OpenPGP\Common\Config;
use OpenPGP\Enum\{
    HashAlgorithm,
    SignatureType,
};
use OpenPGP\Packet\{
    PacketList,
    Signature,
    UserID,
};
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
 * @package   OpenPGP
 * @category  Key
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class User implements UserInterface
{
    /**
     * Revocation signature packets
     * 
     * @var array<SignaturePacketInterface>
     */
    private array $revocationSignatures;

    /**
     * Self certification signature packets
     * 
     * @var array<SignaturePacketInterface>
     */
    private array $selfCertifications;

    /**
     * Other certification signature packets
     * 
     * @var array<SignaturePacketInterface>
     */
    private array $otherCertifications;

    /**
     * Constructor
     *
     * @param KeyInterface $mainKey
     * @param UserIDPacketInterface $userIDPacket
     * @param array<SignaturePacketInterface> $revocationSignatures
     * @param array<SignaturePacketInterface> $selfCertifications
     * @param array<SignaturePacketInterface> $otherCertifications
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
                static function ($a, $b) {
                    $aTime = $a->getSignatureCreationTime() ?? new DateTime();
                    $bTime = $b->getSignatureCreationTime() ?? new DateTime();
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
        ?KeyPacketInterface $keyPacket = null,
        ?SignaturePacketInterface $certificate = null,
        ?DateTime $time = null
    ): bool
    {
        $keyID = $certificate?->getIssuerKeyID() ?? '';
        $keyPacket = $keyPacket ?? $this->mainKey->toPublic()->getKeyPacket();
        $dataToVerify = implode([
            $keyPacket->getSignBytes(),
            $this->userIDPacket->getSignBytes(),
        ]);
        foreach ($this->revocationSignatures as $signature) {
            if (empty($keyID) || $keyID === $signature->getIssuerKeyID()) {
                if ($signature->verify(
                    $keyPacket,
                    $dataToVerify,
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
    public function verify(?DateTime $time = null): bool
    {
        if ($this->isRevoked(time: $time)) {
            Config::getLogger()->debug(
                'User is revoked.'
            );
            return false;
        }
        $keyPacket = $this->mainKey->toPublic()->getKeyPacket();
        $dataToVerify = implode([
            $keyPacket->getSignBytes(),
            $this->userIDPacket->getSignBytes(),
        ]);
        foreach ($this->selfCertifications as $signature) {
            if (!$signature->verify(
                $keyPacket,
                $dataToVerify,
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
    public function certify(
        PrivateKeyInterface $signKey, ?DateTime $time = null
    ): self
    {
        if ($signKey->getFingerprint() === $this->mainKey->getFingerprint()) {
            throw new \InvalidArgumentException(
                'The user\'s own key can only be used for self-certifications'
            );
        }
        $user = clone $this;
        $user->otherCertifications[] = Signature::createCertGeneric(
            $signKey->getSigningKeyPacket(),
            $user->getUserIDPacket(),
            $time
        );
        return $user;
    }

    /**
     * {@inheritdoc}
     */
    public function revoke(
        PrivateKeyInterface $signKey,
        string $revocationReason = '',
        ?DateTime $time = null
    ): self
    {
        $user = clone $this;
        $user->revocationSignatures[] = Signature::createCertRevocation(
            $signKey->getSigningKeyPacket(),
            $user->getUserIDPacket(),
            $revocationReason,
            $time
        );
        return $user;
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
