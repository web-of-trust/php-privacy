<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Key;

use DateTimeInterface;
use OpenPGP\Enum\{KeyAlgorithm, RevocationReasonTag};
use OpenPGP\Packet\{PacketList, Signature};
use OpenPGP\Packet\Signature\KeyFlags;
use OpenPGP\Type\{
    KeyInterface,
    PacketListInterface,
    PrivateKeyInterface,
    SignaturePacketInterface,
    SubkeyInterface,
    SubkeyPacketInterface
};

/**
 * OpenPGP sub key class
 *
 * @package  OpenPGP
 * @category Key
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class Subkey implements SubkeyInterface
{
    /**
     * Revocation signature packets
     *
     * @var array
     */
    private readonly array $revocationSignatures;

    /**
     * Binding signature packets
     *
     * @var array
     */
    private readonly array $bindingSignatures;

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
        array $revocationSignatures = [],
        array $bindingSignatures = []
    ) {
        $this->revocationSignatures = array_values(
            array_filter(
                $revocationSignatures,
                static fn($signature) => $signature instanceof
                    SignaturePacketInterface && $signature->isSubkeyRevocation()
            )
        );
        $this->bindingSignatures = array_values(
            array_filter(
                $bindingSignatures,
                static fn($signature) => $signature instanceof
                    SignaturePacketInterface && $signature->isSubkeyBinding()
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
    public function getRevocationSignatures(): array
    {
        return $this->revocationSignatures;
    }

    /**
     * {@inheritdoc}
     */
    public function getBindingSignatures(): array
    {
        return $this->bindingSignatures;
    }

    /**
     * {@inheritdoc}
     */
    public function getLatestBindingSignature(): ?SignaturePacketInterface
    {
        if (!empty($this->bindingSignatures)) {
            $signatures = $this->bindingSignatures;
            usort($signatures, static function ($a, $b): int {
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
    public function getKeyPacket(): SubkeyPacketInterface
    {
        return $this->keyPacket;
    }

    /**
     * {@inheritdoc}
     */
    public function getVersion(): int
    {
        return $this->keyPacket->getVersion();
    }

    /**
     * {@inheritdoc}
     */
    public function getExpirationTime(): ?DateTimeInterface
    {
        return AbstractKey::getKeyExpiration($this->bindingSignatures);
    }

    /**
     * {@inheritdoc}
     */
    public function getCreationTime(): ?DateTimeInterface
    {
        return $this->keyPacket->getCreationTime();
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyAlgorithm(): KeyAlgorithm
    {
        return $this->keyPacket->getKeyAlgorithm();
    }

    /**
     * {@inheritdoc}
     */
    public function getFingerprint(bool $toHex = false): string
    {
        return $this->keyPacket->getFingerprint($toHex);
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyID(bool $toHex = false): string
    {
        return $this->keyPacket->getKeyID($toHex);
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyStrength(): int
    {
        return $this->keyPacket->getKeyStrength();
    }

    /**
     * {@inheritdoc}
     */
    public function isSigningKey(): bool
    {
        if (!$this->keyPacket->isSigningKey()) {
            return false;
        }
        $keyFlags = $this->getLatestBindingSignature()?->getKeyFlags();
        if ($keyFlags instanceof KeyFlags && !$keyFlags->isSignData()) {
            return false;
        }
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function isEncryptionKey(): bool
    {
        if (!$this->keyPacket->isEncryptionKey()) {
            return false;
        }
        $keyFlags = $this->getLatestBindingSignature()?->getKeyFlags();
        if (
            $keyFlags instanceof KeyFlags &&
            !(
                $keyFlags->isEncryptCommunication() ||
                $keyFlags->isEncryptStorage()
            )
        ) {
            return false;
        }
        return true;
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
                            $this->keyPacket->getSignBytes(),
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
    public function verify(?DateTimeInterface $time = null): bool
    {
        if ($this->isRevoked(time: $time)) {
            return false;
        }
        $keyPacket = $this->mainKey->toPublic()->getSigningKeyPacket();
        foreach ($this->bindingSignatures as $signature) {
            if (!$signature->verify(
                $keyPacket,
                implode([
                    $this->mainKey->getKeyPacket()->getSignBytes(),
                    $this->keyPacket->getSignBytes(),
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
    public function revokeBy(
        PrivateKeyInterface $signKey,
        string $revocationReason = "",
        ?RevocationReasonTag $reasonTag = null,
        ?DateTimeInterface $time = null
    ): self {
        return new self(
            $this->mainKey,
            $this->keyPacket,
            [
                ...$this->revocationSignatures,
                Signature::createSubkeyRevocation(
                    $signKey->getSecretKeyPacket(),
                    $this->mainKey->getKeyPacket(),
                    $this->keyPacket,
                    $revocationReason,
                    $reasonTag,
                    $time
                ),
            ],
            $this->bindingSignatures
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getPacketList(): PacketListInterface
    {
        return new PacketList([
            $this->keyPacket,
            ...$this->revocationSignatures,
            ...$this->bindingSignatures,
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
