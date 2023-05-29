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
use OpenPGP\Enum\KeyAlgorithm;
use OpenPGP\Packet\{
    PacketList,
    Signature,
};
use OpenPGP\Packet\Signature\KeyFlags;
use OpenPGP\Type\{
    KeyInterface,
    KeyPacketInterface,
    PacketContainerInterface,
    PacketListInterface,
    SignaturePacketInterface,
    SubkeyInterface,
    SubkeyPacketInterface,
};

/**
 * OpenPGP sub key class
 * 
 * @package   OpenPGP
 * @category  Key
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class Subkey implements PacketContainerInterface, SubkeyInterface
{
    /**
     * Revocation signature packets
     * 
     * @var array<SignaturePacketInterface>
     */
    private array $revocationSignatures;

    /**
     * Binding signature packets
     * 
     * @var array<SignaturePacketInterface>
     */
    private array $bindingSignatures;

    /**
     * Constructor
     *
     * @param KeyInterface $mainKey
     * @param SubkeyPacketInterface $keyPacket
     * @param array<SignaturePacketInterface> $revocationSignatures
     * @param array<SignaturePacketInterface> $bindingSignatures
     * @return self
     */
    public function __construct(
        private readonly KeyInterface $mainKey,
        private readonly SubkeyPacketInterface $keyPacket,
        array $revocationSignatures = [],
        array $bindingSignatures = []
    )
    {
        $this->revocationSignatures = array_filter(
            $revocationSignatures,
            static fn ($signature) => $signature instanceof SignaturePacketInterface
        );
        $this->bindingSignatures = array_filter(
            $bindingSignatures,
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
     * Gets revocation signatures
     * 
     * @return array<SignaturePacketInterface>
     */
    public function getRevocationSignatures(): array
    {
        return $this->revocationSignatures;
    }

    /**
     * Gets binding signatures
     * 
     * @return array<SignaturePacketInterface>
     */
    public function getBindingSignatures(): array
    {
        return $this->bindingSignatures;
    }

    /**
     * Gets latest binding signature
     * 
     * @return SignaturePacketInterface
     */
    public function getLatestBindingSignature(): ?SignaturePacketInterface
    {
        if (!empty($this->bindingSignatures)) {
            $signatures = $this->bindingSignatures;
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
    public function getKeyPacket(): SubkeyPacketInterface
    {
        return $this->keyPacket;
    }

    /**
     * {@inheritdoc}
     */
    public function getExpirationTime(): ?DateTime
    {
        return AbstractKey::getKeyExpiration($this->bindingSignatures);
    }

    /**
     * {@inheritdoc}
     */
    public function getCreationTime(): DateTime
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
        if (($keyFlags instanceof KeyFlags) && !$keyFlags->isSignData()) {
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
        if (($keyFlags instanceof KeyFlags) &&
           !($keyFlags->isEncryptCommunication() || $keyFlags->isEncryptStorage()))
        {
            return false;
        }
        return true;
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
            $this->keyPacket->getSignBytes(),
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
                'Subkey is revoked.'
            );
            return false;
        }
        $keyPacket = $this->mainKey->toPublic()->getKeyPacket();
        $dataToVerify = implode([
            $keyPacket->getSignBytes(),
            $this->keyPacket->getSignBytes(),
        ]);
        foreach ($this->bindingSignatures as $signature) {
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
     * Revokes the subkey
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
        $revocationSignatures[] = Signature::createSubkeyRevocation(
            $signKey->getSigningKeyPacket(),
            $this->keyPacket,
            $revocationReason,
            $time
        );
        return new self(
            $this->mainKey,
            $this->keyPacket,
            $revocationSignatures,
            $this->bindingSignatures
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toPacketList(): PacketListInterface
    {
        return new PacketList([
            $this->keyPacket,
            ...$this->revocationSignatures,
            ...$this->bindingSignatures,
        ]);
    }
}
