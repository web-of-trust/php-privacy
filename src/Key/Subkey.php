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

use DateInterval;
use DateTime;
use OpenPGP\Enum\KeyAlgorithm;
use OpenPGP\Packet\{PacketList, Signature};
use OpenPGP\Type\{
    KeyInterface,
    PacketContainerInterface,
    PacketListInterface,
    SignaturePacketInterface,
    SubkeyInterface,
    SubkeyPacketInterface
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
    private array $revocationSignatures;

    private array $bindingSignatures;

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
     * @return array
     */
    public function getRevocationSignatures(): array
    {
        return $this->revocationSignatures;
    }

    /**
     * Gets binding signatures
     * 
     * @return array
     */
    public function getBindingSignatures(): array
    {
        return $this->bindingSignatures;
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
        if (!empty($this->bindingSignatures)) {
            usort(
                $this->bindingSignatures,
                static function ($a, $b) {
                    $aTime = $a->getSignatureCreationTime() ?? (new DateTime())->setTimestamp(0);
                    $bTime = $b->getSignatureCreationTime() ?? (new DateTime())->setTimestamp(0);
                    if ($aTime == $bTime) {
                        return 0;
                    }
                    return ($aTime > $bTime) ? -1 : 1;
                }
            );
            foreach ($this->bindingSignatures as $signature) {
                $signature = $this->bindingSignatures[0];
                $keyExpirationTime = $signature->getKeyExpirationTime();
                if (!empty($keyExpirationTime)) {
                    $expirationTime = $keyExpirationTime->getExpirationTime();
                    $creationTime = $signature->getSignatureCreationTime() ?? new DateTime();
                    $keyExpiration = $creationTime->add(
                        DateInterval::createFromDateString($expirationTime . ' seconds')
                    );
                    $signatureExpiration = $signature->getSignatureExpirationTime();
                    if (empty($signatureExpiration)) {
                        return $keyExpiration;
                    }
                    else {
                        return $keyExpiration < $signatureExpiration ? $keyExpiration : $signatureExpiration;
                    }
                }
                else {
                    return $signature->getSignatureExpirationTime();
                }
            }
        }
        return null;
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
                        $this->keyPacket->getSignBytes(),
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
    public function verify(?DateTime $time = null): bool
    {
        if ($this->isRevoked(time: $time)) {
            return false;
        }
        foreach ($this->bindingSignatures as $signature) {
            if (!$signature->verify(
                $this->mainKey->toPublic()->getKeyPacket(),
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
            $signKey->getKeyPacket(),
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
