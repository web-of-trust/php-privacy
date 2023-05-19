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
use OpenPGP\Packet\PacketList;
use OpenPGP\Type\{
    KeyInterface,
    PacketContainerInterface,
    PacketListInterface,
    SignaturePacketInterface,
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
class Subkey implements PacketContainerInterface
{
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
        private readonly array $revocationSignatures = [],
        private readonly array $bindingSignatures = []
    )
    {
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
     * Gets key packet
     * 
     * @return SubkeyPacketInterface
     */
    public function getKeyPacket(): SubkeyPacketInterface
    {
        return $this->keyPacket;
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
     * Returns the expiration time of the subkey or Infinity if key does not expire.
     * Returns null if the subkey is invalid.
     * 
     * @return DateTime
     */
    public function getExpirationTime(): ?DateTime
    {
        if (!empty($this->bindingSignatures)) {
            $bindingSignatures = usort(
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
            $signature = $bindingSignatures[0];
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

    /**
     * Checks if a binding signature of a subkey is revoked
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
     * Verify subkey.
     * Checks for revocation signatures, expiration time and valid binding signature.
     * 
     * @param DateTime $time
     * @return bool
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
