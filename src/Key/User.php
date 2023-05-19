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
use OpenPGP\Packet\{PacketList, Signature};
use OpenPGP\Type\{
    KeyInterface,
    PacketContainerInterface,
    PacketListInterface,
    SecretKeyPacketInterface,
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
    /**
     * Constructor
     *
     * @param KeyInterface $mainKey
     * @param UserIDPacketInterface $userID
     * @param array $revocationSignatures
     * @param array $selfCertifications
     * @param array $otherCertifications
     * @return self
     */
    public function __construct(
        private readonly KeyInterface $mainKey,
        private readonly UserIDPacketInterface $userID,
        private readonly array $revocationSignatures = [],
        private readonly array $selfCertifications = [],
        private readonly array $otherCertifications = []
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
     * Gets user ID packet
     * 
     * @return UserIDPacketInterface
     */
    public function getUserID(): UserIDPacketInterface
    {
        return $this->userID;
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
                    $this->mainKey->getKeyPacket(),
                    implode([
                        $this->mainKey->getKeyPacket()->getSignBytes(),
                        $this->userID->getSignBytes(),
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
                $this->mainKey->getKeyPacket(),
                implode([
                    $this->mainKey->getKeyPacket()->getSignBytes(),
                    $this->userID->getSignBytes(),
                ]),
                $time
            )) {
                return false;
            }
        }
        return true;
    }

    /**
     * Generate third-party certifications over this user and its primary key
     * return new user with new certifications.
     * 
     * @param array $signKeys
     * @param DateTime $time
     * @return self
     */
    public function certify(array $signKeys, ?DateTime $time = null): self
    {
        $signKeys = array_filter(
            $signKeys,
            static fn ($key) => $key instanceof PrivateKey
        );
        if (!empty($signKeys)) {
            $otherCertifications = array_map(
                static fn ($signKey) => Signature::createCertGeneric(
                    $signKey->getKeyPacket(),
                    $this->userID,
                    $time
                ),
                $signKeys
            );
            return new User(
                $this->mainKey,
                $this->userID,
                $this->revocationSignatures,
                $this->selfCertifications,
                $otherCertifications
            );
        }
        return $this;
    }

    public function revoke(
        SecretKeyPacketInterface $primaryKey,
        string $revocationReason = '',
        ?DateTime $time = null
    ): self
    {
        $revocationSignatures = $this->revocationSignatures;
        return new User(
            $this->mainKey,
            $this->userID,
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
            $this->userID,
            ...$this->revocationSignatures,
            ...$this->selfCertifications,
            ...$this->otherCertifications,
        ]);
    }
}
