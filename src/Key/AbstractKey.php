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
use OpenPGP\Common\Helper;
use OpenPGP\Enum\{
    KeyAlgorithm,
    PacketTag,
    SignatureType
};
use OpenPGP\Packet\PacketList;
use OpenPGP\Type\{
    ArmorableInterface,
    KeyInterface,
    KeyPacketInterface,
    PacketContainerInterface,
    PacketListInterface,
    SignaturePacketInterface,
    SubkeyPacketInterface,
    UserIDPacketInterface
};
use Psr\Log\{
    LoggerAwareInterface,
    LoggerAwareTrait,
    LoggerInterface,
};

/**
 * Abstract OpenPGP key class
 * 
 * @package   OpenPGP
 * @category  Key
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
abstract class AbstractKey implements ArmorableInterface, KeyInterface, LoggerAwareInterface, PacketContainerInterface
{
    use LoggerAwareTrait;

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
        $this->setUsers($users)
             ->setSubkeys($subkeys)
             ->setLogger(Helper::getLogger());
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
    public function getLogger(): LoggerInterface
    {
        return $this->logger ?? Helper::getLogger();
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyPacket(): KeyPacketInterface
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
     * Get direct signatures
     * 
     * @return array
     */
    public function getDirectSignatures(): array
    {
        return $this->directSignatures;
    }

    /**
     * Gets users
     * 
     * @return array
     */
    public function getUsers(): array
    {
        return $this->users;
    }

    /**
     * Gets subkeys
     * 
     * @return array
     */
    public function getSubkeys(): array
    {
        return $this->subkeys;
    }

    /**
     * Sets users
     * 
     * @param array $users
     * @return self
     */
    protected function setUsers(array $users): self
    {
        $this->users = array_filter(
            $users,
            static fn ($user) => $user instanceof User
        );
        return $this;
    }

    /**
     * Sets subkeys
     * 
     * @param array $subkeys
     * @return self
     */
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
    public function getSigningKeyPacket(
        string $keyID = '', ?DateTime $time = null
    ): KeyPacketInterface
    {
        if (!$this->verify(time: $time)) {
            throw new \UnexpectedValueException(
                'Primary key is invalid.'
            );
        }
        $subkeys = $this->subkeys;
        usort(
            $subkeys,
            static fn ($a, $b) => $b->getCreationTime()->getTimestamp() - $a->getCreationTime()->getTimestamp()
        );
        foreach ($subkeys as $subkey) {
            if (empty($keyID) || $keyID === $subkey->getKeyID()) {
                if ($subkey->verify($time)) {
                    if (!self::isValidSigningKey(
                        $subkey->getKeyPacket(), $subkey->getLatestBindingSignature()
                    )) {
                        continue;
                    }
                    $embeddedSignature = $subkey->getLatestBindingSignature()->getEmbeddedSignature();
                    if (empty($embeddedSignature)) {
                        throw new \UnexpectedValueException('Missing embedded signature');
                    }
                    // verify embedded signature
                    if ($embeddedSignature->verify(
                        $subkey->getKeyPacket(),
                        implode([
                            $this->getKeyPacket()->getSignBytes(),
                            $subkey->getKeyPacket()->getSignBytes(),
                        ]),
                        $time
                    )) {
                        return $subkey->getKeyPacket();
                    }
                }
            }
        }

        if (!$this->keyPacket->isSigningKey() ||
           (!empty($keyID) && $keyID !== $this->getKeyID())) {
            throw new \UnexpectedValueException('Could not find valid signing key packet.');
        }

        return $this->keyPacket;
    }

    /**
     * {@inheritdoc}
     */
    public function getEncryptionKeyPacket(
        string $keyID = '', ?DateTime $time = null
    ): KeyPacketInterface
    {
        if (!$this->verify(time: $time)) {
            throw new \UnexpectedValueException(
                'Primary key is invalid.'
            );
        }
        $subkeys = $this->subkeys;
        usort(
            $subkeys,
            static fn ($a, $b) => $b->getCreationTime()->getTimestamp() - $a->getCreationTime()->getTimestamp()
        );
        foreach ($subkeys as $subkey) {
            if (empty($keyID) || $keyID === $subkey->getKeyID()) {
                if ($subkey->verify($time)) {
                    if (!self::isValidEncryptionKey(
                        $subkey->getKeyPacket(), $subkey->getLatestBindingSignature()
                    )) {
                        continue;
                    }
                    return $subkey->getKeyPacket();
                }
            }
        }

        if (!$this->keyPacket->isEncryptionKey() ||
           (!empty($keyID) && $keyID !== $this->getKeyID())) {
            throw new \UnexpectedValueException('Could not find valid encryption key packet.');
        }

        return $this->keyPacket;
    }

    /**
     * {@inheritdoc}
     */
    public function getExpirationTime(): ?DateTime
    {
        $selfCertifications = [];
        foreach ($this->users as $user) {
            $selfCertifications = array_merge(
                $selfCertifications, $user->getSelfCertifications()
            );
        }
        if (!empty($selfCertifications)) {
            return Helper::getKeyExpiration($selfCertifications);
        }
        if (!empty($this->directSignatures)) {
            return Helper::getKeyExpiration($this->directSignatures);
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
    public function isPrivate(): bool
    {
        return $this->keyPacket->getTag() === PacketTag::SecretKey;
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
            $this->getLogger()->debug(
                'Primary key is revoked.'
            );
            return false;
        }
        foreach ($this->users as $user) {
            if (empty($userID) || $user->getUserID() === $userID) {
                if (!$user->verify($time)) {
                    return false;
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
        $expirationTime = $this->getExpirationTime();
        if ($expirationTime instanceof DateTime && $expirationTime < new DateTime()) {
            $this->getLogger()->debug(
                'Primary key is expired.'
            );
            return false;
        }
        return true;
    }

    /**
     * Returns primary user
     * 
     * @param DateTime $time
     * @return User
     */
    public function getPrimaryUser(?DateTime $time = null): User
    {
        $users = [];
        foreach ($this->users as $user) {
            if ($user->verify($time)) {
                $users[] = $user;
            }
        }
        if (empty($users)) {
            throw new \UnexpectedValueException(
                'Could not find primary user'
            );
        }
        usort(
            $users,
            static function ($a, $b) {
                $aCert = $a->getLatestSelfCertification();
                $bCert = $b->getLatestSelfCertification();

                $aPrimary = (int) $aCert->isPrimaryUserID();
                $bPrimary = (int) $bCert->isPrimaryUserID();
                if ($aPrimary === $bPrimary) {
                    $aTime = $aCert->getSignatureCreationTime() ?? new DateTime();
                    $bTime = $bCert->getSignatureCreationTime() ?? new DateTime();
                    return $aTime->getTimestamp() - $bTime->getTimestamp();
                }
                else {
                    return $aPrimary - $bPrimary;
                }
            }
        );
        return array_pop($users);
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
                            'Key block contains multiple keys.'
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
                'Key packet not found in packet list.'
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

    protected static function isValidSigningKey(
        KeyPacketInterface $keyPacket, SignaturePacketInterface $signature
    ): bool
    {
        if (!$keyPacket->isSigningKey()) {
            return false;
        }
        $keyFlags = $signature->getKeyFlags();
        if (!empty($keyFlags) && !$keyFlags->isSignData()) {
            return false;
        }
        return true;
    }

    protected static function isValidEncryptionKey(
        KeyPacketInterface $keyPacket, SignaturePacketInterface $signature
    ): bool
    {
        if (!$keyPacket->isEncryptionKey()) {
            return false;
        }
        $keyFlags = $signature->getKeyFlags();
        if (!empty($keyFlags) &&
           !($keyFlags->isEncryptCommunication() || $keyFlags->isEncryptStorage())) {
            return false;
        }
        return true;
    }
}
