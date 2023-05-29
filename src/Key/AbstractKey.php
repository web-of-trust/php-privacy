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
    KeyAlgorithm,
    PacketTag,
    SignatureType,
};
use OpenPGP\Packet\PacketList;
use OpenPGP\Packet\Signature\{
    EmbeddedSignature,
    KeyExpirationTime,
    KeyFlags,
};
use OpenPGP\Type\{
    KeyInterface,
    KeyPacketInterface,
    PacketListInterface,
    SignaturePacketInterface,
    SubkeyPacketInterface,
    UserIDPacketInterface,
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
abstract class AbstractKey implements KeyInterface, LoggerAwareInterface
{
    use LoggerAwareTrait;

    /**
     * Revocation signature packets
     * 
     * @var array<SignaturePacketInterface>
     */
    private readonly array $revocationSignatures;

    /**
     * Direct signature packets
     * 
     * @var array<SignaturePacketInterface>
     */
    private readonly array $directSignatures;

    /**
     * Users of the key
     * 
     * @var array<User>
     */
    private array $users;

    /**
     * Subkeys of the key
     * 
     * @var array<Subkey>
     */
    private array $subkeys;

    /**
     * Constructor
     *
     * @param KeyPacketInterface $keyPacket
     * @param array<SignaturePacketInterface> $revocationSignatures
     * @param array<SignaturePacketInterface> $directSignatures
     * @param array<User> $users
     * @param array<Subkey> $subkeys
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
             ->setLogger(Config::getLogger());
    }

    /**
     * {@inheritdoc}
     */
    public function toPacketList(): PacketListInterface
    {
        $userPackets = [];
        foreach ($this->users as $user) {
            $userPackets = array_merge(
                $userPackets, $user->toPacketList()->getPackets()
            );
        }
        $subkeyPackets = [];
        foreach ($this->subkeys as $subkey) {
            $subkeyPackets = array_merge(
                $subkeyPackets, $subkey->toPacketList()->getPackets()
            );
        }

        return new PacketList([
            $this->keyPacket,
            ...$this->revocationSignatures,
            ...$this->directSignatures,
            ...$userPackets,
            ...$subkeyPackets,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function getLogger(): LoggerInterface
    {
        return $this->logger ?? Config::getLogger();
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
     * @return array<SignaturePacketInterface>
     */
    public function getRevocationSignatures(): array
    {
        return $this->revocationSignatures;
    }

    /**
     * Get direct signatures
     * 
     * @return array<SignaturePacketInterface>
     */
    public function getDirectSignatures(): array
    {
        return $this->directSignatures;
    }

    /**
     * Gets users
     * 
     * @return array<User>
     */
    public function getUsers(): array
    {
        return $this->users;
    }

    /**
     * Gets subkeys
     * 
     * @return array<Subkey>
     */
    public function getSubkeys(): array
    {
        return $this->subkeys;
    }

    /**
     * Sets users
     * 
     * @param array<User> $users
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
     * @param array<Subkey> $subkeys
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
            static fn ($a, $b) => $b->getCreationTime()->getTimestamp()
                                - $a->getCreationTime()->getTimestamp()
        );
        foreach ($subkeys as $subkey) {
            if (empty($keyID) || $keyID === $subkey->getKeyID()) {
                if ($subkey->verify($time)) {
                    if (!$subkey->isSigningKey()) {
                        continue;
                    }
                    $signature = $subkey->getLatestBindingSignature()?->getEmbeddedSignature();
                    if ($signature instanceof EmbeddedSignature) {
                        // verify embedded signature
                        if ($signature->getSignature()->verify(
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
                    else {
                        throw new \UnexpectedValueException('Missing embedded signature');
                    }
                }
            }
        }

        if (!$this->isSigningKey() ||
           (!empty($keyID) && $keyID !== $this->getKeyID()))
        {
            throw new \UnexpectedValueException(
                'Could not find valid signing key packet.'
            );
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
            static fn ($a, $b) => $b->getCreationTime()->getTimestamp()
                                - $a->getCreationTime()->getTimestamp()
        );
        foreach ($subkeys as $subkey) {
            if (empty($keyID) || $keyID === $subkey->getKeyID()) {
                if ($subkey->verify($time)) {
                    if (!$subkey->isEncryptionKey()) {
                        continue;
                    }
                    return $subkey->getKeyPacket();
                }
            }
        }

        if (!$this->isEncryptionKey() ||
           (!empty($keyID) && $keyID !== $this->getKeyID()))
        {
            throw new \UnexpectedValueException(
                'Could not find valid encryption key packet.'
            );
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
            return self::getKeyExpiration($selfCertifications);
        }
        if (!empty($this->directSignatures)) {
            return self::getKeyExpiration($this->directSignatures);
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
        $keyID = ($certificate != null) ? $certificate->getIssuerKeyID() : '';
        foreach ($this->revocationSignatures as $signature) {
            if (empty($keyID) || $keyID === $signature->getIssuerKeyID()) {
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
                $aPrimary = (int) $a->isPrimary();
                $bPrimary = (int) $b->isPrimary();
                if ($aPrimary === $bPrimary) {
                    $aTime = $a->getLatestSelfCertification()?->getSignatureCreationTime() ?? new DateTime();
                    $bTime = $b->getLatestSelfCertification()?->getSignatureCreationTime() ?? new DateTime();
                    return $aTime->getTimestamp() - $bTime->getTimestamp();
                }
                else {
                    return $aPrimary - $bPrimary;
                }
            }
        );
        return array_pop($users);
    }

    /**
     * Return the key is signing or verification key
     * 
     * @return bool
     */
    protected function isSigningKey(?DateTime $time = null): bool
    {
        if (!$this->keyPacket->isSigningKey()) {
            return false;
        }
        $primaryUser = $this->getPrimaryUser($time);
        $keyFlags = $primaryUser->getLatestSelfCertification()?->getKeyFlags();
        if (($keyFlags instanceof KeyFlags) && !$keyFlags->isSignData()) {
            return false;
        }
        return true;
    }

    /**
     * Return the key is encryption or decryption key
     * 
     * @return bool
     */
    protected function isEncryptionKey(?DateTime $time = null): bool
    {
        if (!$this->keyPacket->isEncryptionKey()) {
            return false;
        }
        $primaryUser = $this->getPrimaryUser($time);
        $keyFlags = $primaryUser->getLatestSelfCertification()?->getKeyFlags();
        if (($keyFlags instanceof KeyFlags) &&
           !($keyFlags->isEncryptCommunication() || $keyFlags->isEncryptStorage()))
        {
            return false;
        }
        return true;
    }

    /**
     * Gets key expiration from signatures.
     *
     * @param array<SignaturePacketInterface> $signatures
     * @return DateTime
     */
    public static function getKeyExpiration(array $signatures): ?DateTime
    {
        usort(
            $signatures,
            static function ($a, $b) {
                $aTime = $a->getSignatureCreationTime() ?? new DateTime();
                $bTime = $b->getSignatureCreationTime() ?? new DateTime();
                return $bTime->getTimestamp() - $aTime->getTimestamp();
            }
        );
        foreach ($signatures as $signature) {
            $keyExpirationTime = $signature->getKeyExpirationTime();
            if ($keyExpirationTime instanceof KeyExpirationTime) {
                $expirationTime = $keyExpirationTime->getExpirationTime();
                $creationTime = $signature->getSignatureCreationTime() ?? new DateTime();
                $keyExpiry = $creationTime->setTimestamp(
                    $creationTime->getTimestamp() + $expirationTime
                );
                $signatureExpiry = $signature->getSignatureExpirationTime();
                if (empty($signatureExpiry)) {
                    return $keyExpiry;
                }
                else {
                    return $keyExpiry < $signatureExpiry ? $keyExpiry : $signatureExpiry;
                }
            }
            else {
                return $signature->getSignatureExpirationTime();
            }
        }
        return null;
    }

    /**
     * Reads packet list.
     *
     * @param PacketListInterface $packetList
     * @return array<string, mixed>
     */
    protected static function readPacketList(PacketListInterface $packetList): array
    {
        $revocationSignatures = $directSignatures = $users = $subkeys = [];
        $keyPacket = $primaryKeyID = null;

        foreach ($packetList->getPackets() as $packet) {
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
                                    if ($packet->getIssuerKeyID() === $primaryKeyID) {
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
}
