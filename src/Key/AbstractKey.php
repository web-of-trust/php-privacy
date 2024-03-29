<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Key;

use DateTimeInterface;
use OpenPGP\Common\Config;
use OpenPGP\Enum\{
    KeyAlgorithm,
    PacketTag,
    RevocationReasonTag,
    SignatureType,
};
use OpenPGP\Packet\{
    PacketList,
    Signature,
};
use OpenPGP\Packet\Signature\{
    EmbeddedSignature,
    Features,
    KeyExpirationTime,
    KeyFlags,
    RevocationReason,
};
use OpenPGP\Type\{
    KeyInterface,
    KeyPacketInterface,
    PacketListInterface,
    PrivateKeyInterface,
    SignaturePacketInterface,
    SubkeyInterface,
    SubkeyPacketInterface,
    UserIDPacketInterface,
    UserInterface,
};
use Psr\Log\{
    LoggerAwareTrait,
    LoggerInterface,
};

/**
 * Abstract OpenPGP key class
 * 
 * @package  OpenPGP
 * @category Key
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
abstract class AbstractKey implements KeyInterface
{
    use LoggerAwareTrait;

    /**
     * Revocation signature packets
     * 
     * @var array
     */
    private array $revocationSignatures = [];

    /**
     * Direct signature packets
     * 
     * @var array
     */
    private array $directSignatures = [];

    /**
     * Users of the key
     * 
     * @var array
     */
    private array $users = [];

    /**
     * Subkeys of the key
     * 
     * @var array
     */
    private array $subkeys = [];

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
    protected function __construct(
        private readonly KeyPacketInterface $keyPacket,
        array $revocationSignatures = [],
        array $directSignatures = [],
        array $users = [],
        array $subkeys = []
    )
    {
        $this->revocationSignatures = array_values(array_filter(
            $revocationSignatures,
            static fn ($signature) => $signature instanceof SignaturePacketInterface
        ));
        $this->directSignatures = array_values(array_filter(
            $directSignatures,
            static fn ($signature) => $signature instanceof SignaturePacketInterface
        ));
        $this->setUsers($users)
             ->setSubkeys($subkeys)
             ->setLogger(Config::getLogger());
    }

    /**
     * {@inheritdoc}
     */
    public function getPacketList(): PacketListInterface
    {
        $userPackets = [];
        foreach ($this->users as $user) {
            $userPackets = array_merge(
                $userPackets, $user->getPacketList()->getPackets()
            );
        }
        $subkeyPackets = [];
        foreach ($this->subkeys as $subkey) {
            $subkeyPackets = array_merge(
                $subkeyPackets, $subkey->getPacketList()->getPackets()
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
    public function getPackets(): array
    {
        return $this->getPacketList()->getPackets();
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
     * {@inheritdoc}
     */
    public function __toString(): string
    {
        return $this->armor();
    }

    /**
     * Get revocation signatures
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
     * Get users
     * 
     * @return array
     */
    public function getUsers(): array
    {
        return $this->users;
    }

    /**
     * Get subkeys
     * 
     * @return array
     */
    public function getSubkeys(): array
    {
        return $this->subkeys;
    }

    /**
     * Set users
     * 
     * @param array $users
     * @return static
     */
    protected function setUsers(array $users): static
    {
        $this->users = array_values(array_filter(
            $users,
            static fn ($user) => $user instanceof UserInterface
        ));
        return $this;
    }

    /**
     * Set subkeys
     * 
     * @param array $subkeys
     * @return static
     */
    protected function setSubkeys(array $subkeys): static
    {
        $this->subkeys = array_values(array_filter(
            $subkeys,
            static fn ($subkey) => $subkey instanceof SubkeyInterface
        ));
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getSigningKeyPacket(
        string $keyID = '', ?DateTimeInterface $time = null
    ): KeyPacketInterface
    {
        $subkeys = $this->subkeys;
        usort(
            $subkeys,
            static fn ($a, $b): int => $b->getCreationTime()->getTimestamp()
                                     - $a->getCreationTime()->getTimestamp()
        );
        foreach ($subkeys as $subkey) {
            if (empty($keyID) || $keyID === $subkey->getKeyID()) {
                if (!$subkey->isSigningKey() || !$subkey->verify($time)) {
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
                    throw new \UnexpectedValueException(
                        'Missing embedded signature.'
                    );
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
        string $keyID = '', ?DateTimeInterface $time = null
    ): KeyPacketInterface
    {
        $subkeys = $this->subkeys;
        usort(
            $subkeys,
            static fn ($a, $b): int => $b->getCreationTime()->getTimestamp()
                                     - $a->getCreationTime()->getTimestamp()
        );
        foreach ($subkeys as $subkey) {
            if (empty($keyID) || $keyID === $subkey->getKeyID()) {
                if (!$subkey->isEncryptionKey() || !$subkey->verify($time)) {
                    continue;
                }
                return $subkey->getKeyPacket();
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
    public function getExpirationTime(): ?DateTimeInterface
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
    public function getVersion(): int
    {
        return $this->keyPacket->getVersion();
    }

    /**
     * {@inheritdoc}
     */
    public function getCreationTime(): DateTimeInterface
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
    public function aeadSupported(): bool
    {
        $primaryUser = $this->getPrimaryUser();
        $features = $primaryUser?->getLatestSelfCertification()?->getFeatures();
        if (($features instanceof Features) && $features->supportAeadEncryptedData()) {
            return true;
        }
        return false;
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
                         $this->toPublic()->getSigningKeyPacket();
            foreach ($this->revocationSignatures as $signature) {
                if (empty($keyID) || $keyID === $signature->getIssuerKeyID()) {
                    if ($signature->verify(
                        $keyPacket,
                        $this->keyPacket->getSignBytes(),
                        $time
                    )) {
                        $reason = $signature->getRevocationReason();
                        if ($reason instanceof RevocationReason) {
                            $this->getLogger()->warning(
                                'Primary key is revoked. Reason: {reason}',
                                [
                                    'reason' => $reason->getDescription(),
                                ]
                            );
                        }
                        else {
                            $this->getLogger()->warning(
                                'Primary key is revoked.'
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
        $primaryUser = $this->getPrimaryUser();
        if ($primaryUser instanceof UserInterface) {
            return $primaryUser->isCertified(
                $verifyKey, $certificate, $time
            );
        }
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function verify(
        string $userID = '', ?DateTimeInterface $time = null
    ): bool
    {
        if ($this->isRevoked(time: $time)) {
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
        if ($expirationTime instanceof DateTimeInterface &&
            $expirationTime->getTimestamp() < time()) {
            $this->getLogger()->warning(
                'Primary key is expired.'
            );
            return false;
        }
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function getPrimaryUser(?DateTimeInterface $time = null): ?UserInterface
    {
        $users = array_filter(
            $this->getSortedPrimaryUsers(),
            static fn ($user) => $user->verify($time)
        );
        return array_pop($users);
    }

    /**
     * {@inheritdoc}
     */
    public function certifyBy(
        PrivateKeyInterface $signKey, ?DateTimeInterface $time = null
    ): self
    {
        $users = [];
        $certifedUserID = '';
        $self = $this->clone();
        $primaryUser = $self->getPrimaryUser();
        if ($primaryUser instanceof UserInterface) {
            $certifedUser = $primaryUser->certifyBy($signKey, $time);
            $certifedUserID = $certifedUser->getUserID();
            $users[] = $certifedUser;
        }
        foreach ($self->getUsers() as $user) {
            if ($user->getUserID() !== $certifedUserID) {
                $users[] = $user;
            }
        }
        $self->setUsers($users);

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
        $self = $this->clone();
        $self->revocationSignatures[] = Signature::createKeyRevocation(
            $signKey->getSigningKeyPacket(),
            $self->getKeyPacket(),
            $revocationReason,
            $reasonTag,
            $time
        );

        return $self;
    }

    /**
     * Get key expiration from signatures.
     *
     * @param array $signatures
     * @return DateTimeInterface
     */
    public static function getKeyExpiration(array $signatures): ?DateTimeInterface
    {
        usort(
            $signatures,
            static function ($a, $b): int {
                $aTime = $a->getSignatureCreationTime() ?? new \DateTime();
                $bTime = $b->getSignatureCreationTime() ?? new \DateTime();
                return $bTime->getTimestamp() - $aTime->getTimestamp();
            }
        );
        foreach ($signatures as $signature) {
            $keyExpirationTime = $signature->getKeyExpirationTime();
            if ($keyExpirationTime instanceof KeyExpirationTime) {
                $expirationTime = $keyExpirationTime->getExpirationTime();
                $creationTime = $signature->getSignatureCreationTime() ?? new \DateTime();
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
     * Return the key is signing or verification key
     * 
     * @return bool
     */
    protected function isSigningKey(): bool
    {
        if (!$this->keyPacket->isSigningKey()) {
            return false;
        }
        $users = $this->getSortedPrimaryUsers();
        $user = array_pop($users);
        $keyFlags = $user?->getLatestSelfCertification()?->getKeyFlags();
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
    protected function isEncryptionKey(): bool
    {
        if (!$this->keyPacket->isEncryptionKey()) {
            return false;
        }
        $users = $this->getSortedPrimaryUsers();
        $user = array_pop($users);
        $keyFlags = $user?->getLatestSelfCertification()?->getKeyFlags();
        if (($keyFlags instanceof KeyFlags) &&
           !($keyFlags->isEncryptCommunication() || $keyFlags->isEncryptStorage()))
        {
            return false;
        }
        return true;
    }

    /**
     * Get sorted primary users.
     *
     * @return array
     */
    protected function getSortedPrimaryUsers(): array
    {
        $users = $this->users;
        usort(
            $users,
            static function ($a, $b) {
                $aPrimary = (int) $a->isPrimary();
                $bPrimary = (int) $b->isPrimary();
                if ($aPrimary === $bPrimary) {
                    $aTime = $a->getLatestSelfCertification()?->getSignatureCreationTime()
                             ?? new \DateTime();
                    $bTime = $b->getLatestSelfCertification()?->getSignatureCreationTime()
                             ?? new \DateTime();
                    return $aTime->getTimestamp() - $bTime->getTimestamp();
                }
                else {
                    return $aPrimary - $bPrimary;
                }
            }
        );
        return $users;
    }

    /**
     * Clone key.
     *
     * @return static
     */
    protected function clone(): static
    {
        $self = clone $this;

        $self->setUsers(array_map(
            static fn ($user) => new User(
                $self,
                $user->getUserIDPacket(),
                $user->getRevocationCertifications(),
                $user->getSelfCertifications(),
                $user->getOtherCertifications()
            ),
            $self->getUsers()
        ))->setSubkeys(array_map(
            static fn ($subkey) => new Subkey(
                $self,
                $subkey->getKeyPacket(),
                $subkey->getRevocationSignatures(),
                $subkey->getBindingSignatures()
            ),
            $self->getSubkeys()
        ));

        return $self;
    }

    protected static function applyKeyStructure(
        AbstractKey $key, array $keyMap
    ): void
    {
        $key->setUsers(array_map(
            static fn (array $user) => new User(
                $key,
                $user['userIDPacket'],
                $user['revocationSignatures'],
                $user['selfCertifications'],
                $user['otherCertifications']
            ),
            $keyMap['users']
        ))->setSubkeys(array_map(
            static fn (array $subkey) => new Subkey(
                $key,
                $subkey['keyPacket'],
                $subkey['revocationSignatures'],
                $subkey['bindingSignatures']
            ),
            $keyMap['subkeys']
        ));
    }

    /**
     * Read packet list to key structure.
     *
     * @param PacketListInterface $packetList
     * @return array
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
