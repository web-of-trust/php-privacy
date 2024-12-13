<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Key;

use DateTimeInterface;
use OpenPGP\Enum\{
    KeyAlgorithm,
    PacketTag,
    RevocationReasonTag,
    SignatureType,
    SymmetricAlgorithm
};
use OpenPGP\Packet\{PacketList, Padding, Signature};
use OpenPGP\Packet\Signature\{
    EmbeddedSignature,
    Features,
    KeyExpirationTime,
    KeyFlags
};
use OpenPGP\Type\{
    KeyInterface,
    KeyPacketInterface,
    PacketListInterface,
    PrivateKeyInterface,
    SecretKeyPacketInterface,
    SignaturePacketInterface,
    SubkeyInterface,
    SubkeyPacketInterface,
    UserIDPacketInterface,
    UserInterface
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
    /**
     * Key packet
     *
     * @var KeyPacketInterface
     */
    private readonly KeyPacketInterface $keyPacket;

    /**
     * Revocation signature packets
     *
     * @var array
     */
    private readonly array $revocationSignatures;

    /**
     * Direct signature packets
     *
     * @var array
     */
    private readonly array $directSignatures;

    /**
     * Users of the key
     *
     * @var array
     */
    private readonly array $users;

    /**
     * Subkeys of the key
     *
     * @var array
     */
    private readonly array $subkeys;

    /**
     * Constructor
     *
     * @param PacketListInterface $packetList
     * @return self
     */
    protected function __construct(PacketListInterface $packetList)
    {
        [
            $keyPacket,
            $revocationSignatures,
            $directSignatures,
            $users,
            $subkeys,
        ] = self::keyStructure($packetList);

        $this->keyPacket = $keyPacket;
        $this->revocationSignatures = $revocationSignatures;
        $this->directSignatures = $directSignatures;

        $this->users = array_map(
            fn ($user) => new User(
                $this,
                $user["userIDPacket"],
                $user["revocationSignatures"],
                $user["selfCertifications"],
                $user["otherCertifications"]
            ),
            $users
        );

        $this->subkeys = array_map(
            fn ($subkey) => new Subkey(
                $this,
                $subkey["keyPacket"],
                $subkey["revocationSignatures"],
                $subkey["bindingSignatures"]
            ),
            $subkeys
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getPacketList(): PacketListInterface
    {
        $packets = [
            $this->keyPacket,
            ...$this->revocationSignatures,
            ...$this->directSignatures,
            ...$this->getUserPackets(),
            ...$this->getSubkeyPackets(),
        ];
        if ($this->getVersion() === 6) {
            $packets[] = Padding::createPadding(
                random_int(Padding::PADDING_MIN, Padding::PADDING_MAX)
            );
        }

        return new PacketList($packets);
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
     * {@inheritdoc}
     */
    public function getRevocationSignatures(): array
    {
        return $this->revocationSignatures;
    }

    /**
     * {@inheritdoc}
     */
    public function getDirectSignatures(): array
    {
        return $this->directSignatures;
    }

    /**
     * {@inheritdoc}
     */
    public function getLatestDirectSignature(): ?SignaturePacketInterface
    {
        if (!empty($this->directSignatures)) {
            $signatures = $this->directSignatures;
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
    public function getUsers(): array
    {
        return $this->users;
    }

    /**
     * {@inheritdoc}
     */
    public function getSubkeys(): array
    {
        return $this->subkeys;
    }

    /**
     * {@inheritdoc}
     */
    public function getSigningKeyPacket(
        string $keyID = "",
        ?DateTimeInterface $time = null
    ): KeyPacketInterface {
        $subkeys = $this->subkeys;
        usort(
            $subkeys,
            static fn ($a, $b) =>
                (int) $b->getCreationTime()?->getTimestamp() -
                (int) $a->getCreationTime()?->getTimestamp()
        );
        foreach ($subkeys as $subkey) {
            if (empty($keyID) || strcmp($keyID, $subkey->getKeyID()) === 0) {
                if (!$subkey->isSigningKey() || !$subkey->verify($time)) {
                    continue;
                }
                $signature = $subkey
                    ->getLatestBindingSignature()
                    ?->getEmbeddedSignature();
                if ($signature instanceof EmbeddedSignature) {
                    // verify embedded signature
                    if ($signature
                        ->getSignature()
                        ->verify(
                            $subkey->getKeyPacket(),
                            implode([
                                $this->getKeyPacket()->getSignBytes(),
                                $subkey->getKeyPacket()->getSignBytes(),
                            ]),
                            $time
                        )
                    ) {
                        return $subkey->getKeyPacket();
                    }
                } else {
                    throw new \RuntimeException("Missing embedded signature.");
                }
            }
        }

        if (
            !$this->isSigningKey() ||
            (!empty($keyID) && strcmp($keyID, $this->getKeyID()) !== 0)
        ) {
            throw new \RuntimeException(
                "Could not find valid signing key packet."
            );
        }

        return $this->keyPacket;
    }

    /**
     * {@inheritdoc}
     */
    public function getEncryptionKeyPacket(
        string $keyID = "",
        ?DateTimeInterface $time = null
    ): KeyPacketInterface {
        $subkeys = $this->subkeys;
        usort(
            $subkeys,
            static fn ($a, $b) =>
                (int) $b->getCreationTime()?->getTimestamp() -
                (int) $a->getCreationTime()?->getTimestamp()
        );
        foreach ($subkeys as $subkey) {
            if (empty($keyID) || strcmp($keyID, $subkey->getKeyID()) === 0) {
                if (!$subkey->isEncryptionKey() || !$subkey->verify($time)) {
                    continue;
                }
                return $subkey->getKeyPacket();
            }
        }

        if (
            !$this->isEncryptionKey() ||
            (!empty($keyID) && strcmp($keyID, $this->getKeyID()) !== 0)
        ) {
            throw new \RuntimeException(
                "Could not find valid encryption key packet."
            );
        }

        return $this->keyPacket;
    }

    /**
     * {@inheritdoc}
     */
    public function getExpirationTime(): ?DateTimeInterface
    {
        $expirationTime = self::getKeyExpiration($this->directSignatures);
        if (empty($expirationTime)) {
            $selfCertifications = [];
            foreach ($this->users as $user) {
                $selfCertifications = [
                    ...$selfCertifications,
                    ...$user->getSelfCertifications(),
                ];
            }
            if (!empty($selfCertifications)) {
                $expirationTime = self::getKeyExpiration($selfCertifications);
            }
        }
        return $expirationTime;
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
    public function isPrivate(): bool
    {
        return $this->keyPacket->getTag() === PacketTag::SecretKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getPreferredSymmetrics(): array
    {
        $preferred = $this->getLatestDirectSignature()?->getPreferredSymmetricAlgorithms();
        if (empty($preferred)) {
            $user = $this->getPrimaryUser();
            $preferred = $user?->getLatestSelfCertification()?->getPreferredSymmetricAlgorithms();
        }
        return $preferred?->getPreferences() ?? [];
    }

    /**
     * {@inheritdoc}
     */
    public function getPreferredAeads(SymmetricAlgorithm $symmetric): array
    {
        $preferred = $this->getLatestDirectSignature()?->getPreferredAeadCiphers();
        return $preferred?->getPreferredAeads($symmetric) ?? [];
    }

    /**
     * {@inheritdoc}
     */
    public function aeadSupported(): bool
    {
        $features = $this->getLatestDirectSignature()?->getFeatures();
        if (empty($features)) {
            $user = $this->getPrimaryUser();
            $features = $user?->getLatestSelfCertification()?->getFeatures();
        }
        return $features instanceof Features
            ? $features->supportV2SEIPD()
            : false;
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
                $this->toPublic()->getSigningKeyPacket();
            foreach ($this->revocationSignatures as $signature) {
                if (
                    empty($keyID) ||
                    strcmp($keyID, $signature->getIssuerKeyID()) === 0
                ) {
                    if ($signature->verify(
                        $keyPacket,
                        $this->keyPacket->getSignBytes(),
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
        $primaryUser = $this->getPrimaryUser();
        if ($primaryUser instanceof UserInterface) {
            return $primaryUser->isCertified($verifyKey, $certificate, $time);
        }
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function verify(
        string $userID = "",
        ?DateTimeInterface $time = null
    ): bool {
        if ($this->isRevoked(time: $time)) {
            return false;
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
        foreach ($this->users as $user) {
            if (empty($userID) || strcmp($user->getUserID(), $userID) === 0) {
                if (!$user->verify($time)) {
                    return false;
                }
            }
        }
        $expirationTime = $this->getExpirationTime();
        if (
            $expirationTime instanceof DateTimeInterface &&
            $expirationTime->getTimestamp() < time()
        ) {
            throw new \RuntimeException(
                "Primary key is expired."
            );
        }
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function getPrimaryUser(
        ?DateTimeInterface $time = null
    ): ?UserInterface {
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
        PrivateKeyInterface $signKey,
        ?DateTimeInterface $time = null
    ): self {
        $users = [];
        $certifedUserID = "";
        $primaryUser = $this->getPrimaryUser();
        if ($primaryUser instanceof UserInterface) {
            $certifedUser = $primaryUser->certifyBy($signKey, $time);
            $certifedUserID = $certifedUser->getUserID();
            $users[] = $certifedUser;
        }
        foreach ($this->getUsers() as $user) {
            if (strcmp($user->getUserID(), $certifedUserID) !== 0) {
                $users[] = $user;
            }
        }

        $userPackets = [];
        foreach ($users as $user) {
            $userPackets = [
                ...$userPackets,
                ...$user->getPacketList()->getPackets(),
            ];
        }

        return new static(new PacketList([
            $this->getKeyPacket(),
            ...$this->getRevocationSignatures(),
            ...$this->getDirectSignatures(),
            ...$userPackets,
            ...$this->getSubkeyPackets(),
        ]));
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
        return new static(new PacketList([
            $this->getKeyPacket(),
            ...[
                Signature::createKeyRevocation(
                    $signKey->getSecretKeyPacket(),
                    $this->getKeyPacket(),
                    $revocationReason,
                    $reasonTag,
                    $time
                ),
                ...$this->getRevocationSignatures(),
            ],
            ...$this->getDirectSignatures(),
            ...$this->getUserPackets(),
            ...$this->getSubkeyPackets(),
        ]));
    }

    /**
     * Get key expiration from signatures.
     *
     * @param array $signatures
     * @return DateTimeInterface
     */
    public static function getKeyExpiration(
        array $signatures
    ): ?DateTimeInterface {
        usort($signatures, static function ($a, $b) {
            $aTime = $a->getCreationTime() ?? new \DateTime();
            $bTime = $b->getCreationTime() ?? new \DateTime();
            return $bTime->getTimestamp() - $aTime->getTimestamp();
        });
        foreach ($signatures as $signature) {
            $keyExpirationTime = $signature->getKeyExpirationTime();
            if ($keyExpirationTime instanceof KeyExpirationTime) {
                $expirationTime = $keyExpirationTime->getExpirationTime();
                $creationTime =
                    $signature->getCreationTime() ?? new \DateTime();
                $keyExpiry = $creationTime->setTimestamp(
                    $creationTime->getTimestamp() + $expirationTime
                );
                $signatureExpiry = $signature->getExpirationTime();
                if (empty($signatureExpiry)) {
                    return $keyExpiry;
                } else {
                    return $keyExpiry < $signatureExpiry
                        ? $keyExpiry
                        : $signatureExpiry;
                }
            } else {
                return $signature->getExpirationTime();
            }
        }
        return null;
    }

    /**
     * {@inheritdoc}
     */
    abstract public function toPublic(): KeyInterface;

    /**
     * {@inheritdoc}
     */
    abstract public function armor(): string;

    /**
     * Get user packets
     *
     * @return array
     */
    protected function getUserPackets(): array
    {
        $packets = [];
        foreach ($this->users as $user) {
            $packets = [
                ...$packets,
                ...$user->getPacketList()->getPackets(),
            ];
        }
        return $packets;
    }

    /**
     * Get subkey packets
     *
     * @return array
     */
    protected function getSubkeyPackets(): array
    {
        $packets = [];
        foreach ($this->subkeys as $subkey) {
            $packets = [
                ...$packets,
                ...$subkey->getPacketList()->getPackets(),
            ];
        }
        return $packets;
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
        $keyFlags = $this->getLatestDirectSignature()?->getKeyFlags();
        if (empty($keyFlags)) {
            $users = $this->getSortedPrimaryUsers();
            $user = array_pop($users);
            $keyFlags = $user?->getLatestSelfCertification()?->getKeyFlags();
        }
        if ($keyFlags instanceof KeyFlags && !$keyFlags->isSignData()) {
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
        $keyFlags = $this->getLatestDirectSignature()?->getKeyFlags();
        if (empty($keyFlags)) {
            $users = $this->getSortedPrimaryUsers();
            $user = array_pop($users);
            $keyFlags = $user?->getLatestSelfCertification()?->getKeyFlags();
        }
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
     * Get sorted primary users.
     *
     * @return array
     */
    protected function getSortedPrimaryUsers(): array
    {
        $users = $this->users;
        usort($users, static function ($a, $b) {
            $aPrimary = (int) $a->isPrimary();
            $bPrimary = (int) $b->isPrimary();
            if ($aPrimary === $bPrimary) {
                $aTime =
                    $a->getLatestSelfCertification()?->getCreationTime() ??
                    new \DateTime();
                $bTime =
                    $b->getLatestSelfCertification()?->getCreationTime() ??
                    new \DateTime();
                return $aTime->getTimestamp() - $bTime->getTimestamp();
            } else {
                return $aPrimary - $bPrimary;
            }
        });
        return $users;
    }

    /**
     * Build key structure from packet list.
     *
     * @param PacketListInterface $packetList
     * @return array
     */
    private static function keyStructure(
        PacketListInterface $packetList
    ): array {
        $revocationSignatures = $directSignatures = $users = $subkeys = [];
        $keyPacket = $primaryKeyID = null;

        foreach ($packetList->getPackets() as $packet) {
            switch ($packet->getTag()) {
                case PacketTag::PublicKey:
                case PacketTag::SecretKey:
                    if (!empty($keyPacket)) {
                        throw new \RuntimeException(
                            "Key block contains multiple keys."
                        );
                    }
                    $keyPacket = $packet;
                    $primaryKeyID = $packet->getKeyID();
                    break;
                case PacketTag::PublicSubkey:
                case PacketTag::SecretSubkey:
                    $subkeys[] = [
                        "keyPacket" => $packet,
                        "revocationSignatures" => [],
                        "bindingSignatures" => [],
                    ];
                    break;
                case PacketTag::UserID:
                case PacketTag::UserAttribute:
                    $users[] = [
                        "userIDPacket" => $packet,
                        "revocationSignatures" => [],
                        "selfCertifications" => [],
                        "otherCertifications" => [],
                    ];
                    break;
                case PacketTag::Signature:
                    if ($packet instanceof SignaturePacketInterface) {
                        if ($packet->isKeyRevocation()) {
                            $revocationSignatures[] = $packet;
                        }
                        if ($packet->isDirectKey()) {
                            $directSignatures[] = $packet;
                        }
                        if ($packet->isCertification()) {
                            $user = array_pop($users);
                            if (!empty($user)) {
                                if (
                                    strcmp(
                                        $packet->getIssuerKeyID(),
                                        $primaryKeyID
                                    ) === 0
                                ) {
                                    $user["selfCertifications"][] = $packet;
                                } else {
                                    $user[
                                        "otherCertifications"
                                    ][] = $packet;
                                }
                                $users[] = $user;
                            }
                        }
                        if ($packet->isCertRevocation()) {
                            $user = array_pop($users);
                            if (!empty($user)) {
                                $user["revocationSignatures"][] = $packet;
                                $users[] = $user;
                            }
                        }
                        if ($packet->isSubkeyRevocation()) {
                            $subkey = array_pop($subkeys);
                            if (!empty($subkey)) {
                                $subkey["revocationSignatures"][] = $packet;
                                $subkeys[] = $subkey;
                            }
                        }
                        if ($packet->isSubkeyBinding()) {
                            $subkey = array_pop($subkeys);
                            if (!empty($subkey)) {
                                $subkey["bindingSignatures"][] = $packet;
                                $subkeys[] = $subkey;
                            }
                        }
                    }
                    break;
            }
        }

        if (empty($keyPacket)) {
            throw new \RuntimeException(
                "Key packet not found in packet list."
            );
        }

        $verifyKey = $keyPacket instanceof SecretKeyPacketInterface ?
            $keyPacket->getPublicKey() : $keyPacket;

        return [
            $keyPacket,
            $revocationSignatures,
            array_filter(
                $directSignatures,
                static fn ($signature) => $signature->verify(
                    $verifyKey, $verifyKey->getSignBytes()
                )
            ),
            array_filter(
                $users, 
                static function ($user) use ($verifyKey) {
                    foreach ($user['selfCertifications'] as $signature) {
                        $dataToVerify = implode([
                            $verifyKey->getSignBytes(),
                            $user['userIDPacket']->getSignBytes(),
                        ]);
                        if ($signature->verify($verifyKey, $dataToVerify)) {
                            return true;
                        }
                    }
                    return false;
                }
            ),
            array_filter(
                $subkeys,
                static function ($subkey) use ($verifyKey) {
                    foreach ($subkey['bindingSignatures'] as $signature) {
                        $dataToVerify = implode([
                            $verifyKey->getSignBytes(),
                            $subkey['keyPacket']->getSignBytes(),
                        ]);
                        if ($signature->verify($verifyKey, $dataToVerify)) {
                            return true;
                        }
                    }
                    return false;
                }
            ),
        ];
    }
}
