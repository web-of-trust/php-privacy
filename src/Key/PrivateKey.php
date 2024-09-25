<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Key;

use DateTimeInterface;
use OpenPGP\Common\{
    Armor,
    Config,
};
use OpenPGP\Enum\{
    AeadAlgorithm,
    ArmorType,
    CurveOid,
    KeyAlgorithm,
    KeyType,
    PacketTag,
    RevocationReasonTag,
    RSAKeySize,
};
use OpenPGP\Packet\{
    PacketList,
    SecretKey,
    SecretSubkey,
    Signature,
    UserID,
};
use OpenPGP\Type\{
    KeyInterface,
    PacketListInterface,
    PrivateKeyInterface,
    SecretKeyPacketInterface,
};

/**
 * OpenPGP private key class
 *
 * @package  OpenPGP
 * @category Key
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class PrivateKey extends AbstractKey implements PrivateKeyInterface
{
    /**
     * Constructor
     *
     * @param SecretKeyPacketInterface $secretKeyPacket
     * @param array $revocationSignatures
     * @param array $directSignatures
     * @param array $users
     * @param array $subkeys
     * @return self
     */
    public function __construct(
        private readonly SecretKeyPacketInterface $secretKeyPacket,
        array $revocationSignatures = [],
        array $directSignatures = [],
        array $users = [],
        array $subkeys = [],
    )
    {
        parent::__construct(
            $secretKeyPacket,
            $revocationSignatures,
            $directSignatures,
            $users,
            $subkeys,
        );
    }

    /**
     * Read private key from armored string
     *
     * @param string $armored
     * @return self
     */
    public static function fromArmored(string $armored): self
    {
        return self::fromBytes(
            Armor::decode($armored)->assert(ArmorType::PrivateKey)->getData()
        );
    }

    /**
     * Read private key from binary string
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        return self::fromPacketList(
            PacketList::decode($bytes)
        );
    }

    /**
     * Read private key from packet list
     *
     * @param PacketListInterface $packetList
     * @return self
     */
    public static function fromPacketList(
        PacketListInterface $packetList
    ): self
    {
        $keyMap = self::packetListToKeyMap($packetList);
        if (!($keyMap['keyPacket'] instanceof SecretKeyPacketInterface)) {
            throw new \RuntimeException(
                'Key packet is not secret key type.'
            );
        }
        return new self(
            $keyMap['keyPacket'],
            $keyMap['revocationSignatures'],
            $keyMap['directSignatures'],
            $keyMap['users'],
            $keyMap['subkeys'],
        );
    }

    /**
     * Generate a new OpenPGP key pair. Support RSA, ECC, Curve25519 and Curve448 key types.
     * The generated primary key will have signing capabilities.
     * One subkey with encryption capabilities is also generated.
     *
     * @param array<string> $userIDs
     * @param string $passphrase
     * @param KeyType $type
     * @param RSAKeySize $rsaKeySize
     * @param CurveOid $curve
     * @param int $keyExpiry
     * @param DateTimeInterface $time
     * @return self
     */
    public static function generate(
        array $userIDs,
        string $passphrase,
        KeyType $type = KeyType::Rsa,
        RSAKeySize $rsaKeySize = RSAKeySize::Normal,
        CurveOid $curve = CurveOid::Secp521r1,
        int $keyExpiry = 0,
        ?DateTimeInterface $time = null,
    ): self
    {
        if (empty($userIDs) || empty($passphrase)) {
            throw new \InvalidArgumentException(
                'UserIDs and passphrase are required for key generation.',
            );
        }
        $subkeyCurve = $curve;
        switch ($type) {
            case KeyType::Ecc:
                if ($curve === CurveOid::Ed25519 || $curve === CurveOid::Curve25519) {
                    $keyAlgorithm = KeyAlgorithm::EdDsaLegacy;
                    $curve = CurveOid::Ed25519;
                    $subkeyCurve = CurveOid::Curve25519;
                }
                else {
                    $keyAlgorithm = KeyAlgorithm::EcDsa;
                }
                $subkeyAlgorithm = KeyAlgorithm::Ecdh;
                break;
            case KeyType::Curve25519:
                $keyAlgorithm = KeyAlgorithm::Ed25519;
                $subkeyAlgorithm = KeyAlgorithm::X25519;
                break;
            case KeyType::Curve448:
                $keyAlgorithm = KeyAlgorithm::Ed448;
                $subkeyAlgorithm = KeyAlgorithm::X448;
                break;
            default:
                $keyAlgorithm = KeyAlgorithm::RsaEncryptSign;
                $subkeyAlgorithm = KeyAlgorithm::RsaEncryptSign;
                break;
        }

        $secretKey = SecretKey::generate(
            $keyAlgorithm,
            $rsaKeySize,
            $curve,
            $time,
        );
        $secretSubkey = SecretSubkey::generate(
            $subkeyAlgorithm,
            $rsaKeySize,
            $subkeyCurve,
            $time,
        );

        $v6Key = $secretKey->getVersion() === 6;
        $aead = ($v6Key && Config::aeadProtect()) ?
            Config::getPreferredAead() : null;
        $secretKey = $secretKey->encrypt(
            $passphrase, Config::getPreferredSymmetric(), $aead
        );
        $secretSubkey = $secretSubkey->encrypt(
            $passphrase, Config::getPreferredSymmetric(), $aead
        );

        $packets = [$secretKey];
        if ($v6Key) {
            // Wrap secret key with direct key signature
            $packets[] = Signature::createDirectKeySignature(
                $secretKey,
                $keyExpiry,
                $time,
            );
        }

        // Wrap user id with certificate signature
        $index = 0;
        foreach ($userIDs as $userID) {
            $packet = new UserID($userID);
            $packets[] = $packet;
            $packets[] = Signature::createSelfCertificate(
                $secretKey,
                $packet,
                $index === 0,
                $keyExpiry,
                $time,
            );
            $index++;
        }

        // Wrap secret subkey with binding signature
        $packets[] = $secretSubkey;
        $packets[] = Signature::createSubkeyBinding(
            $secretKey,
            $secretSubkey,
            $keyExpiry,
            false,
            $time,
        );

        return self::fromPacketList(new PacketList($packets));
    }

    /**
     * {@inheritdoc}
     */
    public function armor(): string
    {
        return Armor::encode(
            ArmorType::PrivateKey,
            $this->getPacketList()->encode(),
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toPublic(): KeyInterface
    {
        $packets = [];
        foreach ($this->getPackets() as $packet) {
            if ($packet instanceof SecretKeyPacketInterface) {
                $packets[] = $packet->getPublicKey();
            }
            else {
                $packets[] = $packet;
            }
        }
        return PublicKey::fromPacketList(new PacketList($packets));
    }

    /**
     * {@inheritdoc}
     */
    public function isEncrypted(): bool
    {
        return $this->secretKeyPacket->isEncrypted();
    }

    /**
     * {@inheritdoc}
     */
    public function isDecrypted(): bool
    {
        return $this->secretKeyPacket->isDecrypted();
    }

    /**
     * {@inheritdoc}
     */
    public function aeadProtected(): bool
    {
        return $this->secretKeyPacket->getAead() instanceof AeadAlgorithm;
    }

    /**
     * {@inheritdoc}
     */
    public function getSecretKeyPacket(): SecretKeyPacketInterface
    {
        return $this->secretKeyPacket;
    }

    /**
     * {@inheritdoc}
     */
    public function getDecryptionKeyPackets(
        string $keyID = '', ?DateTimeInterface $time = null
    ): array
    {
        if (!$this->verify(time: $time)) {
            throw new \RuntimeException(
                'Primary key is invalid.'
            );
        }
        $subkeys = $this->getSubkeys();
        usort(
            $subkeys,
            static fn ($a, $b): int =>
                (int) $b->getCreationTime()?->getTimestamp() -
                (int) $a->getCreationTime()?->getTimestamp()
        );

        $keyPackets = [];
        foreach ($subkeys as $subkey) {
            if (empty($keyID) || strcmp($keyID, $subkey->getKeyID()) === 0) {
                if (!$subkey->isEncryptionKey() || !$subkey->verify($time)) {
                    continue;
                }
                $keyPackets[] = $subkey->getKeyPacket();
            }
        }

        if ($this->isEncryptionKey()) {
            $keyPackets[] = $this->secretKeyPacket;
        }

        return $keyPackets;
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt(
        string $passphrase,
        array $subkeyPassphrases = [],
    ): self
    {
        if (empty($passphrase)) {
            throw new \InvalidArgumentException(
                'Passphrase is required for key encryption.'
            );
        }
        if (!$this->isDecrypted()) {
            throw new \RuntimeException(
                'Private key must be decrypted before encrypting.'
            );
        }

        $aead = null;
        if ($this->getVersion() === 6 && Config::aeadProtect()) {
            $aead = Config::getPreferredAead();
        }

        $privateKey = new self(
            $this->secretKeyPacket->encrypt(
                $passphrase, Config::getPreferredSymmetric(), $aead
            ),
            $this->getRevocationSignatures(),
            $this->getDirectSignatures(),
        );
        $privateKey->setUsers(array_map(
            static fn ($user) => new User(
                $privateKey,
                $user->getUserIDPacket(),
                $user->getRevocationCertifications(),
                $user->getSelfCertifications(),
                $user->getOtherCertifications(),
            ),
            $this->getUsers(),
        ));

        $subkeys = [];
        foreach ($this->getSubkeys() as $key => $subkey) {
            $keyPacket = $subkey->getKeyPacket();
            if ($keyPacket instanceof SecretKeyPacketInterface) {
                $subkeyPassphrase = $subkeyPassphrases[$key] ?? $passphrase;
                $keyPacket = $keyPacket->encrypt(
                    $subkeyPassphrase, Config::getPreferredSymmetric(), $aead
                );
            }
            $subkeys[] = new Subkey(
                $privateKey,
                $keyPacket,
                $subkey->getRevocationSignatures(),
                $subkey->getBindingSignatures(),
            );
        }
        return $privateKey->setSubkeys($subkeys);
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(
        string $passphrase,
        array $subkeyPassphrases = [],
    ): self
    {
        if (empty($passphrase)) {
            throw new \InvalidArgumentException(
                'Passphrase is required for key decryption.'
            );
        }
        $secretKey = $this->secretKeyPacket->decrypt($passphrase);
        $privateKey = new self(
            $secretKey,
            $this->getRevocationSignatures(),
            $this->getDirectSignatures(),
        );
        $privateKey->setUsers(array_map(
            static fn ($user) => new User(
                $privateKey,
                $user->getUserIDPacket(),
                $user->getRevocationCertifications(),
                $user->getSelfCertifications(),
                $user->getOtherCertifications(),
            ),
            $this->getUsers(),
        ));

        $subkeys = [];
        foreach ($this->getSubkeys() as $key => $subkey) {
            $keyPacket = $subkey->getKeyPacket();
            if ($keyPacket instanceof SecretKeyPacketInterface) {
                $subkeyPassphrase = $subkeyPassphrases[$key] ?? $passphrase;
                $keyPacket = $keyPacket->decrypt($subkeyPassphrase);
            }
            $subkeys[] = new Subkey(
                $privateKey,
                $keyPacket,
                $subkey->getRevocationSignatures(),
                $subkey->getBindingSignatures(),
            );
        }
        return $privateKey->setSubkeys($subkeys);
    }

    /**
     * {@inheritdoc}
     */
    public function addUsers(array $userIDs): self
    {
        if (empty($userIDs)) {
            throw new \InvalidArgumentException(
                'User IDs are required.',
            );
        }

        $self = $this->clone();
        $users = $self->getUsers();
        foreach ($userIDs as $userID) {
            $packet = new UserID($userID);
            $users[] = new User(
                $self,
                $packet,
                selfCertifications: [
                    Signature::createSelfCertificate(
                        $self->getSecretKeyPacket(),
                        $packet,
                    ),
                ],
            );
        }
        return $self->setUsers($users);
    }

    /**
     * {@inheritdoc}
     */
    public function addSubkey(
        string $passphrase,
        KeyAlgorithm $keyAlgorithm = KeyAlgorithm::RsaEncryptSign,
        RSAKeySize $rsaKeySize = RSAKeySize::Normal,
        CurveOid $curve = CurveOid::Secp521r1,
        int $keyExpiry = 0,
        bool $subkeySign = false,
        ?DateTimeInterface $time = null,
    ): self
    {
        if (empty($passphrase)) {
            throw new \InvalidArgumentException(
                'Passphrase is required for key generation.',
            );
        }

        $aead = null;
        if ($this->getVersion() === 6 && Config::aeadProtect()) {
            $aead = Config::getPreferredAead();
        }

        $self = $this->clone();
        $subkeys = $self->getSubkeys();
        $secretSubkey = SecretSubkey::generate(
            $keyAlgorithm,
            $rsaKeySize,
            $curve,
            $time,
        )->encrypt($passphrase, Config::getPreferredSymmetric(), $aead);
        $subkeys[] = new Subkey(
            $self,
            $secretSubkey,
            bindingSignatures: [
                Signature::createSubkeyBinding(
                    $self->getSecretKeyPacket(),
                    $secretSubkey,
                    $keyExpiry,
                    $subkeySign,
                    $time,
                ),
            ],
        );
        return $self->setSubkeys($subkeys);
    }

    /**
     * {@inheritdoc}
     */
    public function certifyKey(
        KeyInterface $key, ?DateTimeInterface $time = null
    ): KeyInterface
    {
        return $key->certifyBy($this, $time);
    }

    /**
     * {@inheritdoc}
     */
    public function revokeKey(
        KeyInterface $key,
        string $revocationReason = '',
        ?RevocationReasonTag $reasonTag = null,
        ?DateTimeInterface $time = null,
    ): KeyInterface
    {
        return $key->revokeBy(
            $this, $revocationReason, $reasonTag, $time
        );
    }

    /**
     * {@inheritdoc}
     */
    public function revokeUser(
        string $userID,
        string $revocationReason = '',
        ?RevocationReasonTag $reasonTag = null,
        ?DateTimeInterface $time = null,
    ): self
    {
        $self = $this->clone();

        $users = $self->getUsers();
        foreach ($users as $key => $user) {
            if (strcmp($user->getUserID(), $userID) === 0) {
                $users[$key] = $user->revokeBy(
                    $self, $revocationReason, $reasonTag, $time
                );
            }
        }
        return $self->setUsers($users);
    }

    /**
     * {@inheritdoc}
     */
    public function revokeSubkey(
        string $keyID,
        string $revocationReason = '',
        ?RevocationReasonTag $reasonTag = null,
        ?DateTimeInterface $time = null,
    ): self
    {
        $self = $this->clone();
        $subkeys = $self->getSubkeys();
        foreach ($subkeys as $key => $subkey) {
            if (strcmp($subkey->getKeyID(), $keyID) === 0) {
                $subkeys[$key] = $subkey->revokeBy(
                    $self, $revocationReason, $reasonTag, $time
                );
            }
        }
        return $self->setSubkeys($subkeys);
    }
}
