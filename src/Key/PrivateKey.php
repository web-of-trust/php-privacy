<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Key;

use DateTimeInterface;
use OpenPGP\Common\{Armor, Config};
use OpenPGP\Enum\{
    AeadAlgorithm,
    ArmorType,
    Ecc,
    KeyAlgorithm,
    KeyType,
    RevocationReasonTag,
    RSAKeySize,
    SymmetricAlgorithm
};
use OpenPGP\Packet\{PacketList, SecretKey, SecretSubkey, Signature, UserID};
use OpenPGP\Type\{
    KeyInterface,
    PacketListInterface,
    PrivateKeyInterface,
    SecretKeyPacketInterface,
    SubkeyPacketInterface,
    UserIDPacketInterface
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
     * Secret key packet
     *
     * @var SecretKeyPacketInterface
     */
    private readonly SecretKeyPacketInterface $secretKeyPacket;

    /**
     * Constructor
     *
     * @param PacketListInterface $packetList
     * @return self
     */
    public function __construct(
        PacketListInterface $packetList
    ) {
        parent::__construct($packetList);
        if ($this->getKeyPacket() instanceof SecretKeyPacketInterface) {
            $this->secretKeyPacket = $this->getKeyPacket();
        }
        else {
            throw new \RuntimeException("Key packet is not secret key type.");

        }
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
            Armor::decode($armored)
                ->assert(ArmorType::PrivateKey)
                ->getData()
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
        return new self(PacketList::decode($bytes));
    }

    /**
     * Generate a new OpenPGP key pair. Support RSA, ECC, Curve25519 and Curve448 key types.
     * The generated primary key will have signing capabilities.
     * One subkey with encryption capabilities is also generated if `signOnly` is false.
     *
     * @param array<string> $userIDs
     * @param string $passphrase
     * @param KeyType $type
     * @param RSAKeySize $rsaKeySize
     * @param Ecc $curve
     * @param int $keyExpiry
     * @param bool $signOnly
     * @param DateTimeInterface $time
     * @return self
     */
    public static function generate(
        array $userIDs,
        string $passphrase,
        KeyType $type = KeyType::Rsa,
        RSAKeySize $rsaKeySize = RSAKeySize::Normal,
        Ecc $curve = Ecc::Secp521r1,
        int $keyExpiry = 0,
        bool $signOnly = false,
        ?DateTimeInterface $time = null
    ): self {
        if (empty($userIDs) || empty($passphrase)) {
            throw new \InvalidArgumentException(
                "UserIDs and passphrase are required for key generation."
            );
        }
        $subkeyCurve = $curve;
        switch ($type) {
            case KeyType::Ecc:
                if (
                    $curve === Ecc::Ed25519 ||
                    $curve === Ecc::Curve25519
                ) {
                    $keyAlgorithm = KeyAlgorithm::EdDsaLegacy;
                    $curve = Ecc::Ed25519;
                    $subkeyCurve = Ecc::Curve25519;
                } else {
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
            $time
        );

        $v6Key = $secretKey->getVersion() === 6;
        $aead =
            $v6Key && Config::aeadProtect() ? Config::getPreferredAead() : null;
        $secretKey = $secretKey->encrypt(
            $passphrase,
            Config::getPreferredSymmetric(),
            $aead
        );

        $packets = [$secretKey];
        if ($v6Key) {
            // Wrap secret key with direct key signature
            $packets[] = Signature::createDirectKeySignature(
                $secretKey,
                $keyExpiry,
                $time
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
                $time
            );
            $index++;
        }

        if (!$signOnly) {
            $secretSubkey = SecretSubkey::generate(
                $subkeyAlgorithm,
                $rsaKeySize,
                $subkeyCurve,
                $time
            )->encrypt($passphrase, Config::getPreferredSymmetric(), $aead);
            // Wrap secret subkey with binding signature
            $packets[] = $secretSubkey;
            $packets[] = Signature::createSubkeyBinding(
                $secretKey,
                $secretSubkey,
                $keyExpiry,
                false,
                $time
            );
        }

        return new self(new PacketList($packets));
    }

    /**
     * {@inheritdoc}
     */
    public function armor(): string
    {
        return Armor::encode(
            ArmorType::PrivateKey,
            $this->getPacketList()->encode()
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
            } else {
                $packets[] = $packet;
            }
        }
        return new PublicKey(new PacketList($packets));
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
        string $keyID = "",
        ?DateTimeInterface $time = null
    ): array {
        $subkeys = $this->getSubkeys();
        usort(
            $subkeys,
            static fn ($a, $b) =>
                (int) $b->getCreationTime()?->getTimestamp() -
                (int) $a->getCreationTime()?->getTimestamp()
        );

        $keyPackets = [];
        foreach ($subkeys as $subkey) {
            if (empty($keyID) || strcmp($keyID, $subkey->getKeyID()) === 0) {
                if (
                    !$subkey->isEncryptionKey() ||
                    $subkey->isRevoked(time: $time)
                ) {
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
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes256
    ): self {
        if (empty($passphrase)) {
            throw new \InvalidArgumentException(
                "Passphrase is required for key encryption."
            );
        }
        if (!$this->isDecrypted()) {
            throw new \RuntimeException(
                "Private key must be decrypted before encrypting."
            );
        }

        $aead = null;
        if ($this->getVersion() === 6 && Config::aeadProtect()) {
            $aead = Config::getPreferredAead();
        }
        $subkeyPackets = $this->getSubkeyPackets();
        foreach ($subkeyPackets as $key => $packet) {
            if ($packet instanceof SecretKeyPacketInterface) {
                $subkeyPassphrase = $subkeyPassphrases[$key] ?? $passphrase;
                $subkeyPackets[$key] = $packet->encrypt(
                    $subkeyPassphrase,
                    $symmetric,
                    $aead
                );
            }
        }

        return new self(new PacketList([
            $this->secretKeyPacket->encrypt(
                $passphrase,
                $symmetric,
                $aead
            ),
            ...$this->getRevocationSignatures(),
            ...$this->getDirectSignatures(),
            ...$this->getUserPackets(),
            ...$subkeyPackets,
        ]));
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(
        string $passphrase,
        array $subkeyPassphrases = []
    ): self {
        if (empty($passphrase)) {
            throw new \InvalidArgumentException(
                "Passphrase is required for key decryption."
            );
        }
        $subkeyPackets = $this->getSubkeyPackets();
        foreach ($subkeyPackets as $key => $packet) {
            if ($packet instanceof SecretKeyPacketInterface) {
                $subkeyPassphrase = $subkeyPassphrases[$key] ?? $passphrase;
                $subkeyPackets[$key] = $packet->decrypt($subkeyPassphrase);
            }
        }

        return new self(new PacketList([
            $this->secretKeyPacket->decrypt($passphrase),
            ...$this->getRevocationSignatures(),
            ...$this->getDirectSignatures(),
            ...$this->getUserPackets(),
            ...$subkeyPackets,
        ]));
    }

    /**
     * {@inheritdoc}
     */
    public function addUsers(array $userIDs): self
    {
        if (empty($userIDs)) {
            throw new \InvalidArgumentException("User IDs are required.");
        }

        $userPackets = $this->getUserPackets();
        foreach ($userIDs as $userID) {
            $packet = new UserID($userID);
            $userPackets = [
                ...[
                    $packet,
                    Signature::createSelfCertificate(
                        $this->secretKeyPacket,
                        $packet
                    ),
                ],
                ...$userPackets,
            ];
        }

        return new self(new PacketList([
            $this->secretKeyPacket,
            ...$this->getRevocationSignatures(),
            ...$this->getDirectSignatures(),
            ...$userPackets,
            ...$this->getSubkeyPackets(),
        ]));
    }

    /**
     * {@inheritdoc}
     */
    public function addSubkey(
        string $passphrase,
        KeyAlgorithm $keyAlgorithm = KeyAlgorithm::RsaEncryptSign,
        RSAKeySize $rsaKeySize = RSAKeySize::Normal,
        Ecc $curve = Ecc::Secp521r1,
        int $keyExpiry = 0,
        bool $forSigning = false,
        ?DateTimeInterface $time = null
    ): self {
        if (empty($passphrase)) {
            throw new \InvalidArgumentException(
                "Passphrase is required for key generation."
            );
        }

        $aead = null;
        if ($this->getVersion() === 6 && Config::aeadProtect()) {
            $aead = Config::getPreferredAead();
        }

        $secretSubkey = SecretSubkey::generate(
            $keyAlgorithm,
            $rsaKeySize,
            $curve,
            $time
        )->encrypt($passphrase, Config::getPreferredSymmetric(), $aead);
        $subkeyPackets = [
            ...[
                $secretSubkey,
                Signature::createSubkeyBinding(
                    $this->secretKeyPacket,
                    $secretSubkey,
                    $keyExpiry,
                    $forSigning,
                    $time
                ),
            ],
            ...$this->getSubkeyPackets(),
        ];

        return new self(new PacketList([
            $this->secretKeyPacket,
            ...$this->getRevocationSignatures(),
            ...$this->getDirectSignatures(),
            ...$this->getUserPackets(),
            ...$subkeyPackets,
        ]));
    }

    /**
     * {@inheritdoc}
     */
    public function certifyKey(
        KeyInterface $key,
        ?DateTimeInterface $time = null
    ): KeyInterface {
        return $key->certifyBy($this, $time);
    }

    /**
     * {@inheritdoc}
     */
    public function revokeKey(
        KeyInterface $key,
        string $revocationReason = "",
        ?RevocationReasonTag $reasonTag = null,
        ?DateTimeInterface $time = null
    ): KeyInterface {
        return $key->revokeBy($this, $revocationReason, $reasonTag, $time);
    }

    /**
     * {@inheritdoc}
     */
    public function revokeUser(
        string $userID,
        string $revocationReason = "",
        ?RevocationReasonTag $reasonTag = null,
        ?DateTimeInterface $time = null
    ): self {
        $users = $this->getUsers();
        foreach ($users as $key => $user) {
            if (strcmp($user->getUserID(), $userID) === 0) {
                $users[$key] = $user->revokeBy(
                    $this,
                    $revocationReason,
                    $reasonTag,
                    $time
                );
            }
        }

        $userPackets = [];
        foreach ($users as $user) {
            $userPackets = [
                ...$userPackets,
                ...$user->getPacketList()->getPackets(),
            ];
        }

        return new self(new PacketList([
            $this->secretKeyPacket,
            ...$this->getRevocationSignatures(),
            ...$this->getDirectSignatures(),
            ...$userPackets,
            ...$this->getSubkeyPackets(),
        ]));
    }

    /**
     * {@inheritdoc}
     */
    public function revokeSubkey(
        string $keyID,
        string $revocationReason = "",
        ?RevocationReasonTag $reasonTag = null,
        ?DateTimeInterface $time = null
    ): self {
        $subkeys = $this->getSubkeys();
        foreach ($subkeys as $key => $subkey) {
            if (strcmp($subkey->getKeyID(), $keyID) === 0) {
                $subkeys[$key] = $subkey->revokeBy(
                    $this,
                    $revocationReason,
                    $reasonTag,
                    $time
                );
            }
        }
        $subkeyPackets = [];
        foreach ($subkeys as $subkey) {
            $subkeyPackets = [
                ...$subkeyPackets,
                ...$subkey->getPacketList()->getPackets(),
            ];
        }

        return new self(new PacketList([
            $this->secretKeyPacket,
            ...$this->getRevocationSignatures(),
            ...$this->getDirectSignatures(),
            ...$this->getUserPackets(),
            ...$subkeyPackets,
        ]));
    }
}
