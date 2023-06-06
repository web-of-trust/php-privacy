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

use DateTimeInterface;
use OpenPGP\Common\Armor;
use OpenPGP\Enum\{
    ArmorType,
    CurveOid,
    DHKeySize,
    KeyAlgorithm,
    KeyType,
    PacketTag,
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
    private readonly SecretKeyPacketInterface $secretKeyPacket;

    /**
     * Constructor
     *
     * @param SecretKeyPacketInterface $keyPacket
     * @param array $revocationSignatures
     * @param array $directSignatures
     * @param array $users
     * @param array $subkeys
     * @return self
     */
    public function __construct(
        SecretKeyPacketInterface $keyPacket,
        array $revocationSignatures = [],
        array $directSignatures = [],
        array $users = [],
        array $subkeys = []
    )
    {
        parent::__construct(
            $keyPacket, $revocationSignatures, $directSignatures, $users, $subkeys
        );
        $this->secretKeyPacket = $keyPacket;
    }

    /**
     * Read private key from armored string
     *
     * @param string $armored
     * @return self
     */
    public static function fromArmored(string $armored): self
    {
        $armor = Armor::decode($armored);
        if ($armor->getType() !== ArmorType::PrivateKey) {
            throw new \UnexpectedValueException(
                'Armored text not of private key type'
            );
        }
        return self::fromPacketList(
            PacketList::decode($armor->getData())
        );
    }

    /**
     * Read private key from packet list
     *
     * @param PacketListInterface $packetList
     * @return self
     */
    public static function fromPacketList(PacketListInterface $packetList): self
    {
        $keyStruct = self::readPacketList($packetList);
        if (!($keyStruct['keyPacket'] instanceof SecretKeyPacketInterface)) {
            throw new \UnexpectedValueException(
                'Key packet is not secret key type'
            );
        }
        $privateKey = new self(
            $keyStruct['keyPacket'],
            $keyStruct['revocationSignatures'],
            $keyStruct['directSignatures']
        );
        self::applyKeyStructure($privateKey, $keyStruct);

        return $privateKey;
    }

    /**
     * Generate a new OpenPGP key pair. Support RSA, DSA and ECC key types.
     * The generated primary key will have signing capabilities.
     * One subkey with encryption capabilities is also generated.
     *
     * @param array<string> $userIDs
     * @param string $passphrase
     * @param KeyType $type
     * @param RSAKeySize $rsaKeySize
     * @param DHKeySize $dhKeySize
     * @param CurveOid $curve
     * @param int $keyExpiry
     * @param DateTimeInterface $time
     * @return self
     */
    public static function generate(
        array $userIDs,
        string $passphrase,
        KeyType $type = KeyType::Rsa,
        RSAKeySize $rsaKeySize = RSAKeySize::S2048,
        DHKeySize $dhKeySize = DHKeySize::L2048_N224,
        CurveOid $curve = CurveOid::Ed25519,
        int $keyExpiry = 0,
        ?DateTimeInterface $time = null
    ): self
    {
        if (empty($userIDs) || empty($passphrase)) {
            throw new \InvalidArgumentException(
                'UserIDs and passphrase are required for key generation.',
            );
        }
        $keyAlgorithm = KeyAlgorithm::RsaEncryptSign;
        $subkeyAlgorithm = KeyAlgorithm::RsaEncryptSign;
        $subkeyCurve = $curve;
        if ($type == KeyType::Dsa) {
            $keyAlgorithm = KeyAlgorithm::Dsa;
            $subkeyAlgorithm = KeyAlgorithm::ElGamal;
        }
        elseif ($type == KeyType::Ecc) {
            if ($curve == CurveOid::Ed25519 || $curve == CurveOid::Curve25519) {
                $keyAlgorithm = KeyAlgorithm::EdDsa;
                $curve = CurveOid::Ed25519;
                $subkeyCurve = CurveOid::Curve25519;
            }
            else {
                $keyAlgorithm = KeyAlgorithm::EcDsa;
            }
            $subkeyAlgorithm = KeyAlgorithm::Ecdh;
        }

        $secretKey = SecretKey::generate(
            $keyAlgorithm,
            $rsaKeySize,
            $dhKeySize,
            $curve,
            $time,
        )->encrypt($passphrase);
        $secretSubkey = SecretSubkey::generate(
            $subkeyAlgorithm,
            $rsaKeySize,
            $dhKeySize,
            $subkeyCurve,
            $time,
        )->encrypt($passphrase);

        $packets = [$secretKey];

        // Wrap user id with certificate signature
        $index = 0;
        foreach ($userIDs as $userID) {
            $packet = new UserID($userID);
            $packets[] = $packet;
            $packets[] = Signature::createSelfCertificate(
                $secretKey,
                $packet,
                ($index === 0) ? true : false,
                $keyExpiry,
                $time
            );
            $index++;
        }

        // Wrap secret subkey with binding signature
        $packets[] = $secretSubkey;
        $packets[] = Signature::createSubkeyBinding(
            $secretKey, $secretSubkey, $keyExpiry, false, $time
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
    public function getDecryptionKeyPackets(?DateTimeInterface $time = null): array
    {
        if (!$this->verify(time: $time)) {
            throw new \UnexpectedValueException(
                'Primary key is invalid.'
            );
        }
        $subkeys = $this->getSubkeys();
        usort(
            $subkeys,
            static fn ($a, $b) => $b->getCreationTime()->getTimestamp()
                                - $a->getCreationTime()->getTimestamp()
        );

        $keyPackets = [];
        foreach ($subkeys as $subkey) {
            if (empty($keyID) || $keyID === $subkey->getKeyID()) {
                if (!$subkey->isEncryptionKey()) {
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
        array $subkeyPassphrases = []
    ): self
    {
        if (empty($passphrase)) {
            throw new \InvalidArgumentException(
                'Passphrase is required for key encryption.'
            );
        }
        if (!$this->isDecrypted()) {
            throw new \UnexpectedValueException(
                'Private key must be decrypted before encrypting.'
            );
        }

        $privateKey = new self(
            $this->secretKeyPacket->encrypt($passphrase),
            $this->getRevocationSignatures(),
            $this->getDirectSignatures(),
        );
        $privateKey->setUsers(array_map(
            static fn ($user) => new User(
                $privateKey,
                $user->getUserIDPacket(),
                $user->getRevocationCertifications(),
                $user->getSelfCertifications(),
                $user->getOtherCertifications()
            ),
            $this->getUsers()
        ));

        $subkeys = [];
        foreach ($this->getSubkeys() as $key => $subkey) {
            $keyPacket = $subkey->getKeyPacket();
            if ($keyPacket instanceof SecretKeyPacketInterface) {
                $subkeyPassphrase = $subkeyPassphrases[$key] ?? $passphrase;
                $keyPacket = $keyPacket->encrypt($subkeyPassphrase);
            }
            $subkeys[] = new Subkey(
                $privateKey,
                $keyPacket,
                $subkey->getRevocationSignatures(),
                $subkey->getBindingSignatures()
            );
        }
        $privateKey->setSubkeys($subkeys);

        return $privateKey;
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(
        string $passphrase, array $subkeyPassphrases = []
    ): self
    {
        if (empty($passphrase)) {
            throw new \InvalidArgumentException(
                'passphrase is required for key decryption.'
            );
        }
        $secretKey = $this->secretKeyPacket->decrypt($passphrase);
        if (!$secretKey->getKeyMaterial()->isValid()) {
            throw new \UnexpectedValueException(
                'The key material is not consistent.'
            );
        }
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
                $user->getOtherCertifications()
            ),
            $this->getUsers()
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
                $subkey->getBindingSignatures()
            );
        }
        $privateKey->setSubkeys($subkeys);

        return $privateKey;
    }

    /**
     * {@inheritdoc}
     */
    public function addUsers(array $userIDs): self
    {
        if (empty($userIDs)) {
            throw new \InvalidArgumentException(
                'UserIDs are required.',
            );
        }

        $privateKey = $this->clone();
        $users = $privateKey->getUsers();
        foreach ($userIDs as $userID) {
            $packet = new UserID($userID);
            $selfCertificate = Signature::createSelfCertificate(
                $privateKey->getSigningKeyPacket(),
                $packet
            );
            $users[] = new User(
                $privateKey,
                $packet,
                selfCertifications: [$selfCertificate],
            );
        }
        $privateKey->setUsers($users);

        return $privateKey;
    }

    /**
     * {@inheritdoc}
     */
    public function addSubkey(
        string $passphrase,
        KeyAlgorithm $keyAlgorithm = KeyAlgorithm::RsaEncryptSign,
        RSAKeySize $rsaKeySize = RSAKeySize::S2048,
        DHKeySize $dhKeySize = DHKeySize::L2048_N224,
        CurveOid $curve = CurveOid::Ed25519,
        int $keyExpiry = 0,
        bool $subkeySign = false,
        ?DateTimeInterface $time = null
    ): self
    {
        if (empty($passphrase)) {
            throw new \InvalidArgumentException(
                'passphrase is required for key generation.',
            );
        }

        $privateKey = $this->clone();
        $subkeys = $privateKey->getSubkeys();
        $secretSubkey = SecretSubkey::generate(
            $keyAlgorithm,
            $rsaKeySize,
            $dhKeySize,
            $curve,
            $time,
        )->encrypt($passphrase);
        $bindingSignature = Signature::createSubkeyBinding(
            $privateKey->getSigningKeyPacket(),
            $secretSubkey,
            $keyExpiry,
            $subkeySign,
            $time
        );
        $subkeys[] = new Subkey(
            $privateKey,
            $secretSubkey,
            bindingSignatures: [$bindingSignature]
        );
        $privateKey->setSubkeys($subkeys);

        return $privateKey;
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
        ?DateTimeInterface $time = null
    ): KeyInterface
    {
        return $key->revokeBy($this, $revocationReason, $time);
    }

    /**
     * {@inheritdoc}
     */
    public function revokeUser(
        string $userID,
        string $revocationReason = '',
        ?DateTimeInterface $time = null
    ): self
    {
        $privateKey = $this->clone();

        $users = $privateKey->getUsers();
        foreach ($users as $key => $user) {
            if ($user->getUserID() === $userID) {
                $users[$key] = $user->revokeBy(
                    $privateKey, $revocationReason, $time
                );
            }
        }
        $privateKey->setUsers($users);

        return $privateKey;
    }

    /**
     * {@inheritdoc}
     */
    public function revokeSubkey(
        string $keyID,
        string $revocationReason = '',
        ?DateTimeInterface $time = null
    ): self
    {
        $privateKey = $this->clone();
        $subkeys = $privateKey->getSubkeys();
        foreach ($subkeys as $key => $subkey) {
            if ($subkey->getKeyID() === $keyID) {
                $subkeys[$key] = $subkey->revokeBy(
                    $privateKey, $revocationReason, $time
                );
            }
        }
        $privateKey->setSubkeys($subkeys);

        return $privateKey;
    }
}
