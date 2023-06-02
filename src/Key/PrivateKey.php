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
 * @package   OpenPGP
 * @category  Key
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
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
     * Reads private key from armored string
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
     * Reads private key from packet list
     *
     * @param PacketListInterface $packetList
     * @return self
     */
    public static function fromPacketList(PacketListInterface $packetList): self
    {
        $keyMap = self::readPacketList($packetList);
        if (!($keyMap['keyPacket'] instanceof SecretKeyPacketInterface)) {
            throw new \UnexpectedValueException(
                'Key packet is not secret key type'
            );
        }
        $privateKey = new self(
            $keyMap['keyPacket'],
            $keyMap['revocationSignatures'],
            $keyMap['directSignatures']
        );
        $users = array_map(
            static fn ($user) => new User(
                $privateKey,
                $user['userIDPacket'],
                $user['revocationSignatures'],
                $user['selfCertifications'],
                $user['otherCertifications']
            ),
            $keyMap['users']
        );
        $privateKey->setUsers($users);
        $subkeys = array_map(
            static fn ($subkey) => new Subkey(
                $privateKey,
                $subkey['keyPacket'],
                $subkey['revocationSignatures'],
                $subkey['bindingSignatures']
            ),
            $keyMap['subkeys']
        );
        $privateKey->setSubkeys($subkeys);

        return $privateKey;
    }

    /**
     * Generates a new OpenPGP key pair. Supports RSA, DSA and ECC key types.
     * By default, primary and subkeys will be of same type.
     * The generated primary key will have signing capabilities.
     * By default, one subkey with encryption capabilities is also generated.
     *
     * @param array<string> $userIDs
     * @param string $passphrase
     * @param KeyType $type
     * @param RSAKeySize $rsaKeySize
     * @param DHKeySize $dhKeySize
     * @param CurveOid $curve
     * @param int $keyExpiry
     * @param DateTime $time
     * @return self
     */
    public static function generate(
        array $userIDs,
        string $passphrase,
        KeyType $type = KeyType::Rsa,
        RSAKeySize $rsaKeySize = RSAKeySize::S4096,
        DHKeySize $dhKeySize = DHKeySize::L2048_N224,
        CurveOid $curve = CurveOid::Secp521r1,
        int $keyExpiry = 0,
        ?DateTime $time = null
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
            $this->toPacketList()->encode()
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
    public function getDecryptionKeyPackets(?DateTime $time = null): array
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
                if ($subkey->verify($time)) {
                    if (!$subkey->isEncryptionKey()) {
                        continue;
                    }
                    $keyPackets[] = $subkey->getKeyPacket();
                }
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
                'Private key must be decrypted.'
            );
        }

        $privateKey = new self(
            $this->secretKeyPacket->encrypt($passphrase),
            $this->getRevocationSignatures(),
            $this->getDirectSignatures(),
        );

        $users = array_map(
            static fn ($user) => new User(
                $privateKey,
                $user->getUserIDPacket(),
                $user->getRevocationCertifications(),
                $user->getSelfCertifications(),
                $user->getOtherCertifications()
            ),
            $this->getUsers()
        );
        $privateKey->setUsers($users);

        $subkeys = [];
        foreach ($this->getSubkeys() as $key => $subkey) {
            $subkeyPassphrase = $subkeyPassphrases[$key] ?? $passphrase;
            $keyPacket = $subkey->getKeyPacket()->encrypt($subkeyPassphrase);
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
                'passphrase are required for key decryption.'
            );
        }
        $secretKey = $this->secretKeyPacket->decrypt($passphrase);
        if (!$secretKey->getKeyMaterial()->isValid()) {
            throw new \UnexpectedValueException(
                'The key parameters are not consistent.'
            );
        }
        $privateKey = new self(
            $secretKey,
            $this->getRevocationSignatures(),
            $this->getDirectSignatures(),
        );

        $users = array_map(
            static fn ($user) => new User(
                $privateKey,
                $user->getUserIDPacket(),
                $user->getRevocationCertifications(),
                $user->getSelfCertifications(),
                $user->getOtherCertifications()
            ),
            $this->getUsers()
        );
        $privateKey->setUsers($users);

        $subkeys = [];
        foreach ($this->getSubkeys() as $key => $subkey) {
            $subkeyPassphrase = $subkeyPassphrases[$key] ?? $passphrase;
            $keyPacket = $subkey->getKeyPacket()->decrypt($subkeyPassphrase);
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

        $privateKey = clone $this;
        $users = $privateKey->getUsers();
        foreach ($userIDs as $userID) {
            $packet = new UserID($userID);
            $selfCertificate = Signature::createSelfCertificate(
                $privateKey->getSigningKeyPacket(),
                $packet,
                false,
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
        RSAKeySize $rsaKeySize = RSAKeySize::S4096,
        DHKeySize $dhKeySize = DHKeySize::L2048_N224,
        CurveOid $curve = CurveOid::Secp521r1,
        int $keyExpiry = 0,
        bool $subkeySign = false,
        ?DateTime $time = null
    ): self
    {
        if (empty($passphrase)) {
            throw new \InvalidArgumentException(
                'passphrase are required for key generation.',
            );
        }

        $privateKey = clone $this;
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
        KeyInterface $key, ?DateTime $time = null
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
        ?DateTime $time = null
    ): KeyInterface
    {
        return $key->revokeBy($this, $revocationReason, $time);
    }

    /**
     * Revokes User,
     * and returns a clone of the key object with the new revoked user.
     * 
     * @param string $userID
     * @param string $revocationReason
     * @param DateTime $time
     * @return self
     */
    public function revokeUser(
        string $userID,
        string $revocationReason = '',
        ?DateTime $time = null
    )
    {
        $users = $this->getUsers();
        foreach ($users as $key => $user) {
            if ($user->getUserID() === $userID) {
                $users[$key] = $user->revoke(
                    $this, $revocationReason, $time
                );
            }
        }

        return new self(
            $this->secretKeyPacket,
            $this->getRevocationSignatures(),
            $this->getDirectSignatures(),
            $users,
            $this->getSubkeys()
        );
    }

    /**
     * Revokes subkey,
     * and returns a clone of the key object with the new revoked subkey.
     * 
     * @param string $keyID
     * @param string $revocationReason
     * @param DateTime $time
     * @return self
     */
    public function revokeSubkey(
        string $keyID,
        string $revocationReason = '',
        ?DateTime $time = null
    )
    {
        $subkeys = $this->getSubkeys();
        foreach ($subkeys as $key => $subkey) {
            if ($subkey->getKeyID() === $keyID) {
                $subkeys[$key] = $subkey->revoke(
                    $this, $revocationReason, $time
                );
            }
        }

        return new self(
            $this->secretKeyPacket,
            $this->getRevocationSignatures(),
            $this->getDirectSignatures(),
            $this->getUsers(),
            $subkeys
        );
    }
}
